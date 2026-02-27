//! IPC socket handler — the trust boundary between the Python Cortex and Rust
//! kernel rule enforcement.
//!
//! # Security invariants enforced at this layer (Rust — cannot be bypassed by Python)
//!
//! 1. **ML-DSA-65 signature verified BEFORE any payload field is read.**
//!    A compromised Cortex process cannot push rules without the private key.
//! 2. **`RuleBundle` fields validated** — version, reason length, nonce, and
//!    timestamp window (±[`MAX_BUNDLE_AGE_SECS`] seconds).
//! 3. **Anti-replay nonce cache** — nonces are tracked for `2 × MAX_BUNDLE_AGE_SECS`.
//!    Exact replay of a valid bundle within the timestamp window is rejected.
//! 4. **Sacrosanct check** — any network that overlaps a protected address (SCADA
//!    gateways, loopback, management network) is rejected here in Rust.  The Python
//!    Cortex also checks, but that check is not the authoritative one.
//! 5. **nftables applied only after all checks pass** — no partial rule state.
//!
//! # Socket permissions
//!
//! The socket is created with `0o600` (owner read/write only) so that only the
//! `vglf` service user (or root) can submit rules.  The kernel enforces this.

#![allow(clippy::module_name_repetitions)]

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::crypto::traits::{DigitalSignature, PublicKey, Signature};
use crate::ipc::nft;
use crate::ipc::protocol::{RuleBundle, SignedBundle, MAX_BUNDLE_AGE_SECS, MAX_MSG_BYTES};
use crate::ipc::sacrosanct::SacrosanctList;

// ---------------------------------------------------------------------------
// Connection timeout
// ---------------------------------------------------------------------------

/// Maximum time allowed for a single connection to send its message and
/// receive a response.  Prevents slow-write attacks from holding the socket.
const CONNECTION_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Anti-replay nonce cache
// ---------------------------------------------------------------------------

/// Rolling nonce cache — tracks seen nonces to detect bundle replay.
///
/// Entries older than `MAX_BUNDLE_AGE_SECS * 2` are evicted to bound memory
/// usage.  The `MAX_BUNDLE_AGE_SECS` timestamp window in `validate_and_parse`
/// ensures a bundle older than that is rejected by the timestamp check before
/// it even reaches the nonce cache, so the cache only needs to hold the recent
/// window.
struct NonceCache {
    entries: VecDeque<(Instant, String)>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    /// Returns `true` if `nonce` was already seen (replay detected).
    ///
    /// Evicts stale entries, then inserts the new nonce.
    fn check_and_insert(&mut self, nonce: &str) -> bool {
        let now = Instant::now();
        let max_age = Duration::from_secs(MAX_BUNDLE_AGE_SECS.saturating_mul(2));

        // Evict entries older than the rolling window.
        while let Some(front) = self.entries.front() {
            if now.duration_since(front.0) > max_age {
                self.entries.pop_front();
            } else {
                break;
            }
        }

        // Check for replay.
        if self.entries.iter().any(|(_, n)| n == nonce) {
            return true; // Replay detected — do NOT insert again.
        }

        self.entries.push_back((now, nonce.to_string()));
        false
    }
}

// ---------------------------------------------------------------------------
// Handler configuration
// ---------------------------------------------------------------------------

/// Configuration for the IPC listener.
pub struct HandlerConfig {
    /// Path to the Unix domain socket (e.g. `/var/run/vglf/rules.sock`).
    pub socket_path: PathBuf,

    /// ML-DSA-65 public key used to verify all incoming rule bundles.
    ///
    /// This key corresponds to the private key held by the Cortex engine
    /// (via TPM 2.0 or Vault transit in production).
    pub verifier_pubkey: PublicKey,

    /// The immutable sacrosanct network list — loaded once at startup.
    pub sacrosanct: Arc<SacrosanctList>,
}

// ---------------------------------------------------------------------------
// Main listener loop
// ---------------------------------------------------------------------------

/// Run the IPC listener.
///
/// Binds the Unix socket at `config.socket_path`, sets `0o600` permissions,
/// and accepts connections indefinitely.  Each connection is handled in a
/// separate Tokio task.
///
/// This function only returns on a fatal error (e.g. bind failure, permission
/// error).
///
/// # Errors
///
/// Returns an error if the socket cannot be bound or permissions cannot be
/// set.  Individual connection errors are logged and do not stop the listener.
pub async fn run(
    config: HandlerConfig,
    dsa: Arc<dyn DigitalSignature>,
) -> anyhow::Result<()> {
    // Remove a stale socket file left from a previous run.
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path).with_context(|| {
            format!(
                "failed to remove stale socket at {}",
                config.socket_path.display()
            )
        })?;
    }

    let listener = UnixListener::bind(&config.socket_path).with_context(|| {
        format!(
            "failed to bind IPC socket at {}",
            config.socket_path.display()
        )
    })?;

    // Restrict to owner read/write only — prevents non-vglf processes from
    // injecting rules even if they can reach the socket path.
    std::fs::set_permissions(
        &config.socket_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .context("failed to set IPC socket permissions to 0o600")?;

    info!(
        socket = ?config.socket_path,
        "VGLF IPC listener ready (permissions 0o600)"
    );

    let nonce_cache = Arc::new(Mutex::new(NonceCache::new()));
    let config = Arc::new(config);

    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("accept() on IPC socket failed")?;

        let dsa = Arc::clone(&dsa);
        let config = Arc::clone(&config);
        let nonce_cache = Arc::clone(&nonce_cache);

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, &config, &dsa, &nonce_cache).await
            {
                warn!(error = %e, "IPC connection error");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Handle a single connection — enforces all security invariants.
///
/// Returns `Ok(())` on success or any handled error.  Only returns `Err` if
/// the connection cannot be cleanly closed.
async fn handle_connection(
    stream: UnixStream,
    config: &HandlerConfig,
    dsa: &Arc<dyn DigitalSignature>,
    nonce_cache: &Arc<Mutex<NonceCache>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Wrap the entire read-parse-respond in a timeout to prevent slow-write
    // attacks from occupying a task indefinitely.
    let result = tokio::time::timeout(
        Duration::from_secs(CONNECTION_TIMEOUT_SECS),
        process_message(&mut reader, &mut writer, config, dsa, nonce_cache),
    )
    .await;

    match result {
        Ok(inner) => inner,
        Err(_elapsed) => {
            warn!("IPC connection timed out");
            // Best-effort close — ignore error since we're cleaning up.
            let _ = writer.write_all(b"ERR:timeout\n").await;
            Ok(())
        }
    }
}

/// Core message processing — called inside the connection timeout.
#[allow(clippy::too_many_lines)]
async fn process_message(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    config: &HandlerConfig,
    dsa: &Arc<dyn DigitalSignature>,
    nonce_cache: &Arc<Mutex<NonceCache>>,
) -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // Step 1: Read one newline-delimited message with a size cap.
    // -----------------------------------------------------------------------
    let mut line = String::with_capacity(MAX_MSG_BYTES);
    let bytes_read = reader
        .read_line(&mut line)
        .await
        .context("failed to read from IPC socket")?;

    if bytes_read == 0 {
        return Ok(()); // Client disconnected before sending anything.
    }

    if bytes_read > MAX_MSG_BYTES {
        warn!(
            bytes = bytes_read,
            limit = MAX_MSG_BYTES,
            "IPC message exceeds size limit, rejecting"
        );
        writer.write_all(b"ERR:message_too_large\n").await?;
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Step 2: Parse the outer SignedBundle envelope.
    // -----------------------------------------------------------------------
    let bundle: SignedBundle = match serde_json::from_str(line.trim()) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to parse SignedBundle JSON");
            writer.write_all(b"ERR:parse_error\n").await?;
            return Ok(());
        }
    };

    // -----------------------------------------------------------------------
    // Step 3: Verify ML-DSA-65 signature BEFORE decoding payload.
    //
    // The signature covers the raw payload bytes (the hex string itself, not
    // the decoded JSON).  This eliminates any ambiguity about what was signed.
    //
    // SECURITY: if verification fails, we respond with a generic error and
    // do NOT reveal which field was wrong — this prevents oracle attacks.
    // -----------------------------------------------------------------------
    let Ok(sig_bytes) = hex::decode(&bundle.signature) else {
        warn!("ML-DSA-65 signature field is not valid hex — rejecting");
        writer.write_all(b"ERR:invalid_signature\n").await?;
        return Ok(());
    };

    let sig = Signature(sig_bytes);

    if let Err(e) = dsa.verify(
        &config.verifier_pubkey,
        bundle.payload.as_bytes(),
        &sig,
    ) {
        warn!(
            error = %e,
            "ML-DSA-65 signature FAILED — bundle rejected"
        );
        // Generic error response — do not expose verification internals.
        writer.write_all(b"ERR:invalid_signature\n").await?;
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Step 4: Decode payload hex → JSON → RuleBundle.
    // Only reached after signature is verified.
    // -----------------------------------------------------------------------
    let Ok(payload_bytes) = hex::decode(&bundle.payload) else {
        warn!("payload field is not valid hex (post-sig-verify)");
        writer.write_all(b"ERR:parse_error\n").await?;
        return Ok(());
    };

    let Ok(rule): Result<RuleBundle, _> = serde_json::from_slice(&payload_bytes) else {
        warn!("RuleBundle JSON parse failed (post-sig-verify)");
        writer.write_all(b"ERR:parse_error\n").await?;
        return Ok(());
    };

    // -----------------------------------------------------------------------
    // Step 5: Validate all bundle fields (version, reason, nonce, timestamp).
    // -----------------------------------------------------------------------
    let network = match rule.validate_and_parse() {
        Ok(net) => net,
        Err(e) => {
            warn!(error = %e, "RuleBundle validation failed");
            let msg = format!("ERR:validation:{e}\n");
            writer.write_all(msg.as_bytes()).await?;
            return Ok(());
        }
    };

    // -----------------------------------------------------------------------
    // Step 6: Anti-replay — reject if this nonce was seen within the window.
    // -----------------------------------------------------------------------
    {
        let mut cache = nonce_cache.lock().await;
        if cache.check_and_insert(&rule.nonce) {
            warn!(
                nonce = %rule.nonce,
                "replay detected — nonce already seen in window"
            );
            writer.write_all(b"ERR:replay_detected\n").await?;
            return Ok(());
        }
    }

    // -----------------------------------------------------------------------
    // Step 7: Sacrosanct check — RUST ENFORCEMENT (Invariant #5).
    //
    // This check MUST remain in Rust.  Python-only enforcement is insufficient
    // (red team finding RT-M01: a compromised Cortex bypasses Python checks).
    // -----------------------------------------------------------------------
    if config.sacrosanct.would_affect_sacrosanct(network) {
        warn!(
            %network,
            "attempt to affect sacrosanct network REJECTED (Invariant #5)"
        );
        writer.write_all(b"ERR:sacrosanct_violation\n").await?;
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Step 8: Apply rule to nftables — only reached if ALL checks passed.
    // -----------------------------------------------------------------------
    if let Err(e) = nft::apply_rule(&rule, network) {
        error!(
            error = %e,
            %network,
            action = ?rule.action,
            "nftables apply_rule failed"
        );
        let msg = format!("ERR:nft:{e}\n");
        writer.write_all(msg.as_bytes()).await?;
        return Ok(());
    }

    info!(
        action = ?rule.action,
        %network,
        reason = %rule.reason,
        duration_secs = rule.duration_secs,
        "rule APPLIED successfully"
    );

    writer.write_all(b"APPLIED\n").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::sacrosanct::SacrosanctList;
    use ipnetwork::IpNetwork;

    // ---- NonceCache --------------------------------------------------------

    #[test]
    fn test_nonce_cache_accepts_new_nonce() {
        let mut cache = NonceCache::new();
        assert!(
            !cache.check_and_insert("aabbccddeeff00112233445566778899"),
            "first insert must return false (not a replay)"
        );
    }

    #[test]
    fn test_nonce_cache_detects_replay() {
        let mut cache = NonceCache::new();
        cache.check_and_insert("aabbccddeeff00112233445566778899");
        assert!(
            cache.check_and_insert("aabbccddeeff00112233445566778899"),
            "second insert of same nonce must return true (replay detected)"
        );
    }

    #[test]
    fn test_nonce_cache_accepts_distinct_nonces() {
        let mut cache = NonceCache::new();
        assert!(!cache.check_and_insert("nonce_one_000000000000000000000000"));
        assert!(!cache.check_and_insert("nonce_two_000000000000000000000000"));
        assert!(!cache.check_and_insert("nonce_three_00000000000000000000000"));
    }

    // ---- Sacrosanct enforcement (Invariant #5) -----------------------------
    //
    // This test must pass on every commit that touches the IPC handler.
    // It directly tests the Rust-layer sacrosanct enforcement that handler.rs
    // calls at Step 7 of process_message().

    #[test]
    fn test_sacrosanct_ip_cannot_be_blocked() {
        let sacrosanct = SacrosanctList::baseline_only();

        // Exact loopback IPv4 address.
        let loopback4: IpNetwork = "127.0.0.1/32".parse().expect("valid CIDR");
        assert!(
            sacrosanct.would_affect_sacrosanct(loopback4),
            "127.0.0.1/32 must be rejected by sacrosanct check"
        );

        // Supernet attack: blocking 127.0.0.0/8 would deny all loopback.
        let loopback4_net: IpNetwork = "127.0.0.0/8".parse().expect("valid CIDR");
        assert!(
            sacrosanct.would_affect_sacrosanct(loopback4_net),
            "127.0.0.0/8 supernet must be rejected (would block loopback)"
        );

        // IPv6 loopback.
        let loopback6: IpNetwork = "::1/128".parse().expect("valid CIDR");
        assert!(
            sacrosanct.would_affect_sacrosanct(loopback6),
            "::1/128 must be rejected by sacrosanct check"
        );

        // A normal external IP must NOT be rejected.
        let external: IpNetwork = "8.8.8.8/32".parse().expect("valid CIDR");
        assert!(
            !sacrosanct.would_affect_sacrosanct(external),
            "external IP must not be protected by baseline sacrosanct list"
        );
    }
}
