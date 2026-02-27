//! IPC wire protocol between the Python Cortex engine and the Rust IPC handler.
//!
//! # Trust model
//!
//! The Python Cortex is **untrusted** from the Rust handler's perspective.
//! Every incoming message must pass ML-DSA-65 signature verification before
//! any field is parsed or any rule is applied.  A compromised Cortex process
//! cannot push unsigned rules.
//!
//! # Wire format
//!
//! A single newline-delimited JSON message per connection:
//! ```json
//! {
//!   "payload": "<hex-encoded JSON of RuleBundle>",
//!   "signature": "<hex-encoded ML-DSA-65 signature over payload bytes>"
//! }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

/// Protocol version.  Reject any bundle whose version != this.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum raw message size accepted from the socket (bytes).
/// Prevents memory exhaustion from a malicious or buggy Cortex process.
pub const MAX_MSG_BYTES: usize = 8_192;

/// Maximum age of a rule bundle (seconds).
/// Bundles older than this are rejected as potential replays.
pub const MAX_BUNDLE_AGE_SECS: u64 = 30;

/// Length of the anti-replay nonce (bytes).
pub const NONCE_LEN: usize = 16;

/// Maximum length of the human-readable `reason` field (bytes).
pub const MAX_REASON_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// A signed rule bundle received from the Cortex engine over the IPC socket.
///
/// The `payload` field is hex-encoded JSON of a [`RuleBundle`].
/// The `signature` field is the hex-encoded ML-DSA-65 signature over
/// the *raw bytes* of `payload` (i.e. over the hex string itself, not the
/// decoded JSON — this prevents any ambiguity in what was signed).
///
/// INVARIANT: The signature is verified *before* `payload` is decoded.
/// A message that fails signature verification is silently dropped.
#[derive(Debug, Deserialize)]
pub struct SignedBundle {
    /// Hex-encoded JSON payload.
    pub payload: String,
    /// Hex-encoded ML-DSA-65 signature over `payload.as_bytes()`.
    pub signature: String,
}

/// The inner, unsigned rule bundle — only parsed after signature verification.
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleBundle {
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u8,

    /// The action to take.
    pub action: RuleAction,

    /// Target network in CIDR notation (`"1.2.3.4/32"` or `"::1/128"`).
    /// Parsed and validated via [`ipnetwork::IpNetwork`].
    pub network: String,

    /// How long the rule should remain active (seconds).
    pub duration_secs: u64,

    /// Human-readable reason string.  Maximum [`MAX_REASON_BYTES`] bytes.
    pub reason: String,

    /// Unix timestamp (seconds since epoch) when this bundle was created.
    pub timestamp: u64,

    /// 16 random bytes (hex-encoded) for anti-replay protection.
    pub nonce: String,
}

/// The action a rule bundle requests.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleAction {
    /// Add this network to the blocklist.
    Block,
    /// Remove this network from the blocklist (allowlist override).
    Allow,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Errors produced during rule bundle validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("unsupported protocol version {0}, expected {PROTOCOL_VERSION}")]
    UnsupportedVersion(u8),

    #[error("reason field exceeds {MAX_REASON_BYTES} bytes")]
    ReasonTooLong,

    #[error("nonce is not valid hex or wrong length")]
    InvalidNonce,

    #[error("bundle timestamp is too old (possible replay attack)")]
    BundleTooOld,

    #[error("bundle timestamp is in the future (clock skew > {MAX_BUNDLE_AGE_SECS}s)")]
    BundleFuture,

    #[error("invalid network address: {0}")]
    InvalidNetwork(String),
}

impl RuleBundle {
    /// Validate all bundle fields and return the parsed [`IpNetwork`].
    ///
    /// This is the only gateway from untrusted wire bytes to a typed network
    /// address.  All checks run unconditionally — no early return on the first
    /// failure except for the timestamp check (which is the cheapest).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if any field is invalid.
    pub fn validate_and_parse(&self) -> Result<IpNetwork, ValidationError> {
        // Version check first — reject unknown formats immediately.
        if self.version != PROTOCOL_VERSION {
            return Err(ValidationError::UnsupportedVersion(self.version));
        }

        // Reason length — prevent log injection via oversized strings.
        if self.reason.len() > MAX_REASON_BYTES {
            return Err(ValidationError::ReasonTooLong);
        }

        // Nonce validation — must be hex-encoded and exactly NONCE_LEN bytes.
        let nonce_bytes = hex::decode(&self.nonce)
            .map_err(|_| ValidationError::InvalidNonce)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(ValidationError::InvalidNonce);
        }

        // Timestamp validation — reject stale and future-dated bundles.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age = now.saturating_sub(self.timestamp);
        if age > MAX_BUNDLE_AGE_SECS {
            return Err(ValidationError::BundleTooOld);
        }
        if self.timestamp > now + MAX_BUNDLE_AGE_SECS {
            return Err(ValidationError::BundleFuture);
        }

        // Network address — the only type that can reach nftables.
        let network: IpNetwork = self
            .network
            .parse()
            .map_err(|_| ValidationError::InvalidNetwork(self.network.clone()))?;

        Ok(network)
    }
}
