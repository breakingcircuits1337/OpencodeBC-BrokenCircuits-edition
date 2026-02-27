//! nftables integration — applying VGLF rule bundles to the kernel packet filter.
//!
//! # Safety model
//!
//! - Uses `Command::new("nft")` with **explicit argument list** — never a shell.
//!   There is no `sh -c` anywhere in this module.
//! - The network address passed to nft comes from `IpNetwork::to_string()`, which
//!   produces only valid CIDR notation (digits, dots, colons, slashes).
//! - A secondary character-allowlist check (`is_safe_nft_operand`) is applied
//!   before constructing the argument list — belt-and-suspenders.
//! - nft stdout is discarded; stderr is captured for error reporting only.
//!
//! # Dry-run mode
//!
//! When the `VGLF_DRY_RUN` environment variable is `"true"`, all calls to
//! `apply_rule` log what would be done but do not execute `nft`.  This is the
//! default in the development `settings.json`.

use std::process::{Command, Stdio};

use ipnetwork::IpNetwork;
use tracing::{info, warn};

use crate::ipc::protocol::{RuleAction, RuleBundle};

// nftables table/set names must match tier0-ratelimit/nftables.conf exactly.
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "vglf";
const SET_BLOCKLIST4: &str = "blocklist4";
const SET_BLOCKLIST6: &str = "blocklist6";

/// Apply a validated rule bundle to nftables.
///
/// # Errors
///
/// Returns [`NftError`] if the argument string is unsafe, or if the `nft`
/// command fails or cannot be spawned.
pub fn apply_rule(bundle: &RuleBundle, network: IpNetwork) -> Result<(), NftError> {
    if std::env::var("VGLF_DRY_RUN").as_deref() == Ok("true") {
        info!(
            action = ?bundle.action,
            %network,
            dry_run = true,
            "DRY-RUN: would apply nftables rule"
        );
        return Ok(());
    }

    let set_name = match network {
        IpNetwork::V4(_) => SET_BLOCKLIST4,
        IpNetwork::V6(_) => SET_BLOCKLIST6,
    };

    // IpNetwork::to_string() produces only valid CIDR notation.
    // The secondary check rejects anything unexpected before it reaches nft.
    let ip_str = network.to_string();
    if !is_safe_nft_operand(&ip_str) {
        return Err(NftError::UnsafeOperand(ip_str));
    }

    // Build the set literal: "{ 1.2.3.4/32 }"
    let set_literal = format!("{{ {ip_str} }}");

    // NEVER: Command::new("sh").arg("-c").arg(...)
    // ALWAYS: explicit argument list, no shell interpretation
    // nft add|delete element inet vglf <set> { <cidr> }
    let verb = match bundle.action {
        RuleAction::Block => "add",
        RuleAction::Allow => "delete",
    };
    let args: Vec<&str> = vec!["element", NFT_FAMILY, NFT_TABLE, set_name, &set_literal];

    info!(
        action = ?bundle.action,
        %network,
        set = set_name,
        "applying nftables rule"
    );

    let output = Command::new("nft")
        .arg(verb)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(NftError::Spawn)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        warn!(%stderr, "nft command failed");
        return Err(NftError::CommandFailed(stderr));
    }

    Ok(())
}

/// Returns `true` if the string contains only characters safe to pass as an
/// nftables set element operand.
///
/// Valid IPv4/IPv6 CIDR strings contain only:
/// - ASCII hex digits: `0–9`, `a–f`, `A–F`
/// - Separators: `.` `:` `/`
///
/// Any other character (space, semicolon, `$`, backtick, etc.) indicates
/// something unexpected has occurred and the string must be rejected.
fn is_safe_nft_operand(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
}

/// Errors from the nftables integration layer.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("unsafe character in network operand: {0:?}")]
    UnsafeOperand(String),

    #[error("failed to spawn nft: {0}")]
    Spawn(#[source] std::io::Error),

    #[error("nft command returned non-zero exit: {0}")]
    CommandFailed(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_ipv4_cidr() {
        assert!(is_safe_nft_operand("192.168.1.1/32"));
        assert!(is_safe_nft_operand("10.0.0.0/8"));
    }

    #[test]
    fn test_safe_ipv6_cidr() {
        assert!(is_safe_nft_operand("2001:db8::1/128"));
        assert!(is_safe_nft_operand("::1/128"));
        assert!(is_safe_nft_operand("fe80::/10"));
    }

    #[test]
    fn test_rejects_shell_injection() {
        assert!(!is_safe_nft_operand("1.2.3.4; rm -rf /"));
        assert!(!is_safe_nft_operand("1.2.3.4 && nft flush ruleset"));
        assert!(!is_safe_nft_operand("$(whoami)"));
        assert!(!is_safe_nft_operand("`id`"));
        assert!(!is_safe_nft_operand("1.2.3.4\nnft flush ruleset"));
    }

    #[test]
    fn test_rejects_empty_string() {
        assert!(!is_safe_nft_operand(""));
    }

    #[test]
    fn test_rejects_spaces() {
        assert!(!is_safe_nft_operand("1.2.3.4 /32"));
    }

    #[test]
    fn test_ipnetwork_tostring_is_always_safe() {
        // Confirm that IpNetwork::to_string() output always passes the check.
        let cases = ["192.168.0.0/16", "10.0.0.1/32", "::1/128", "2001:db8::/32"];
        for case in &cases {
            let net: IpNetwork = case.parse().expect("valid");
            assert!(
                is_safe_nft_operand(&net.to_string()),
                "IpNetwork::to_string() produced unsafe string for {case}"
            );
        }
    }
}
