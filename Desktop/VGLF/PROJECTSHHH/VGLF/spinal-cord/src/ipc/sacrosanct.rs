//! Sacrosanct IP enforcement — VGLF Security Invariant #5.
//!
//! This module is the Rust-layer enforcement of the sacrosanct list.
//! It is the **authoritative** check.  The Python Cortex also performs a
//! belt-and-suspenders check, but a compromised Cortex process cannot bypass
//! the check implemented here.
//!
//! # Overlap checking
//!
//! The check is not just exact-IP matching.  It detects CIDR overlap:
//! an attacker cannot block `127.0.0.0/8` to deny loopback traffic even if
//! `127.0.0.1/32` is the only entry in the sacrosanct list.
//!
//! # Mandatory baseline
//!
//! The following networks are **always** sacrosanct, regardless of
//! configuration.  They are hardcoded here and cannot be removed by any
//! config file, CLI flag, or code path:
//!
//! - `127.0.0.0/8`   — IPv4 loopback (RFC 5735)
//! - `::1/128`       — IPv6 loopback (RFC 4291)

use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Hardcoded baseline — these are burned in and cannot be overridden
// ---------------------------------------------------------------------------

const MANDATORY_BASELINE: &[&str] = &[
    "127.0.0.0/8", // IPv4 loopback — RFC 5735
    "::1/128",     // IPv6 loopback — RFC 4291
];

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

/// Parsed `sacrosanct.toml` structure.
#[derive(Debug, Deserialize)]
pub struct SacrosanctConfig {
    pub networks: Vec<SacrosanctEntry>,
}

/// A single entry in the sacrosanct config.
#[derive(Debug, Deserialize)]
pub struct SacrosanctEntry {
    pub cidr: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// SacrosanctList
// ---------------------------------------------------------------------------

/// The loaded, immutable sacrosanct network list.
///
/// Once constructed, this struct is `Send + Sync` and should be wrapped in
/// `Arc` to share across Tokio tasks.
#[derive(Debug)]
pub struct SacrosanctList {
    networks: Vec<IpNetwork>,
}

/// Errors produced when loading the sacrosanct list.
#[derive(Debug, thiserror::Error)]
pub enum SacrosanctError {
    #[error("invalid CIDR in sacrosanct config entry {entry:?}: {cidr:?}")]
    InvalidCidr { cidr: String, entry: String },
}

impl SacrosanctList {
    /// Construct the sacrosanct list from a parsed config.
    ///
    /// Always includes the mandatory baseline regardless of what the config
    /// contains.  Returns an error if any config entry is not valid CIDR.
    ///
    /// # Errors
    ///
    /// Returns [`SacrosanctError`] if any CIDR string is invalid.
    ///
    /// # Panics
    ///
    /// Does not panic in practice — the mandatory baseline CIDRs are hardcoded
    /// compile-time constants that are always valid CIDR strings.
    pub fn load(config: &SacrosanctConfig) -> Result<Self, SacrosanctError> {
        let mut networks: Vec<IpNetwork> = Vec::new();

        // Burn in the mandatory baseline first — these are immovable.
        for cidr in MANDATORY_BASELINE {
            networks.push(
                cidr.parse()
                    .expect("mandatory baseline CIDRs are always valid"),
            );
        }

        // Load site-specific entries from config.
        for entry in &config.networks {
            let net: IpNetwork = entry.cidr.parse().map_err(|_| SacrosanctError::InvalidCidr {
                cidr: entry.cidr.clone(),
                entry: entry.description.clone(),
            })?;
            // Avoid duplicates (config may repeat loopback for auditability).
            if !networks.contains(&net) {
                networks.push(net);
            }
        }

        tracing::info!(
            count = networks.len(),
            "sacrosanct list loaded ({} networks protected)",
            networks.len()
        );

        Ok(Self { networks })
    }

    /// Construct the minimal sacrosanct list containing only the mandatory
    /// baseline.  Used in tests and when no config file is present.
    ///
    /// # Panics
    ///
    /// Does not panic in practice — the baseline CIDRs are hardcoded
    /// compile-time constants that are always valid CIDR strings.
    #[must_use]
    pub fn baseline_only() -> Self {
        let networks = MANDATORY_BASELINE
            .iter()
            .map(|s| s.parse().expect("baseline CIDRs are always valid"))
            .collect();
        Self { networks }
    }

    /// Returns `true` if blocking `proposed` would affect any sacrosanct IP.
    ///
    /// Checks for **CIDR overlap** in addition to exact match.  An attacker
    /// cannot bypass this by proposing `127.0.0.0/8` when only `127.0.0.1/32`
    /// is in the list.
    ///
    /// IPv4 and IPv6 networks are checked independently and can never overlap
    /// with each other.
    #[must_use]
    pub fn would_affect_sacrosanct(&self, proposed: IpNetwork) -> bool {
        for protected in &self.networks {
            if networks_overlap(*protected, proposed) {
                tracing::warn!(
                    proposed = %proposed,
                    protected = %protected,
                    "sacrosanct overlap detected"
                );
                return true;
            }
        }
        false
    }

    /// Returns `true` if the given IP address is covered by any sacrosanct network.
    #[must_use]
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(ip))
    }

    /// Returns the number of protected networks (including baseline).
    #[must_use]
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Returns `true` if the list contains only the mandatory baseline.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CIDR overlap detection
// ---------------------------------------------------------------------------

/// Returns `true` if networks `a` and `b` share any IP address.
///
/// A network `X/n` overlaps with `Y/m` if `X` is contained in `Y` or
/// `Y` is contained in `X`.  Mismatched address families never overlap.
fn networks_overlap(a: IpNetwork, b: IpNetwork) -> bool {
    match (a, b) {
        (IpNetwork::V4(a4), IpNetwork::V4(b4)) => {
            // b's network address is within a, or a's network address is within b
            a4.contains(b4.network()) || b4.contains(a4.network())
        }
        (IpNetwork::V6(a6), IpNetwork::V6(b6)) => {
            a6.contains(b6.network()) || b6.contains(a6.network())
        }
        // IPv4 ↔ IPv6 — can never overlap
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn baseline() -> SacrosanctList {
        SacrosanctList::baseline_only()
    }

    // ---- Exact-match tests ------------------------------------------------

    #[test]
    fn test_loopback_ipv4_exact_blocked() {
        let s = baseline();
        let proposed: IpNetwork = "127.0.0.1/32".parse().expect("valid");
        assert!(
            s.would_affect_sacrosanct(proposed),
            "127.0.0.1/32 must be protected"
        );
    }

    #[test]
    fn test_loopback_ipv6_exact_blocked() {
        let s = baseline();
        let proposed: IpNetwork = "::1/128".parse().expect("valid");
        assert!(
            s.would_affect_sacrosanct(proposed),
            "::1/128 must be protected"
        );
    }

    // ---- CIDR-overlap tests (RT-M01 / red-team scenario 5) ---------------

    #[test]
    fn test_loopback_cidr_overlap_blocked() {
        let s = baseline();
        // Attacker tries to block the entire loopback range
        let proposed: IpNetwork = "127.0.0.0/8".parse().expect("valid");
        assert!(
            s.would_affect_sacrosanct(proposed),
            "127.0.0.0/8 overlaps sacrosanct 127.0.0.0/8"
        );
    }

    #[test]
    fn test_supernet_of_sacrosanct_blocked() {
        let mut config = SacrosanctConfig {
            networks: vec![SacrosanctEntry {
                cidr: "10.0.1.1/32".to_string(),
                description: "SCADA gateway".to_string(),
            }],
        };
        // Suppress unused warning in config
        config.networks[0].description = config.networks[0].description.clone();

        let s = SacrosanctList::load(&config).expect("valid config");

        // Attacker proposes to block the entire /24 containing the SCADA gateway
        let proposed: IpNetwork = "10.0.1.0/24".parse().expect("valid");
        assert!(
            s.would_affect_sacrosanct(proposed),
            "supernet containing sacrosanct IP must be rejected"
        );
    }

    #[test]
    fn test_non_sacrosanct_ipv4_allowed() {
        let s = baseline();
        let proposed: IpNetwork = "1.2.3.4/32".parse().expect("valid");
        assert!(
            !s.would_affect_sacrosanct(proposed),
            "external IP should not be protected"
        );
    }

    #[test]
    fn test_non_sacrosanct_ipv6_allowed() {
        let s = baseline();
        let proposed: IpNetwork = "2001:db8::1/128".parse().expect("valid");
        assert!(
            !s.would_affect_sacrosanct(proposed),
            "external IPv6 should not be protected"
        );
    }

    #[test]
    fn test_ipv4_does_not_affect_ipv6_sacrosanct() {
        let s = baseline();
        // An IPv4 block should never claim to affect an IPv6 sacrosanct entry
        let proposed: IpNetwork = "127.0.0.1/32".parse().expect("valid");
        // This should match (IPv4 loopback is sacrosanct), but not because of ::1
        assert!(s.would_affect_sacrosanct(proposed));
        // Verify that an IPv4 address is NOT contained in the IPv6 list
        assert!(!s.contains_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_loopback_ip_contained() {
        let s = baseline();
        assert!(s.contains_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(s.contains_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_baseline_minimum_size() {
        let s = baseline();
        assert!(
            s.len() >= MANDATORY_BASELINE.len(),
            "baseline must include at least all mandatory networks"
        );
    }
}
