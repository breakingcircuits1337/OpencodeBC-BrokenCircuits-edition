//! Canonical record schema for VGLF traffic metadata.
//!
//! # Schema definition
//!
//! Every record flowing through the VGLF pipeline has a fixed schema.
//! This module defines that schema and provides validation for incoming
//! records before they enter the persistence layer.
//!
//! # IPv6 parity
//!
//! Source and destination addresses are stored as 128-bit byte arrays.
//! IPv4 addresses are stored in IPv4-mapped IPv6 format (`::ffff:a.b.c.d`)
//! to maintain a single code path for both address families.

use std::net::{IpAddr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum length of the reason/tag field (bytes).
const MAX_TAG_LEN: usize = 256;

/// Maximum number of records in a single batch.
pub const MAX_BATCH_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Traffic record
// ---------------------------------------------------------------------------

/// A single traffic metadata record in the VGLF pipeline.
///
/// This is the canonical internal representation.  All fields are typed
/// and validated — no raw strings from untrusted sources reach the
/// persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    /// Unix timestamp in microseconds when this record was captured.
    pub timestamp_us: u64,

    /// Source IP address (IPv4 or IPv6).
    pub src_addr: IpAddr,

    /// Destination IP address (IPv4 or IPv6).
    pub dst_addr: IpAddr,

    /// Source port (0 for ICMP/non-port protocols).
    pub src_port: u16,

    /// Destination port (0 for ICMP/non-port protocols).
    pub dst_port: u16,

    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, etc.).
    pub ip_proto: u8,

    /// Packet size in bytes.
    pub packet_bytes: u32,

    /// VGLF tier that captured this record (0=nftables, 1=proxy, 2=sink).
    pub tier: u8,

    /// Classification tag from the ONNX reflex model or Cortex analysis.
    /// Empty string if not yet classified.
    pub tag: String,

    /// Threat score from the reflex model (0.0 = benign, 1.0 = certain threat).
    pub threat_score: f32,
}

/// Errors produced during record validation.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("tag exceeds maximum length ({MAX_TAG_LEN} bytes)")]
    TagTooLong,

    #[error("threat_score {0} is not in [0.0, 1.0]")]
    ThreatScoreOutOfRange(f32),

    #[error("batch exceeds maximum size ({MAX_BATCH_SIZE} records)")]
    BatchTooLarge,

    #[error("timestamp is zero (likely uninitialized)")]
    ZeroTimestamp,
}

impl TrafficRecord {
    /// Validate this record's fields.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] if any field violates the schema constraints.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.tag.len() > MAX_TAG_LEN {
            return Err(SchemaError::TagTooLong);
        }
        if !(0.0..=1.0).contains(&self.threat_score) {
            return Err(SchemaError::ThreatScoreOutOfRange(self.threat_score));
        }
        if self.timestamp_us == 0 {
            return Err(SchemaError::ZeroTimestamp);
        }
        Ok(())
    }

    /// Create a record with the current system time.
    ///
    /// # Panics
    ///
    /// Panics only if the system clock is before the Unix epoch (impossible
    /// in practice on modern systems).
    #[must_use]
    pub fn now(
        src_addr: IpAddr,
        dst_addr: IpAddr,
        src_port: u16,
        dst_port: u16,
        ip_proto: u8,
        packet_bytes: u32,
    ) -> Self {
        #[allow(clippy::cast_possible_truncation)] // clamped to u64::MAX before cast
        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;

        Self {
            timestamp_us,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            ip_proto,
            packet_bytes,
            tier: 1,
            tag: String::new(),
            threat_score: 0.0,
        }
    }

    /// Convert source address to IPv4-mapped IPv6 for uniform storage.
    #[must_use]
    pub fn src_addr_v6(&self) -> Ipv6Addr {
        ip_to_v6(self.src_addr)
    }

    /// Convert destination address to IPv4-mapped IPv6 for uniform storage.
    #[must_use]
    pub fn dst_addr_v6(&self) -> Ipv6Addr {
        ip_to_v6(self.dst_addr)
    }
}

/// Convert an IP address to its IPv6 representation.
///
/// IPv4 addresses are mapped to `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2).
/// IPv6 addresses are returned as-is.
fn ip_to_v6(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Validate a batch of records.
///
/// # Errors
///
/// Returns [`SchemaError`] if the batch is too large or any record is invalid.
pub fn validate_batch(records: &[TrafficRecord]) -> Result<(), SchemaError> {
    if records.len() > MAX_BATCH_SIZE {
        return Err(SchemaError::BatchTooLarge);
    }
    for record in records {
        record.validate()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_ipv4_record() -> TrafficRecord {
        TrafficRecord {
            timestamp_us: 1_709_000_000_000_000,
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            src_port: 54321,
            dst_port: 443,
            ip_proto: 6, // TCP
            packet_bytes: 1500,
            tier: 1,
            tag: "suspicious_scan".to_string(),
            threat_score: 0.87,
        }
    }

    fn sample_ipv6_record() -> TrafficRecord {
        TrafficRecord {
            timestamp_us: 1_709_000_000_000_000,
            src_addr: IpAddr::V6("2001:db8::1".parse().expect("valid")),
            dst_addr: IpAddr::V6("2001:db8::2".parse().expect("valid")),
            src_port: 54321,
            dst_port: 443,
            ip_proto: 6,
            packet_bytes: 1500,
            tier: 1,
            tag: "benign".to_string(),
            threat_score: 0.05,
        }
    }

    // ---- Validation ---------------------------------------------------------

    #[test]
    fn test_valid_ipv4_record() {
        sample_ipv4_record().validate().expect("valid record");
    }

    #[test]
    fn test_valid_ipv6_record() {
        sample_ipv6_record().validate().expect("valid record");
    }

    #[test]
    fn test_tag_too_long() {
        let mut r = sample_ipv4_record();
        r.tag = "x".repeat(MAX_TAG_LEN + 1);
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_threat_score_too_high() {
        let mut r = sample_ipv4_record();
        r.threat_score = 1.01;
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_threat_score_negative() {
        let mut r = sample_ipv4_record();
        r.threat_score = -0.1;
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_zero_timestamp() {
        let mut r = sample_ipv4_record();
        r.timestamp_us = 0;
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_threat_score_boundaries() {
        let mut r = sample_ipv4_record();
        r.threat_score = 0.0;
        r.validate().expect("0.0 is valid");
        r.threat_score = 1.0;
        r.validate().expect("1.0 is valid");
    }

    // ---- Batch validation ---------------------------------------------------

    #[test]
    fn test_batch_too_large() {
        let records: Vec<TrafficRecord> = (0..=MAX_BATCH_SIZE)
            .map(|i| {
                let mut r = sample_ipv4_record();
                r.timestamp_us += i as u64;
                r
            })
            .collect();
        assert!(validate_batch(&records).is_err());
    }

    #[test]
    fn test_empty_batch_valid() {
        validate_batch(&[]).expect("empty batch is valid");
    }

    // ---- IPv6 mapping -------------------------------------------------------

    #[test]
    fn test_ipv4_mapped_to_v6() {
        let r = sample_ipv4_record();
        let v6 = r.src_addr_v6();
        // 192.168.1.100 → ::ffff:192.168.1.100 → ::ffff:c0a8:164
        assert!(v6.to_ipv4_mapped().is_some());
        assert_eq!(
            v6.to_ipv4_mapped().expect("mapped"),
            Ipv4Addr::new(192, 168, 1, 100)
        );
    }

    #[test]
    fn test_ipv6_unchanged() {
        let r = sample_ipv6_record();
        let v6 = r.src_addr_v6();
        let expected: Ipv6Addr = "2001:db8::1".parse().expect("valid");
        assert_eq!(v6, expected);
    }

    // ---- Record constructor -------------------------------------------------

    #[test]
    fn test_now_constructor() {
        let r = TrafficRecord::now(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            12345,
            80,
            6,
            512,
        );
        assert!(r.timestamp_us > 0);
        assert_eq!(r.tier, 1);
        assert!(r.tag.is_empty());
        r.validate().expect("now() record must be valid");
    }
}
