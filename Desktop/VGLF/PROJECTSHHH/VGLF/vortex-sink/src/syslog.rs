//! Syslog mirror — RFC 5424 formatted output for SIEM integration.
//!
//! # Purpose
//!
//! VGLF mirrors high-threat traffic records to syslog so that external SIEM
//! systems (Splunk, Elastic, `QRadar`, etc.) can ingest events without direct
//! access to the VGLF persistence layer.
//!
//! # Format
//!
//! Events are formatted as RFC 5424 structured data messages:
//!
//! ```text
//! <priority>1 timestamp hostname vglf - - [vglf@0 src="..." dst="..." ...] msg
//! ```
//!
//! # IPv6 parity
//!
//! All address fields are formatted with their native representation (IPv4 as
//! dotted-decimal, IPv6 as colon-hex).  SIEM parsers must handle both.

use std::fmt;
use std::net::IpAddr;

use crate::schema::TrafficRecord;

/// Syslog facility for VGLF events (local0 = 16).
const FACILITY_LOCAL0: u8 = 16;

/// RFC 5424 syslog severity levels relevant to VGLF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Emergency: system is unusable (unused by VGLF).
    Emergency = 0,
    /// Alert: action must be taken immediately.
    Alert = 1,
    /// Critical: critical conditions (`threat_score` >= 0.9).
    Critical = 2,
    /// Warning: warning conditions (`threat_score` >= 0.7).
    Warning = 4,
    /// Notice: normal but significant (`threat_score` >= 0.5).
    Notice = 5,
    /// Informational: informational messages (`threat_score` < 0.5).
    Informational = 6,
}

impl Severity {
    /// Map a threat score to a syslog severity.
    ///
    /// | Threat score | Severity       |
    /// |-------------|----------------|
    /// | >= 0.9      | Critical (2)   |
    /// | >= 0.7      | Warning (4)    |
    /// | >= 0.5      | Notice (5)     |
    /// | < 0.5       | Informational (6) |
    #[must_use]
    pub fn from_threat_score(score: f32) -> Self {
        if score >= 0.9 {
            Self::Critical
        } else if score >= 0.7 {
            Self::Warning
        } else if score >= 0.5 {
            Self::Notice
        } else {
            Self::Informational
        }
    }

    /// Compute the RFC 5424 PRI value: `facility * 8 + severity`.
    #[must_use]
    pub fn pri(self) -> u8 {
        FACILITY_LOCAL0 * 8 + self as u8
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emergency => write!(f, "EMERGENCY"),
            Self::Alert => write!(f, "ALERT"),
            Self::Critical => write!(f, "CRITICAL"),
            Self::Warning => write!(f, "WARNING"),
            Self::Notice => write!(f, "NOTICE"),
            Self::Informational => write!(f, "INFO"),
        }
    }
}

// ---------------------------------------------------------------------------
// Syslog message formatting
// ---------------------------------------------------------------------------

/// A formatted syslog message ready for transmission.
#[derive(Debug, Clone)]
pub struct SyslogMessage {
    /// The RFC 5424 formatted message string.
    pub message: String,

    /// The severity level for routing/filtering.
    pub severity: Severity,
}

/// Format a traffic record as an RFC 5424 syslog message.
///
/// The structured data section contains all relevant fields for SIEM parsing.
/// The message body is a human-readable summary.
#[must_use]
pub fn format_record(record: &TrafficRecord, hostname: &str) -> SyslogMessage {
    let severity = Severity::from_threat_score(record.threat_score);
    let pri = severity.pri();

    // RFC 5424 timestamp: we use the record's microsecond timestamp.
    // Convert to ISO 8601 format (simplified — seconds precision from epoch).
    let timestamp_secs = record.timestamp_us / 1_000_000;

    // Escape structured data values (RFC 5424 §6.3.3: escape \, ], ").
    let tag = escape_sd_value(&record.tag);
    let src = format_addr(record.src_addr, record.src_port);
    let dst = format_addr(record.dst_addr, record.dst_port);

    let message = format!(
        "<{pri}>1 {timestamp_secs} {hostname} vglf - - \
         [vglf@0 src=\"{src}\" dst=\"{dst}\" proto=\"{proto}\" \
         bytes=\"{bytes}\" tier=\"{tier}\" tag=\"{tag}\" \
         score=\"{score:.2}\" severity=\"{severity}\"] \
         {severity}: {src} -> {dst} score={score:.2} tag={raw_tag}",
        proto = record.ip_proto,
        bytes = record.packet_bytes,
        tier = record.tier,
        score = record.threat_score,
        raw_tag = if record.tag.is_empty() { "-" } else { &record.tag },
    );

    SyslogMessage { message, severity }
}

/// Format a batch of records as syslog messages.
///
/// Only records with `threat_score >= threshold` are included.
/// This prevents flooding the SIEM with benign traffic.
#[must_use]
pub fn format_batch(
    records: &[TrafficRecord],
    hostname: &str,
    threshold: f32,
) -> Vec<SyslogMessage> {
    records
        .iter()
        .filter(|r| r.threat_score >= threshold)
        .map(|r| format_record(r, hostname))
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Format an IP:port pair for syslog output.
///
/// IPv6 addresses are bracketed: `[2001:db8::1]:443`.
/// IPv4 addresses use the standard format: `192.168.1.1:443`.
fn format_addr(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Escape a string for use as an RFC 5424 structured data value.
///
/// Per RFC 5424 §6.3.3, the characters `\`, `]`, and `"` must be escaped
/// with a backslash prefix.
fn escape_sd_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv4_record(score: f32) -> TrafficRecord {
        TrafficRecord {
            timestamp_us: 1_709_000_000_000_000,
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            src_port: 54321,
            dst_port: 443,
            ip_proto: 6,
            packet_bytes: 1500,
            tier: 1,
            tag: "port_scan".to_string(),
            threat_score: score,
        }
    }

    fn ipv6_record(score: f32) -> TrafficRecord {
        TrafficRecord {
            timestamp_us: 1_709_000_000_000_000,
            src_addr: IpAddr::V6("2001:db8::bad:1".parse().expect("valid")),
            dst_addr: IpAddr::V6("2001:db8::1".parse().expect("valid")),
            src_port: 54321,
            dst_port: 443,
            ip_proto: 6,
            packet_bytes: 1500,
            tier: 1,
            tag: "port_scan".to_string(),
            threat_score: score,
        }
    }

    // ---- Severity mapping ---------------------------------------------------

    #[test]
    fn test_severity_critical() {
        assert_eq!(Severity::from_threat_score(0.95), Severity::Critical);
        assert_eq!(Severity::from_threat_score(0.9), Severity::Critical);
        assert_eq!(Severity::from_threat_score(1.0), Severity::Critical);
    }

    #[test]
    fn test_severity_warning() {
        assert_eq!(Severity::from_threat_score(0.7), Severity::Warning);
        assert_eq!(Severity::from_threat_score(0.89), Severity::Warning);
    }

    #[test]
    fn test_severity_notice() {
        assert_eq!(Severity::from_threat_score(0.5), Severity::Notice);
        assert_eq!(Severity::from_threat_score(0.69), Severity::Notice);
    }

    #[test]
    fn test_severity_informational() {
        assert_eq!(Severity::from_threat_score(0.0), Severity::Informational);
        assert_eq!(Severity::from_threat_score(0.49), Severity::Informational);
    }

    // ---- PRI value ----------------------------------------------------------

    #[test]
    fn test_pri_critical() {
        // local0 (16) * 8 + critical (2) = 130
        assert_eq!(Severity::Critical.pri(), 130);
    }

    #[test]
    fn test_pri_informational() {
        // local0 (16) * 8 + informational (6) = 134
        assert_eq!(Severity::Informational.pri(), 134);
    }

    // ---- Message formatting (IPv4) ------------------------------------------

    #[test]
    fn test_format_ipv4_record() {
        let msg = format_record(&ipv4_record(0.95), "vglf-node01");
        assert!(msg.message.contains("<130>1")); // PRI for critical
        assert!(msg.message.contains("192.168.1.100:54321"));
        assert!(msg.message.contains("10.0.1.1:443"));
        assert!(msg.message.contains("port_scan"));
        assert!(msg.message.contains("score=\"0.95\""));
        assert_eq!(msg.severity, Severity::Critical);
    }

    // ---- Message formatting (IPv6) ------------------------------------------

    #[test]
    fn test_format_ipv6_record() {
        let msg = format_record(&ipv6_record(0.75), "vglf-node01");
        assert!(msg.message.contains("[2001:db8::bad:1]:54321"));
        assert!(msg.message.contains("[2001:db8::1]:443"));
        assert_eq!(msg.severity, Severity::Warning);
    }

    // ---- Batch filtering ----------------------------------------------------

    #[test]
    fn test_batch_threshold_filter() {
        let records = vec![
            ipv4_record(0.1),  // below threshold
            ipv4_record(0.8),  // above
            ipv6_record(0.3),  // below
            ipv6_record(0.95), // above
        ];
        let msgs = format_batch(&records, "test", 0.5);
        assert_eq!(msgs.len(), 2, "only records above threshold should be included");
    }

    #[test]
    fn test_batch_threshold_exact() {
        let records = vec![ipv4_record(0.5)]; // exactly at threshold
        let msgs = format_batch(&records, "test", 0.5);
        assert_eq!(msgs.len(), 1, "record at exact threshold should be included");
    }

    #[test]
    fn test_empty_batch() {
        let msgs = format_batch(&[], "test", 0.5);
        assert!(msgs.is_empty());
    }

    // ---- Escaping -----------------------------------------------------------

    #[test]
    fn test_escape_sd_value_clean() {
        assert_eq!(escape_sd_value("clean_tag"), "clean_tag");
    }

    #[test]
    fn test_escape_sd_value_special_chars() {
        assert_eq!(escape_sd_value(r"test\"), r"test\\");
        assert_eq!(escape_sd_value("test]"), "test\\]");
        assert_eq!(escape_sd_value(r#"test""#), r#"test\""#);
    }

    // ---- Address formatting -------------------------------------------------

    #[test]
    fn test_format_addr_ipv4() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(format_addr(addr, 80), "10.0.0.1:80");
    }

    #[test]
    fn test_format_addr_ipv6() {
        let addr = IpAddr::V6("2001:db8::1".parse().expect("valid"));
        assert_eq!(format_addr(addr, 443), "[2001:db8::1]:443");
    }

    #[test]
    fn test_format_addr_ipv6_loopback() {
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(format_addr(addr, 8080), "[::1]:8080");
    }
}
