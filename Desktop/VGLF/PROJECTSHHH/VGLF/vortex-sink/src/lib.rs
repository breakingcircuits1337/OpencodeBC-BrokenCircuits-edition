#![deny(clippy::all, clippy::pedantic)]

//! Vortex Sink — VGLF Tier 2 persistence and integrity layer.
//!
//! # Purpose
//!
//! Receives traffic metadata records from the Tier 1 proxy (spinal-cord),
//! persists them with integrity guarantees, and mirrors threat events to
//! syslog for SIEM integration.
//!
//! # Architecture
//!
//! | Module        | Purpose                                              |
//! |---------------|------------------------------------------------------|
//! | `schema`      | Canonical record schema for VGLF traffic metadata    |
//! | `merkle`      | SHA3-256 Merkle hash chain for log integrity          |
//! | `syslog`      | RFC 5424 syslog mirror for SIEM integration           |
//! | `store`       | AES-256-GCM encrypted at-rest segment storage         |
//!
//! # Integrity model
//!
//! Every persisted segment is:
//! 1. Serialized to a canonical binary form (records + metadata).
//! 2. Chained into a SHA3-256 Merkle hash chain — each segment hash
//!    includes the previous segment hash, preventing silent deletion.
//! 3. Signed with ML-DSA-65 via the `DigitalSignature` trait.
//! 4. Encrypted at rest with AES-256-GCM before writing to disk.
//!
//! An adversary cannot tamper with, reorder, or silently delete log segments
//! without breaking the chain.

pub mod merkle;
pub mod schema;
pub mod store;
pub mod syslog;
