//! IPC layer — the boundary between the Python Cortex engine and Rust kernel
//! rule enforcement.
//!
//! # Module overview
//!
//! | Module       | Purpose                                               |
//! |--------------|-------------------------------------------------------|
//! | `protocol`   | Wire types: [`SignedBundle`], [`RuleBundle`]          |
//! | `sacrosanct` | Immutable protected IP list (Invariant #5)            |
//! | `nft`        | nftables integration (safe argument list, no shell)   |
//! | `handler`    | Async Tokio Unix socket listener + trust boundary     |
//!
//! # Trust model
//!
//! The Python Cortex is treated as **untrusted** by the Rust IPC handler.
//! All messages must carry a valid ML-DSA-65 signature before any field is
//! read.  The sacrosanct check is enforced here in Rust, not in Python.

pub mod handler;
pub mod nft;
pub mod protocol;
pub mod sacrosanct;

pub use protocol::{RuleAction, RuleBundle, SignedBundle};
pub use sacrosanct::SacrosanctList;
