//! Crypto agility layer for VGLF.
//!
//! All algorithm references flow through the traits defined here.
//! Never hardcode algorithm names outside `traits.rs`.

pub mod dsa;
pub mod kem;
pub mod traits;

pub use dsa::MlDsa65;
pub use traits::{
    Ciphertext, CryptoError, DigitalSignature, KeyEncapsulation, PublicKey, SecretKey,
    SharedSecret, Signature,
};
