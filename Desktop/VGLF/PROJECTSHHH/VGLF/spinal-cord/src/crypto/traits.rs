//! Crypto agility traits for VGLF.
//!
//! Every algorithm reference in the codebase flows through these traits.
//! Never hardcode algorithm names outside this module.

use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error type for all cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenFailed(String),

    /// Encapsulation failed.
    #[error("encapsulation failed: {0}")]
    EncapsulateFailed(String),

    /// Decapsulation failed.
    #[error("decapsulation failed: {0}")]
    DecapsulateFailed(String),

    /// Signing failed.
    #[error("signing failed: {0}")]
    SignFailed(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerifyFailed(String),

    /// ONNX model SHA-256 hash did not match the pinned value.
    #[error("model hash mismatch for {path}")]
    ModelHashMismatch {
        /// Path to the model file whose hash did not match.
        path: PathBuf,
    },

    /// ML-DSA-65 signature over a model file or rule bundle was invalid.
    #[error("model signature invalid")]
    ModelSignatureInvalid,
}

/// A public key as an opaque byte vector.
///
/// For the hybrid KEM this contains `ml_kem_pk || x25519_pk`.
#[derive(Debug, Clone)]
pub struct PublicKey(pub Vec<u8>);

/// A secret key as an opaque byte vector, zeroized on drop.
///
/// For the hybrid KEM this contains `ml_kem_sk || x25519_sk_der`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub Vec<u8>);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// An encapsulated ciphertext as an opaque byte vector.
///
/// For the hybrid KEM this contains `ml_kem_ct || x25519_ephemeral_pub`.
#[derive(Debug, Clone)]
pub struct Ciphertext(pub Vec<u8>);

/// A 32-byte shared secret, zeroized on drop.
///
/// Always the output of `SHA3-256(ml_kem_ss || x25519_ss)` in the hybrid KEM.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

/// A digital signature as an opaque byte vector.
#[derive(Debug, Clone)]
pub struct Signature(pub Vec<u8>);

/// Crypto agility trait for key encapsulation mechanisms.
///
/// All KEM implementations must go through this trait. Never call
/// algorithm-specific code directly outside the implementing module.
pub trait KeyEncapsulation: Send + Sync + 'static {
    /// A stable, compile-time identifier for this algorithm.
    ///
    /// Example: `"ML-KEM-768+X25519-SHA3-256"`
    fn algorithm_id(&self) -> &'static str;

    /// Generate a fresh KEM keypair.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyGenFailed`] if the underlying RNG or key
    /// generation fails.
    fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), CryptoError>;

    /// Encapsulate a shared secret to `pk`.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EncapsulateFailed`] on failure.
    fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), CryptoError>;

    /// Decapsulate `ct` using `sk`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecapsulateFailed`] on failure.
    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, CryptoError>;
}

/// Crypto agility trait for digital signature schemes.
///
/// All signature implementations must go through this trait.
pub trait DigitalSignature: Send + Sync + 'static {
    /// A stable, compile-time identifier for this algorithm.
    ///
    /// Example: `"ML-DSA-65"`
    fn algorithm_id(&self) -> &'static str;

    /// Sign `msg` with `sk`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SignFailed`] on failure.
    fn sign(&self, sk: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError>;

    /// Verify `sig` over `msg` with `pk`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerifyFailed`] if the signature does not verify.
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError>;
}
