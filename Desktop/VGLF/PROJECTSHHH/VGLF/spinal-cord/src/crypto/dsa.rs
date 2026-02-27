//! ML-DSA-65 digital signature implementation (FIPS 204).
//!
//! Implements the [`DigitalSignature`] crypto agility trait using `aws-lc-rs`
//! (`unstable` feature, which exposes the pqc-dsa API).
//! Never use `liboqs-rust` — it carries a hard "DO NOT USE IN PRODUCTION" warning
//! as of 2026.
//!
//! # Key format
//!
//! | Type        | Contents                    | Size (bytes) |
//! |-------------|-----------------------------|--------------|
//! | `PublicKey` | ML-DSA-65 raw public key    | 1952         |
//! | `SecretKey` | ML-DSA-65 32-byte seed (ζ) | 32           |
//! | `Signature` | ML-DSA-65 signature         | 3309         |
//!
//! The private key is stored as a 32-byte seed per FIPS 204 §3.6.
//! On each [`sign`] call the full key pair is reconstructed from the seed
//! via `PqdsaKeyPair::from_seed`.  This is deterministic and avoids persisting
//! the 4032-byte expanded key material.
//!
//! # NIST FIPS 204 ML-DSA-65 size constants
//!
//! | Parameter | Value | Source              |
//! |-----------|-------|---------------------|
//! | pk size   | 1952  | FIPS 204 Table 2     |
//! | seed size | 32    | FIPS 204 §3.6 (ζ)   |
//! | sig size  | 3309  | FIPS 204 Table 2     |

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};

use crate::crypto::traits::{CryptoError, DigitalSignature, PublicKey, SecretKey, Signature};

// ---------------------------------------------------------------------------
// NIST FIPS 204 ML-DSA-65 size constants
// ---------------------------------------------------------------------------

/// ML-DSA-65 public key size in bytes (NIST FIPS 204 Table 2).
pub const PUBLIC_KEY_BYTES: usize = 1952;

/// ML-DSA-65 seed size in bytes stored in [`SecretKey`] (FIPS 204 §3.6).
pub const SEED_BYTES: usize = 32;

/// ML-DSA-65 signature size in bytes (NIST FIPS 204 Table 2).
pub const SIGNATURE_BYTES: usize = 3309;

// ---------------------------------------------------------------------------
// MlDsa65 — implements DigitalSignature
// ---------------------------------------------------------------------------

/// ML-DSA-65 digital signature scheme (FIPS 204, security category 3).
///
/// Used to authenticate:
/// - Cortex→Rust IPC rule bundles (Invariant #1 in CLAUDE.md)
/// - ONNX model files and their `.sha256` sidecars (RT-C04)
/// - Log segment headers (Merkle chain, RT-M02)
///
/// All callers reference this type through the [`DigitalSignature`] trait.
pub struct MlDsa65;

impl MlDsa65 {
    /// Generate a fresh ML-DSA-65 keypair using a random 32-byte seed.
    ///
    /// Returns `(PublicKey, SecretKey)` where `SecretKey` contains the 32-byte
    /// FIPS 204 seed.  The same seed can always be used to reconstruct the
    /// full keypair and re-derive the public key.
    ///
    /// Uses `aws_lc_rs::rand::SystemRandom` — never `rand::random()`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyGenFailed`] if the RNG or key expansion fails.
    pub fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), CryptoError> {
        // Generate a 32-byte random seed from the system entropy source.
        // SystemRandom uses OS /dev/urandom or equivalent — never user-space PRNG.
        let rng = SystemRandom::new();
        let mut seed = [0u8; SEED_BYTES];
        rng.fill(&mut seed)
            .map_err(|_| CryptoError::KeyGenFailed("SystemRandom fill failed".to_string()))?;

        // Expand seed into a full keypair (deterministic per FIPS 204 §3.6).
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed)
            .map_err(|e| CryptoError::KeyGenFailed(format!("ML-DSA-65 from_seed: {e}")))?;

        // Extract raw public key bytes (1952 bytes for ML-DSA-65).
        let pk_bytes = key_pair.public_key().as_ref().to_vec();

        debug_assert_eq!(
            pk_bytes.len(),
            PUBLIC_KEY_BYTES,
            "unexpected ML-DSA-65 public key size"
        );
        debug_assert_eq!(seed.len(), SEED_BYTES, "unexpected ML-DSA-65 seed size");

        Ok((PublicKey(pk_bytes), SecretKey(seed.to_vec())))
    }
}

impl DigitalSignature for MlDsa65 {
    fn algorithm_id(&self) -> &'static str {
        "ML-DSA-65"
    }

    /// Sign `msg` using the ML-DSA-65 key whose seed is stored in `sk`.
    ///
    /// Reconstructs the key pair from the 32-byte seed on each call.  This is
    /// constant-time key expansion with no observable timing difference.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SignFailed`] if `sk` is not exactly `SEED_BYTES`
    /// bytes, or if the underlying signing operation fails.
    fn sign(&self, sk: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
        if sk.0.len() != SEED_BYTES {
            return Err(CryptoError::SignFailed(format!(
                "ML-DSA-65 seed must be {SEED_BYTES} bytes, got {}",
                sk.0.len()
            )));
        }

        // Reconstruct key pair from seed — deterministic per FIPS 204 §3.6.
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &sk.0)
            .map_err(|e| CryptoError::SignFailed(format!("ML-DSA-65 from_seed: {e}")))?;

        // PqdsaKeyPair::sign() writes into a pre-allocated buffer.
        let mut sig_buf = vec![0u8; SIGNATURE_BYTES];
        key_pair
            .sign(msg, &mut sig_buf)
            .map_err(|e| CryptoError::SignFailed(format!("ML-DSA-65 sign: {e}")))?;

        debug_assert_eq!(sig_buf.len(), SIGNATURE_BYTES, "unexpected ML-DSA-65 sig size");

        Ok(Signature(sig_buf))
    }

    /// Verify `sig` over `msg` using the raw ML-DSA-65 public key in `pk`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerifyFailed`] if `pk` is not `PUBLIC_KEY_BYTES`
    /// bytes, if the public key is malformed, or if the signature does not verify.
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        if pk.0.len() != PUBLIC_KEY_BYTES {
            return Err(CryptoError::VerifyFailed(format!(
                "ML-DSA-65 public key must be {PUBLIC_KEY_BYTES} bytes, got {}",
                pk.0.len()
            )));
        }

        // UnparsedPublicKey::new accepts raw public key bytes for ML-DSA-65.
        // &ML_DSA_65 is &'static PqdsaVerificationAlgorithm.
        let unparsed = UnparsedPublicKey::new(&ML_DSA_65, pk.0.as_slice());

        unparsed
            .verify(msg, sig.0.as_slice())
            .map_err(|e| CryptoError::VerifyFailed(format!("ML-DSA-65 verify: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn scheme() -> MlDsa65 {
        MlDsa65
    }

    // ---- NIST FIPS 204 size constant sanity checks -------------------------

    #[test]
    fn test_public_key_bytes_fips_204() {
        // FIPS 204 Table 2: ML-DSA-65 pk = 1952 bytes.
        assert_eq!(PUBLIC_KEY_BYTES, 1952, "FIPS 204 ML-DSA-65 pk must be 1952 bytes");
    }

    #[test]
    fn test_seed_bytes_fips_204() {
        // FIPS 204 §3.6: all ML-DSA variants use a 32-byte seed ζ.
        assert_eq!(SEED_BYTES, 32, "ML-DSA-65 seed must be 32 bytes");
    }

    #[test]
    fn test_signature_bytes_fips_204() {
        // FIPS 204 Table 2: ML-DSA-65 sig = 3309 bytes.
        assert_eq!(SIGNATURE_BYTES, 3309, "FIPS 204 ML-DSA-65 sig must be 3309 bytes");
    }

    // ---- algorithm_id -------------------------------------------------------

    #[test]
    fn test_algorithm_id() {
        assert_eq!(scheme().algorithm_id(), "ML-DSA-65");
    }

    // ---- Key generation -----------------------------------------------------

    #[test]
    fn test_generate_keypair_sizes() {
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen must succeed");
        assert_eq!(pk.0.len(), PUBLIC_KEY_BYTES, "pk size must be PUBLIC_KEY_BYTES");
        assert_eq!(sk.0.len(), SEED_BYTES, "sk (seed) size must be SEED_BYTES");
    }

    #[test]
    fn test_generate_keypair_randomness() {
        // Two keygens should produce different seeds (with overwhelming probability).
        let s = scheme();
        let (_, sk1) = s.generate_keypair().expect("keygen 1");
        let (_, sk2) = s.generate_keypair().expect("keygen 2");
        assert_ne!(sk1.0, sk2.0, "consecutive seeds must differ");
    }

    // ---- Sign + verify roundtrip --------------------------------------------

    #[test]
    fn test_sign_verify_roundtrip() {
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen");
        let msg = b"VGLF rule bundle: BLOCK 1.2.3.4/32 reason=test";
        let sig = s.sign(&sk, msg).expect("sign");
        assert_eq!(sig.0.len(), SIGNATURE_BYTES, "signature size must be SIGNATURE_BYTES");
        s.verify(&pk, msg, &sig).expect("verify must pass on correct signature");
    }

    #[test]
    fn test_wrong_public_key_verify_fails() {
        let s = scheme();
        let (_, sk1) = s.generate_keypair().expect("keygen 1");
        let (pk2, _) = s.generate_keypair().expect("keygen 2");
        let msg = b"message signed with key 1";
        let sig = s.sign(&sk1, msg).expect("sign");
        assert!(
            s.verify(&pk2, msg, &sig).is_err(),
            "verify with wrong public key must fail"
        );
    }

    #[test]
    fn test_tampered_message_verify_fails() {
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen");
        let msg = b"original message content";
        let sig = s.sign(&sk, msg).expect("sign");
        assert!(
            s.verify(&pk, b"tampered message content", &sig).is_err(),
            "verify over tampered message must fail"
        );
    }

    #[test]
    fn test_tampered_signature_verify_fails() {
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen");
        let msg = b"message";
        let mut sig = s.sign(&sk, msg).expect("sign");
        // Flip a byte near the middle of the signature.
        sig.0[SIGNATURE_BYTES / 2] ^= 0xFF;
        assert!(
            s.verify(&pk, msg, &sig).is_err(),
            "verify with tampered signature must fail"
        );
    }

    // ---- Input validation --------------------------------------------------

    #[test]
    fn test_sign_rejects_non_seed_length() {
        let s = scheme();
        let bad_sk = SecretKey(vec![0u8; 64]); // 64 bytes, not 32
        assert!(
            s.sign(&bad_sk, b"msg").is_err(),
            "sign must reject keys with wrong byte count"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_pk_length() {
        let s = scheme();
        let bad_pk = PublicKey(vec![0u8; 32]); // too short
        let (_, sk) = s.generate_keypair().expect("keygen");
        let sig = s.sign(&sk, b"msg").expect("sign");
        assert!(
            s.verify(&bad_pk, b"msg", &sig).is_err(),
            "verify must reject public keys with wrong byte count"
        );
    }

    // ---- Seed determinism --------------------------------------------------

    #[test]
    fn test_same_seed_same_public_key() {
        // FIPS 204 §3.6: same seed always produces same key pair.
        let s = scheme();
        let (pk1, sk1) = s.generate_keypair().expect("keygen 1");
        // Reconstruct using PqdsaKeyPair::from_seed directly to verify.
        let kp2 = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &sk1.0)
            .expect("from_seed with generated seed");
        let pk2_bytes = kp2.public_key().as_ref().to_vec();
        assert_eq!(pk1.0, pk2_bytes, "same seed must produce same public key");
    }

    #[test]
    fn test_both_signatures_verify_from_same_seed() {
        // ML-DSA uses hedged (randomized) signing — signatures from same key may differ.
        // Both must verify correctly.
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen");
        let msg = b"hedged signing test";
        let sig1 = s.sign(&sk, msg).expect("sign 1");
        let sig2 = s.sign(&sk, msg).expect("sign 2");
        s.verify(&pk, msg, &sig1).expect("sig1 must verify");
        s.verify(&pk, msg, &sig2).expect("sig2 must verify");
    }

    // ---- Edge cases --------------------------------------------------------

    #[test]
    fn test_sign_verify_empty_message() {
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen");
        let sig = s.sign(&sk, b"").expect("sign empty message");
        s.verify(&pk, b"", &sig).expect("verify empty message");
    }

    #[test]
    fn test_sign_verify_large_message() {
        let s = scheme();
        let (pk, sk) = s.generate_keypair().expect("keygen");
        let large_msg = vec![0xABu8; 64 * 1024]; // 64 KiB
        let sig = s.sign(&sk, &large_msg).expect("sign large message");
        s.verify(&pk, &large_msg, &sig).expect("verify large message");
    }
}
