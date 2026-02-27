//! Hybrid ML-KEM-768 + X25519 key encapsulation for VGLF.
//!
//! # Hybrid construction
//!
//! ```text
//! shared_secret = SHA3-256( ML-KEM-768_ss || X25519_ss )
//! ```
//!
//! This construction is mandated by the VGLF hybrid KEM policy:
//! - **ML-KEM-768** (FIPS 203) provides post-quantum security.
//! - **X25519** (RFC 7748) provides classical security as a downgrade-resistance
//!   hedge: even if ML-KEM-768 is broken, the classical component remains secure,
//!   and vice-versa.
//! - **SHA3-256** (FIPS 202) binds both secrets. Secrets are *concatenated*,
//!   never XOR'd, per the VGLF hybrid KEM policy.
//!
//! # Wire format
//!
//! | Value        | Layout                                       | Bytes |
//! |--------------|----------------------------------------------|-------|
//! | `PublicKey`  | `ml_kem_pk (1184) \|\| x25519_pk (32)`      | 1216  |
//! | `SecretKey`  | `ml_kem_sk (2400) \|\| x25519_sk_raw (32)`  | 2432  |
//! | `Ciphertext` | `ml_kem_ct (1088) \|\| x25519_eph_pk (32)`   | 1120  |
//!
//! The X25519 secret key component is stored as the raw 32-byte scalar.
//! This avoids DER serialization and matches what `PrivateKey::from_private_key`
//! expects at decapsulation time.

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use aws_lc_rs::{
    agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, X25519},
    kem::{DecapsulationKey, EncapsulationKey, ML_KEM_768},
    rand::{SecureRandom, SystemRandom},
};

use crate::crypto::traits::{
    Ciphertext, CryptoError, KeyEncapsulation, PublicKey, SecretKey, SharedSecret,
};

// ---------------------------------------------------------------------------
// Fixed algorithm sizes (FIPS 203 Table 2, k=3 for ML-KEM-768; RFC 7748)
// ---------------------------------------------------------------------------

/// ML-KEM-768 encapsulation key (public key) length in bytes.
const MLKEM768_PK_LEN: usize = 1184;
/// ML-KEM-768 decapsulation key (secret key) length in bytes.
const MLKEM768_SK_LEN: usize = 2400;
/// ML-KEM-768 ciphertext length in bytes.
const MLKEM768_CT_LEN: usize = 1088;
/// X25519 public key / shared secret / raw private scalar length in bytes.
const X25519_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// HybridMlKem768X25519
// ---------------------------------------------------------------------------

/// Hybrid ML-KEM-768 + X25519 KEM, with shared secret derived via SHA3-256.
///
/// The unit struct carries no state; all key material lives in the typed
/// `PublicKey` / `SecretKey` / `Ciphertext` / `SharedSecret` wrappers.
pub struct HybridMlKem768X25519;

impl KeyEncapsulation for HybridMlKem768X25519 {
    /// Returns the canonical VGLF algorithm identifier.
    fn algorithm_id(&self) -> &'static str {
        "ML-KEM-768+X25519-SHA3-256"
    }

    /// Generate a fresh hybrid keypair.
    ///
    /// ML-KEM-768 uses `DecapsulationKey::generate` (aws-lc-rs internal RNG).
    /// X25519 uses `SystemRandom::fill` to produce a raw 32-byte scalar, then
    /// `PrivateKey::from_private_key` to validate and construct the key object.
    ///
    /// # Returns
    ///
    /// `(PublicKey, SecretKey)` where:
    /// - `PublicKey.0`  = `ml_kem_pk (1184) || x25519_pk (32)`
    /// - `SecretKey.0`  = `ml_kem_sk (2400) || x25519_sk_raw (32)`
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyGenFailed`] if either key generation fails.
    #[allow(clippy::similar_names)] // dk/ek, pk_bytes/sk_bytes are standard crypto abbreviations
    fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), CryptoError> {
        let rng = SystemRandom::new();

        // ---- ML-KEM-768 keypair ----------------------------------------
        let mlkem_dk = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|e| CryptoError::KeyGenFailed(format!("ML-KEM-768 keygen: {e}")))?;

        let mlkem_ek = mlkem_dk
            .encapsulation_key()
            .map_err(|e| CryptoError::KeyGenFailed(format!("ML-KEM-768 encap key: {e}")))?;

        let mlkem_pk_bytes = mlkem_ek
            .key_bytes()
            .map_err(|e| CryptoError::KeyGenFailed(format!("ML-KEM-768 pk bytes: {e}")))?;

        let mlkem_sk_bytes = mlkem_dk
            .key_bytes()
            .map_err(|e| CryptoError::KeyGenFailed(format!("ML-KEM-768 sk bytes: {e}")))?;

        debug_assert_eq!(
            mlkem_pk_bytes.as_ref().len(),
            MLKEM768_PK_LEN,
            "ML-KEM-768 public key size invariant violated"
        );
        debug_assert_eq!(
            mlkem_sk_bytes.as_ref().len(),
            MLKEM768_SK_LEN,
            "ML-KEM-768 secret key size invariant violated"
        );

        // ---- X25519 static keypair ------------------------------------
        // Generate 32 random bytes as the raw X25519 scalar, then validate via
        // from_private_key. We store the raw bytes (not DER) because aws-lc-rs
        // 1.x PrivateKey does not expose an as_der() serialization method.
        let mut x25519_sk_raw = [0u8; X25519_KEY_LEN];
        rng.fill(&mut x25519_sk_raw)
            .map_err(|e| CryptoError::KeyGenFailed(format!("X25519 RNG fill: {e}")))?;

        let x25519_sk = PrivateKey::from_private_key(&X25519, &x25519_sk_raw)
            .map_err(|e| CryptoError::KeyGenFailed(format!("X25519 from_private_key: {e}")))?;

        let x25519_pk_bytes = x25519_sk
            .compute_public_key()
            .map_err(|e| CryptoError::KeyGenFailed(format!("X25519 compute pk: {e}")))?;

        // ---- Assemble PublicKey: ml_kem_pk || x25519_pk ----------------
        let mut pk_vec = Vec::with_capacity(MLKEM768_PK_LEN + X25519_KEY_LEN);
        pk_vec.extend_from_slice(mlkem_pk_bytes.as_ref());
        pk_vec.extend_from_slice(x25519_pk_bytes.as_ref());

        // ---- Assemble SecretKey: ml_kem_sk || x25519_sk_raw ------------
        let mut sk_vec = Vec::with_capacity(MLKEM768_SK_LEN + X25519_KEY_LEN);
        sk_vec.extend_from_slice(mlkem_sk_bytes.as_ref());
        sk_vec.extend_from_slice(&x25519_sk_raw);

        // Zeroize the stack copy of the raw X25519 scalar now that it is
        // safely stored inside sk_vec (which is ZeroizeOnDrop).
        x25519_sk_raw.zeroize();

        Ok((PublicKey(pk_vec), SecretKey(sk_vec)))
    }

    /// Encapsulate a shared secret to `pk`.
    ///
    /// Generates an ephemeral X25519 keypair internally. The ephemeral public
    /// key is embedded in the returned ciphertext; the ephemeral private key is
    /// consumed by `agree_ephemeral` and never stored.
    ///
    /// # Returns
    ///
    /// `(Ciphertext, SharedSecret)` where:
    /// - `Ciphertext.0`   = `ml_kem_ct (1088) || x25519_eph_pk (32)`
    /// - `SharedSecret.0` = `SHA3-256(ml_kem_ss || x25519_ss)` — always 32 bytes
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EncapsulateFailed`] on any failure.
    fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), CryptoError> {
        let pk_bytes = pk.0.as_slice();
        let expected_pk_len = MLKEM768_PK_LEN + X25519_KEY_LEN;

        if pk_bytes.len() != expected_pk_len {
            return Err(CryptoError::EncapsulateFailed(format!(
                "public key length mismatch: expected {expected_pk_len}, got {}",
                pk_bytes.len()
            )));
        }

        let mlkem_pk_slice = &pk_bytes[..MLKEM768_PK_LEN];
        let x25519_pk_slice = &pk_bytes[MLKEM768_PK_LEN..];

        let rng = SystemRandom::new();

        // ---- ML-KEM-768 encapsulation ----------------------------------
        let mlkem_ek = EncapsulationKey::new(&ML_KEM_768, mlkem_pk_slice).map_err(|e| {
            CryptoError::EncapsulateFailed(format!("ML-KEM-768 EncapsulationKey::new: {e}"))
        })?;

        let (mlkem_ct, mlkem_ss) = mlkem_ek.encapsulate().map_err(|e| {
            CryptoError::EncapsulateFailed(format!("ML-KEM-768 encapsulate: {e}"))
        })?;

        let mlkem_ct_slice = mlkem_ct.as_ref();
        let mlkem_ss_slice = mlkem_ss.as_ref();

        debug_assert_eq!(
            mlkem_ct_slice.len(),
            MLKEM768_CT_LEN,
            "ML-KEM-768 ciphertext size invariant violated"
        );

        // ---- X25519 ephemeral DH ---------------------------------------
        // EphemeralPrivateKey is consumed by agree_ephemeral — never reused.
        let eph_sk = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|e| {
            CryptoError::EncapsulateFailed(format!("X25519 ephemeral keygen: {e}"))
        })?;

        let eph_pk_bytes = eph_sk.compute_public_key().map_err(|e| {
            CryptoError::EncapsulateFailed(format!("X25519 ephemeral pk: {e}"))
        })?;

        // agree_ephemeral: ring-style 4-arg API
        //   (private_key, peer_pub, error_value, kdf_closure -> Result<R, E>)
        let recipient_pk = UnparsedPublicKey::new(&X25519, x25519_pk_slice);
        let mut x25519_ss_arr: [u8; X25519_KEY_LEN] = agreement::agree_ephemeral(
            eph_sk,
            recipient_pk,
            CryptoError::EncapsulateFailed("X25519 agree_ephemeral failed".into()),
            |ss_bytes| {
                let mut arr = [0u8; X25519_KEY_LEN];
                arr.copy_from_slice(ss_bytes);
                Ok(arr)
            },
        )?;

        // ---- Hybrid key derivation: SHA3-256(ml_kem_ss || x25519_ss) --
        let shared_secret = derive_hybrid_secret(mlkem_ss_slice, &x25519_ss_arr);

        // Wipe the raw X25519 shared secret from the stack.
        x25519_ss_arr.zeroize();

        // ---- Assemble ciphertext: ml_kem_ct || x25519_eph_pk -----------
        let mut ct_vec = Vec::with_capacity(MLKEM768_CT_LEN + X25519_KEY_LEN);
        ct_vec.extend_from_slice(mlkem_ct_slice);
        ct_vec.extend_from_slice(eph_pk_bytes.as_ref());

        Ok((Ciphertext(ct_vec), shared_secret))
    }

    /// Decapsulate `ct` using `sk`.
    ///
    /// Recovers the hybrid shared secret by:
    /// 1. Decapsulating the ML-KEM-768 ciphertext component.
    /// 2. Performing X25519 DH between the stored static key and the ephemeral
    ///    public key embedded in the ciphertext.
    /// 3. Deriving `SHA3-256(ml_kem_ss || x25519_ss)`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecapsulateFailed`] on any failure.
    #[allow(clippy::similar_names)] // sk_slice/ss_slice are standard crypto abbreviations
    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, CryptoError> {
        let sk_bytes = sk.0.as_slice();
        let ct_bytes = ct.0.as_slice();

        let expected_sk_len = MLKEM768_SK_LEN + X25519_KEY_LEN;
        let expected_ct_len = MLKEM768_CT_LEN + X25519_KEY_LEN;

        if sk_bytes.len() != expected_sk_len {
            return Err(CryptoError::DecapsulateFailed(format!(
                "secret key length mismatch: expected {expected_sk_len}, got {}",
                sk_bytes.len()
            )));
        }
        if ct_bytes.len() != expected_ct_len {
            return Err(CryptoError::DecapsulateFailed(format!(
                "ciphertext length mismatch: expected {expected_ct_len}, got {}",
                ct_bytes.len()
            )));
        }

        // Parse SecretKey: ml_kem_sk (2400) || x25519_sk_raw (32)
        let mlkem_sk_slice = &sk_bytes[..MLKEM768_SK_LEN];
        let x25519_sk_slice = &sk_bytes[MLKEM768_SK_LEN..];

        // Parse Ciphertext: ml_kem_ct (1088) || x25519_eph_pk (32)
        let mlkem_ct_slice = &ct_bytes[..MLKEM768_CT_LEN];
        let x25519_eph_pk_slice = &ct_bytes[MLKEM768_CT_LEN..];

        // ---- ML-KEM-768 decapsulation ----------------------------------
        let mlkem_dk = DecapsulationKey::new(&ML_KEM_768, mlkem_sk_slice).map_err(|e| {
            CryptoError::DecapsulateFailed(format!("ML-KEM-768 DecapsulationKey::new: {e}"))
        })?;

        let mlkem_ss = mlkem_dk
            .decapsulate(mlkem_ct_slice.into())
            .map_err(|e| {
                CryptoError::DecapsulateFailed(format!("ML-KEM-768 decapsulate: {e}"))
            })?;

        let mlkem_ss_slice = mlkem_ss.as_ref();

        // ---- X25519 static DH ------------------------------------------
        // Reconstruct the recipient's static private key from the stored raw scalar.
        let x25519_static_sk =
            PrivateKey::from_private_key(&X25519, x25519_sk_slice).map_err(|e| {
                CryptoError::DecapsulateFailed(format!("X25519 from_private_key: {e}"))
            })?;

        let eph_pub = UnparsedPublicKey::new(&X25519, x25519_eph_pk_slice);

        // agree: ring-style 4-arg API (non-ephemeral private key variant)
        let mut x25519_ss_arr: [u8; X25519_KEY_LEN] = agreement::agree(
            &x25519_static_sk,
            eph_pub,
            CryptoError::DecapsulateFailed("X25519 agree failed".into()),
            |ss_bytes| {
                let mut arr = [0u8; X25519_KEY_LEN];
                arr.copy_from_slice(ss_bytes);
                Ok(arr)
            },
        )?;

        // ---- Hybrid key derivation: SHA3-256(ml_kem_ss || x25519_ss) --
        let shared_secret = derive_hybrid_secret(mlkem_ss_slice, &x25519_ss_arr);

        // Wipe the raw X25519 shared secret from the stack.
        x25519_ss_arr.zeroize();

        Ok(shared_secret)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive the 32-byte hybrid shared secret.
///
/// `output = SHA3-256( ml_kem_ss || x25519_ss )`
///
/// Secrets are concatenated — **never** XOR'd — per the VGLF hybrid KEM policy.
/// XOR is forbidden because it would allow an attacker who breaks one component
/// to cancel its contribution and recover the shared secret entirely.
fn derive_hybrid_secret(ml_kem_ss: &[u8], x25519_ss: &[u8; X25519_KEY_LEN]) -> SharedSecret {
    let mut hasher = Sha3_256::new();
    hasher.update(ml_kem_ss);
    hasher.update(x25519_ss);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SharedSecret(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::traits::KeyEncapsulation;

    fn kem() -> HybridMlKem768X25519 {
        HybridMlKem768X25519
    }

    // ---- Functional tests -----------------------------------------------

    /// Full roundtrip: encapsulator and decapsulator must derive identical secrets.
    #[test]
    fn test_hybrid_kem_roundtrip() {
        let k = kem();
        let (pk, sk) = k.generate_keypair().expect("keygen must succeed");
        let (ct, ss_enc) = k.encapsulate(&pk).expect("encapsulate must succeed");
        let ss_dec = k.decapsulate(&sk, &ct).expect("decapsulate must succeed");
        assert_eq!(
            ss_enc.0, ss_dec.0,
            "encapsulator and decapsulator must arrive at the same shared secret"
        );
    }

    /// Encapsulate to pk1, decapsulate with sk2: secrets must differ.
    ///
    /// ML-KEM uses implicit rejection: a wrong-key decapsulation does not error
    /// but returns a pseudorandom value unrelated to the real shared secret.
    #[test]
    fn test_hybrid_kem_different_secret_keys_dont_match() {
        let k = kem();
        let (pk1, _sk1) = k.generate_keypair().expect("keygen 1 must succeed");
        let (_pk2, sk2) = k.generate_keypair().expect("keygen 2 must succeed");
        let (ct, ss_correct) = k.encapsulate(&pk1).expect("encapsulate must succeed");
        let ss_wrong = k
            .decapsulate(&sk2, &ct)
            .expect("decapsulate with wrong key should not hard-error (implicit rejection)");
        assert_ne!(
            ss_correct.0, ss_wrong.0,
            "wrong secret key must not produce the correct shared secret"
        );
    }

    /// Corrupt the ML-KEM ciphertext component; decapsulated secret must differ.
    #[test]
    fn test_hybrid_kem_wrong_ciphertext_fails() {
        let k = kem();
        let (pk, sk) = k.generate_keypair().expect("keygen must succeed");
        let (ct, ss_correct) = k.encapsulate(&pk).expect("encapsulate must succeed");

        // Flip a byte squarely in the ML-KEM ciphertext portion.
        let mut bad = ct.0.clone();
        bad[42] ^= 0xFF;
        let bad_ct = Ciphertext(bad);

        if let Ok(ss_bad) = k.decapsulate(&sk, &bad_ct) {
            assert_ne!(
                ss_correct.0, ss_bad.0,
                "corrupted ciphertext must not yield the correct shared secret"
            );
        }
        // Err(_) is also acceptable — hard error on corrupted ciphertext is fine.
    }

    // ---- Size invariant tests -------------------------------------------

    /// `SharedSecret` is always exactly 32 bytes (SHA3-256 output width).
    #[test]
    fn test_shared_secret_length() {
        let k = kem();
        let (pk, sk) = k.generate_keypair().expect("keygen must succeed");
        let (ct, ss_enc) = k.encapsulate(&pk).expect("encapsulate must succeed");
        let ss_dec = k.decapsulate(&sk, &ct).expect("decapsulate must succeed");
        assert_eq!(ss_enc.0.len(), 32);
        assert_eq!(ss_dec.0.len(), 32);
    }

    /// Hybrid public key must be exactly `MLKEM768_PK_LEN + X25519_KEY_LEN` bytes.
    #[test]
    fn test_public_key_wire_length() {
        let k = kem();
        let (pk, _sk) = k.generate_keypair().expect("keygen must succeed");
        assert_eq!(pk.0.len(), MLKEM768_PK_LEN + X25519_KEY_LEN);
    }

    /// Hybrid secret key must be exactly `MLKEM768_SK_LEN + X25519_KEY_LEN` bytes.
    #[test]
    fn test_secret_key_wire_length() {
        let k = kem();
        let (_pk, sk) = k.generate_keypair().expect("keygen must succeed");
        assert_eq!(sk.0.len(), MLKEM768_SK_LEN + X25519_KEY_LEN);
    }

    /// Hybrid ciphertext must be exactly `MLKEM768_CT_LEN + X25519_KEY_LEN` bytes.
    #[test]
    fn test_ciphertext_wire_length() {
        let k = kem();
        let (pk, _sk) = k.generate_keypair().expect("keygen must succeed");
        let (ct, _ss) = k.encapsulate(&pk).expect("encapsulate must succeed");
        assert_eq!(ct.0.len(), MLKEM768_CT_LEN + X25519_KEY_LEN);
    }

    // ---- Security property tests ----------------------------------------

    /// `algorithm_id()` must return exactly the canonical VGLF string.
    #[test]
    fn test_algorithm_id() {
        assert_eq!(kem().algorithm_id(), "ML-KEM-768+X25519-SHA3-256");
    }

    /// `SecretKey` memory must be zeroed after drop (`ZeroizeOnDrop`).
    ///
    /// Retains a raw pointer to the Vec's heap buffer and reads it after `drop`.
    /// On Linux/ptmalloc the freed memory is not immediately reused in a
    /// single-threaded test binary; surviving non-zero bytes indicate
    /// `ZeroizeOnDrop` did not fire.
    #[test]
    fn test_zeroize_on_drop() {
        let k = kem();
        let (_pk, sk) = k.generate_keypair().expect("keygen must succeed");

        let ptr = sk.0.as_ptr();
        let len = sk.0.len();

        drop(sk);

        // SAFETY: The pointer was valid immediately before `drop`. On Linux/ptmalloc
        // the freed memory is not immediately reclaimed or reused in a
        // single-threaded test binary, so reading it reflects the post-zeroize
        // state. This pattern is widely used in security-critical Rust test suites
        // to verify ZeroizeOnDrop despite being technically undefined behaviour.
        let zeroed = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            zeroed.iter().all(|&b| b == 0),
            "SecretKey backing memory must be zeroed after drop (ZeroizeOnDrop did not fire)"
        );
    }

    /// Two fresh encapsulations of the same key must produce different ciphertexts
    /// and different shared secrets (randomized encapsulation).
    #[test]
    fn test_encapsulation_is_randomized() {
        let k = kem();
        let (pk, _sk) = k.generate_keypair().expect("keygen must succeed");
        let (ct1, ss1) = k.encapsulate(&pk).expect("encapsulate 1 must succeed");
        let (ct2, ss2) = k.encapsulate(&pk).expect("encapsulate 2 must succeed");
        assert_ne!(ct1.0, ct2.0, "two encapsulations must produce distinct ciphertexts");
        assert_ne!(ss1.0, ss2.0, "two encapsulations must produce distinct shared secrets");
    }

    // ---- NIST KAT documentation test -----------------------------------

    /// NIST ML-KEM-768 Known Answer Test (KAT) size constants validation.
    ///
    /// Actual NIST KAT vectors for ML-KEM-768 are published at:
    ///   <https://csrc.nist.gov/projects/post-quantum-cryptography/>
    ///   File: `kat_kem.tar.gz` → `PQCkemKAT_2400.rsp`  (ML-KEM-768, k=3)
    ///
    /// Vectors must be placed at:
    ///   `tests/pqc-vectors/mlkem768/PQCkemKAT_2400.rsp`
    ///
    /// Full KAT integration is tracked under VGLF issue `#MLKEM-KAT`.
    /// Until vector files are present, this test asserts the published FIPS 203
    /// Table 2 (k=3) and RFC 7748 size constants.
    #[test]
    fn test_nist_kat_sizes_per_spec() {
        assert_eq!(MLKEM768_PK_LEN, 1184, "FIPS 203 §7.2: ek size for k=3 is 1184 bytes");
        assert_eq!(MLKEM768_SK_LEN, 2400, "FIPS 203 §7.3: dk size for k=3 is 2400 bytes");
        assert_eq!(MLKEM768_CT_LEN, 1088, "FIPS 203 §6.2: c size for k=3 is 1088 bytes");
        assert_eq!(X25519_KEY_LEN,  32,   "RFC 7748 §6.1: X25519 keys are 32 bytes");
        assert_eq!(
            MLKEM768_PK_LEN + X25519_KEY_LEN, 1216,
            "hybrid public key must be 1216 bytes"
        );
        assert_eq!(
            MLKEM768_SK_LEN + X25519_KEY_LEN, 2432,
            "hybrid secret key must be 2432 bytes"
        );
        assert_eq!(
            MLKEM768_CT_LEN + X25519_KEY_LEN, 1120,
            "hybrid ciphertext must be 1120 bytes"
        );
    }
}
