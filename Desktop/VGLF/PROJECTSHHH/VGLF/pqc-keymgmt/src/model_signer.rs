//! ONNX model signing and verification (RT-C04 fix).
//!
//! Every ONNX model loaded by VGLF must have:
//!
//! 1. A `.sha256` sidecar file containing `sha3-256:<HEXHASH>`.
//! 2. A `.mldsa65.sig` sidecar file containing the hex-encoded ML-DSA-65
//!    signature over the raw model bytes.
//! 3. Both checks pass at load time -- **hard fail** on mismatch
//!    (Security Invariant #4 in CLAUDE.md).
//!
//! # Signing flow
//!
//! ```text
//! model.onnx  --SHA3-256--> model.onnx.sha256   ("sha3-256:ab12cd...")
//!             --ML-DSA-65-> model.onnx.mldsa65.sig (hex signature)
//! ```
//!
//! # Verification flow
//!
//! ```text
//! 1. Read model.onnx bytes
//! 2. Recompute SHA3-256, compare to .sha256 sidecar
//! 3. Read .mldsa65.sig, verify ML-DSA-65 signature over model bytes
//! 4. Only proceed if BOTH checks pass
//! ```

use std::fs;
use std::path::Path;

use sha3::{Digest, Sha3_256};

use spinal_cord::crypto::traits::{CryptoError, DigitalSignature, PublicKey, SecretKey};

// ---------------------------------------------------------------------------
// ModelSignerError
// ---------------------------------------------------------------------------

/// Errors from model signing and verification.
#[derive(Debug, thiserror::Error)]
pub enum ModelSignerError {
    /// File I/O failed.
    #[error("model I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// SHA3-256 hash mismatch -- the model file has been tampered with or
    /// the sidecar is stale.
    #[error("SHA3-256 hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        /// Path to the model file.
        path: String,
        /// Expected hash from the sidecar.
        expected: String,
        /// Actual hash computed over the model bytes.
        actual: String,
    },

    /// The `.sha256` sidecar file has an invalid format.
    #[error("invalid .sha256 sidecar format: {0}")]
    InvalidHashFormat(String),

    /// The `.mldsa65.sig` sidecar file is not valid hex.
    #[error("invalid .mldsa65.sig sidecar: {0}")]
    InvalidSignatureFormat(String),

    /// ML-DSA-65 signature verification failed.
    #[error("ML-DSA-65 signature verification failed: {0}")]
    SignatureInvalid(#[from] CryptoError),

    /// Hex encoding/decoding failed.
    #[error("hex codec error: {0}")]
    HexCodec(String),
}

// ---------------------------------------------------------------------------
// Sidecar file paths
// ---------------------------------------------------------------------------

/// Return the path to the `.sha256` sidecar for a given model path.
///
/// Example: `models/reflex.onnx` -> `models/reflex.onnx.sha256`
fn hash_sidecar_path(model_path: &Path) -> std::path::PathBuf {
    let mut p = model_path.as_os_str().to_owned();
    p.push(".sha256");
    std::path::PathBuf::from(p)
}

/// Return the path to the `.mldsa65.sig` sidecar for a given model path.
///
/// Example: `models/reflex.onnx` -> `models/reflex.onnx.mldsa65.sig`
fn sig_sidecar_path(model_path: &Path) -> std::path::PathBuf {
    let mut p = model_path.as_os_str().to_owned();
    p.push(".mldsa65.sig");
    std::path::PathBuf::from(p)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Compute SHA3-256 over raw bytes and return the hex digest.
fn sha3_256_hex(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// sign_model
// ---------------------------------------------------------------------------

/// Sign an ONNX model file and write sidecar files.
///
/// Creates two sidecar files alongside the model:
/// - `<model>.sha256` -- contains `sha3-256:<hex_hash>`
/// - `<model>.mldsa65.sig` -- contains hex-encoded ML-DSA-65 signature
///
/// The signature is computed over the **raw model bytes**, not the hash.
/// This ensures that verifying the signature also implicitly proves
/// possession of the original file contents.
///
/// # Errors
///
/// Returns [`ModelSignerError`] if:
/// - The model file cannot be read
/// - The DSA signing operation fails
/// - The sidecar files cannot be written
pub fn sign_model(
    path: &Path,
    sk: &SecretKey,
    dsa: &dyn DigitalSignature,
) -> Result<(), ModelSignerError> {
    let model_bytes = fs::read(path)?;

    // 1. Compute SHA3-256 hash of model bytes.
    let hash_hex = sha3_256_hex(&model_bytes);
    let hash_content = format!("sha3-256:{hash_hex}");

    // 2. Sign the raw model bytes with ML-DSA-65.
    let signature = dsa.sign(sk, &model_bytes)?;
    let sig_hex = hex::encode(&signature.0);

    // 3. Write sidecar files.
    fs::write(hash_sidecar_path(path), hash_content.as_bytes())?;
    fs::write(sig_sidecar_path(path), sig_hex.as_bytes())?;

    Ok(())
}

// ---------------------------------------------------------------------------
// verify_model
// ---------------------------------------------------------------------------

/// Verify an ONNX model file against its sidecar files.
///
/// This is the RT-C04 fix implementation.  Both checks must pass:
/// 1. SHA3-256 hash matches the `.sha256` sidecar.
/// 2. ML-DSA-65 signature in `.mldsa65.sig` verifies over the model bytes.
///
/// **Hard fail on mismatch** -- Security Invariant #4 requires no soft-fail
/// path.  A tampered model or missing sidecar is a fatal error.
///
/// # Errors
///
/// Returns [`ModelSignerError`] if:
/// - Any sidecar file is missing or malformed
/// - The hash does not match (indicates tampering or stale sidecar)
/// - The signature does not verify (indicates tampering or wrong key)
pub fn verify_model(
    path: &Path,
    pk: &PublicKey,
    dsa: &dyn DigitalSignature,
) -> Result<(), ModelSignerError> {
    let model_bytes = fs::read(path)?;

    // ---- Step 1: SHA3-256 hash verification --------------------------------
    let hash_sidecar = fs::read_to_string(hash_sidecar_path(path))?;
    let hash_sidecar = hash_sidecar.trim();

    let expected_hash = hash_sidecar
        .strip_prefix("sha3-256:")
        .ok_or_else(|| {
            ModelSignerError::InvalidHashFormat(format!(
                "expected 'sha3-256:<hex>' prefix, got: {hash_sidecar}"
            ))
        })?;

    let actual_hash = sha3_256_hex(&model_bytes);

    if actual_hash != expected_hash {
        return Err(ModelSignerError::HashMismatch {
            path: path.display().to_string(),
            expected: expected_hash.to_string(),
            actual: actual_hash,
        });
    }

    // ---- Step 2: ML-DSA-65 signature verification --------------------------
    let sig_hex = fs::read_to_string(sig_sidecar_path(path))?;
    let sig_hex = sig_hex.trim();
    let sig_bytes = hex::decode(sig_hex).map_err(|e| {
        ModelSignerError::InvalidSignatureFormat(format!("sig hex decode: {e}"))
    })?;

    let signature = spinal_cord::crypto::traits::Signature(sig_bytes);
    dsa.verify(pk, &model_bytes, &signature)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spinal_cord::crypto::dsa::MlDsa65;
    use tempfile::TempDir;

    fn setup() -> (MlDsa65, PublicKey, SecretKey, TempDir) {
        let dsa = MlDsa65;
        let (pk, sk) = dsa.generate_keypair().expect("keygen must succeed");
        let tmp = TempDir::new().expect("tempdir");
        (dsa, pk, sk, tmp)
    }

    fn write_test_model(dir: &Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let model_path = dir.join(name);
        fs::write(&model_path, contents).expect("write model");
        model_path
    }

    // ---- Sign + verify roundtrip ----------------------------------------

    #[test]
    fn test_sign_verify_roundtrip() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "test.onnx", b"ONNX model bytes");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");
        verify_model(&model_path, &pk, &dsa).expect("verify must succeed");
    }

    #[test]
    fn test_sign_verify_large_model() {
        let (dsa, pk, sk, tmp) = setup();
        // 256 KiB model to test with non-trivial file sizes.
        let large_model = vec![0xABu8; 256 * 1024];
        let model_path = write_test_model(tmp.path(), "large.onnx", &large_model);

        sign_model(&model_path, &sk, &dsa).expect("sign large model");
        verify_model(&model_path, &pk, &dsa).expect("verify large model");
    }

    #[test]
    fn test_sign_verify_empty_model() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "empty.onnx", b"");

        sign_model(&model_path, &sk, &dsa).expect("sign empty model");
        verify_model(&model_path, &pk, &dsa).expect("verify empty model");
    }

    // ---- Hash mismatch (tampering) --------------------------------------

    #[test]
    fn test_verify_fails_on_tampered_model() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "tamper.onnx", b"original content");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Tamper with the model file AFTER signing.
        fs::write(&model_path, b"tampered content").expect("tamper");

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify must HARD FAIL on tampered model (Security Invariant #4)"
        );

        // Verify the error is specifically a hash mismatch.
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("hash mismatch"),
            "error must indicate hash mismatch, got: {err_str}"
        );
    }

    // ---- Signature mismatch (wrong key) ---------------------------------

    #[test]
    fn test_verify_fails_with_wrong_public_key() {
        let (dsa, _pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "wrongpk.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Generate a different keypair -- verification with wrong pk must fail.
        let (pk2, _sk2) = dsa.generate_keypair().expect("keygen 2");

        let result = verify_model(&model_path, &pk2, &dsa);
        assert!(
            result.is_err(),
            "verify with wrong public key must HARD FAIL"
        );
    }

    // ---- Tampered signature file ----------------------------------------

    #[test]
    fn test_verify_fails_on_tampered_signature() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "tamsig.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Tamper with the signature sidecar.
        let sig_path = sig_sidecar_path(&model_path);
        let mut sig_hex = fs::read_to_string(&sig_path).expect("read sig");
        // Flip a hex character near the middle.
        let bytes: Vec<u8> = sig_hex.bytes().collect();
        if !bytes.is_empty() {
            let idx = bytes.len() / 2;
            let replacement = if bytes[idx] == b'a' { b'b' } else { b'a' };
            sig_hex = String::from_utf8({
                let mut v = bytes;
                v[idx] = replacement;
                v
            })
            .expect("valid utf8");
            fs::write(&sig_path, sig_hex.as_bytes()).expect("write tampered sig");
        }

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with tampered signature must HARD FAIL"
        );
    }

    // ---- Tampered hash sidecar ------------------------------------------

    #[test]
    fn test_verify_fails_on_tampered_hash_sidecar() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "tamhash.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Tamper with the hash sidecar.
        let hash_path = hash_sidecar_path(&model_path);
        fs::write(
            &hash_path,
            b"sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("write tampered hash");

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with tampered hash sidecar must HARD FAIL"
        );
    }

    // ---- Missing sidecar files ------------------------------------------

    #[test]
    fn test_verify_fails_on_missing_hash_sidecar() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "nohash.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Delete the hash sidecar.
        fs::remove_file(hash_sidecar_path(&model_path)).expect("remove hash sidecar");

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with missing hash sidecar must HARD FAIL"
        );
    }

    #[test]
    fn test_verify_fails_on_missing_sig_sidecar() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "nosig.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Delete the signature sidecar.
        fs::remove_file(sig_sidecar_path(&model_path)).expect("remove sig sidecar");

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with missing signature sidecar must HARD FAIL"
        );
    }

    // ---- Invalid sidecar formats ----------------------------------------

    #[test]
    fn test_verify_fails_on_malformed_hash_prefix() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "badprefix.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Overwrite hash sidecar with wrong prefix.
        let hash_path = hash_sidecar_path(&model_path);
        fs::write(&hash_path, b"sha256:abcd1234").expect("write bad prefix");

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with wrong hash prefix must HARD FAIL"
        );
    }

    #[test]
    fn test_verify_fails_on_invalid_sig_hex() {
        let (dsa, pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "badhex.onnx", b"model data");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        // Overwrite sig sidecar with non-hex content.
        let sig_path = sig_sidecar_path(&model_path);
        fs::write(&sig_path, b"not-valid-hex-ZZZZ").expect("write bad hex");

        let result = verify_model(&model_path, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with invalid hex signature must HARD FAIL"
        );
    }

    // ---- Sidecar file contents verification -----------------------------

    #[test]
    fn test_sidecar_hash_format() {
        let (dsa, _pk, sk, tmp) = setup();
        let model_bytes = b"check sidecar format";
        let model_path = write_test_model(tmp.path(), "format.onnx", model_bytes);

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        let hash_content = fs::read_to_string(hash_sidecar_path(&model_path))
            .expect("read hash sidecar");

        assert!(
            hash_content.starts_with("sha3-256:"),
            "hash sidecar must start with 'sha3-256:'"
        );

        // Verify the hash value.
        let expected_hash = sha3_256_hex(model_bytes);
        assert_eq!(
            hash_content.trim(),
            format!("sha3-256:{expected_hash}"),
            "hash sidecar must contain the correct SHA3-256 hash"
        );
    }

    #[test]
    fn test_sidecar_sig_is_valid_hex() {
        let (dsa, _pk, sk, tmp) = setup();
        let model_path = write_test_model(tmp.path(), "hexcheck.onnx", b"sig format test");

        sign_model(&model_path, &sk, &dsa).expect("sign must succeed");

        let sig_content = fs::read_to_string(sig_sidecar_path(&model_path))
            .expect("read sig sidecar");

        // Must be valid hex.
        let sig_bytes = hex::decode(sig_content.trim());
        assert!(
            sig_bytes.is_ok(),
            "signature sidecar must contain valid hex"
        );

        // ML-DSA-65 signatures are 3309 bytes.
        assert_eq!(
            sig_bytes.expect("valid hex").len(),
            spinal_cord::crypto::dsa::SIGNATURE_BYTES,
            "signature must be exactly SIGNATURE_BYTES (3309) bytes"
        );
    }

    // ---- Helper function tests ------------------------------------------

    #[test]
    fn test_hash_sidecar_path() {
        let p = Path::new("/tmp/models/test.onnx");
        let sidecar = hash_sidecar_path(p);
        assert_eq!(
            sidecar.to_str().expect("valid path"),
            "/tmp/models/test.onnx.sha256"
        );
    }

    #[test]
    fn test_sig_sidecar_path() {
        let p = Path::new("/tmp/models/test.onnx");
        let sidecar = sig_sidecar_path(p);
        assert_eq!(
            sidecar.to_str().expect("valid path"),
            "/tmp/models/test.onnx.mldsa65.sig"
        );
    }

    #[test]
    fn test_sha3_256_hex_known_value() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let empty_hash = sha3_256_hex(b"");
        assert_eq!(
            empty_hash,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "SHA3-256 of empty input must match known test vector"
        );
    }
}
