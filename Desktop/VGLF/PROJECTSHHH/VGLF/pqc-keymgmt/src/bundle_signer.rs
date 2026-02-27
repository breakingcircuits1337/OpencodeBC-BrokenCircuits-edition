//! Rule bundle signing for the IPC protocol.
//!
//! Signs [`RuleBundle`] payloads for transmission over the Cortex->Rust IPC
//! socket.  The wire format matches what `spinal-cord`'s IPC handler expects:
//!
//! ```json
//! {
//!   "payload": "<hex-encoded JSON of RuleBundle>",
//!   "signature": "<hex-encoded ML-DSA-65 signature over payload hex string>"
//! }
//! ```
//!
//! # Important: signature scope
//!
//! The signature covers the **hex string bytes** of the payload, not the
//! decoded JSON.  This matches the verification logic in
//! `spinal_cord::ipc::handler::process_message()` Step 3, which calls
//! `dsa.verify(pk, bundle.payload.as_bytes(), &sig)`.
//!
//! # `SignedBundle` serialization
//!
//! Note: `spinal_cord::ipc::protocol::SignedBundle` only derives `Deserialize`
//! (not `Serialize`).  To avoid modifying spinal-cord, this module constructs
//! the JSON wire format manually.  The format is stable and matches the
//! `SignedBundle` deserialization expectations exactly.

use spinal_cord::crypto::traits::{CryptoError, DigitalSignature, PublicKey, SecretKey, Signature};
use spinal_cord::ipc::protocol::RuleBundle;

// ---------------------------------------------------------------------------
// BundleSignerError
// ---------------------------------------------------------------------------

/// Errors from bundle signing and verification.
#[derive(Debug, thiserror::Error)]
pub enum BundleSignerError {
    /// JSON serialization failed.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Hex encoding/decoding failed.
    #[error("hex codec error: {0}")]
    HexCodec(String),
}

// ---------------------------------------------------------------------------
// sign_bundle
// ---------------------------------------------------------------------------

/// Sign a [`RuleBundle`] and produce the wire-format JSON string.
///
/// Returns the complete JSON string ready to be sent over the IPC socket
/// (with a trailing newline, matching the newline-delimited protocol).
///
/// # Wire format
///
/// The returned string is:
/// ```json
/// {"payload":"<hex-encoded RuleBundle JSON>","signature":"<hex-encoded ML-DSA-65 sig>"}
/// ```
///
/// The signature covers `payload.as_bytes()` -- the hex string itself, not
/// the decoded bytes.  This matches the handler's verification logic.
///
/// # Errors
///
/// Returns [`BundleSignerError`] if JSON serialization or signing fails.
pub fn sign_bundle(
    bundle: &RuleBundle,
    sk: &SecretKey,
    dsa: &dyn DigitalSignature,
) -> Result<String, BundleSignerError> {
    // 1. Serialize RuleBundle to JSON.
    let bundle_json = serde_json::to_string(bundle)?;

    // 2. Hex-encode the JSON bytes to produce the payload field.
    let payload_hex = hex::encode(bundle_json.as_bytes());

    // 3. Sign the hex string bytes (not the decoded bytes).
    //    This matches handler.rs Step 3: dsa.verify(pk, bundle.payload.as_bytes(), &sig)
    let signature = dsa.sign(sk, payload_hex.as_bytes())?;
    let sig_hex = hex::encode(&signature.0);

    // 4. Construct the SignedBundle JSON manually.
    //    SignedBundle only derives Deserialize in spinal-cord, so we build
    //    the JSON by hand.  The field names and structure match exactly.
    let wire_json = serde_json::json!({
        "payload": payload_hex,
        "signature": sig_hex,
    });

    Ok(wire_json.to_string())
}

// ---------------------------------------------------------------------------
// verify_bundle_signature
// ---------------------------------------------------------------------------

/// Verify the ML-DSA-65 signature on a wire-format signed bundle.
///
/// This is the client-side equivalent of what `spinal-cord`'s IPC handler
/// does at Step 3.  Useful for pre-flight checks before sending a bundle.
///
/// # Errors
///
/// Returns [`BundleSignerError`] if:
/// - The JSON cannot be parsed
/// - The signature hex is invalid
/// - The ML-DSA-65 signature does not verify
pub fn verify_bundle_signature(
    wire_json: &str,
    pk: &PublicKey,
    dsa: &dyn DigitalSignature,
) -> Result<RuleBundle, BundleSignerError> {
    // Parse the outer envelope -- same structure as SignedBundle.
    let envelope: serde_json::Value = serde_json::from_str(wire_json)?;

    let payload = envelope
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BundleSignerError::HexCodec("missing or non-string 'payload' field".to_string())
        })?;

    let sig_hex = envelope
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BundleSignerError::HexCodec("missing or non-string 'signature' field".to_string())
        })?;

    // Decode signature hex.
    let sig_bytes = hex::decode(sig_hex).map_err(|e| {
        BundleSignerError::HexCodec(format!("signature hex decode: {e}"))
    })?;

    let signature = Signature(sig_bytes);

    // Verify: signature covers payload.as_bytes() (the hex string).
    dsa.verify(pk, payload.as_bytes(), &signature)?;

    // Signature verified -- now decode the payload.
    let payload_bytes = hex::decode(payload).map_err(|e| {
        BundleSignerError::HexCodec(format!("payload hex decode: {e}"))
    })?;

    let bundle: RuleBundle = serde_json::from_slice(&payload_bytes)?;
    Ok(bundle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spinal_cord::crypto::dsa::MlDsa65;
    use spinal_cord::ipc::protocol::{RuleAction, PROTOCOL_VERSION};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_test_bundle() -> RuleBundle {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time must work")
            .as_secs();

        RuleBundle {
            version: PROTOCOL_VERSION,
            action: RuleAction::Block,
            network: "192.168.1.100/32".to_string(),
            duration_secs: 300,
            reason: "test: suspicious traffic pattern".to_string(),
            timestamp: now,
            nonce: "aabbccddeeff00112233445566778899".to_string(),
        }
    }

    fn make_test_bundle_ipv6() -> RuleBundle {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time must work")
            .as_secs();

        RuleBundle {
            version: PROTOCOL_VERSION,
            action: RuleAction::Block,
            network: "2001:db8::1/128".to_string(),
            duration_secs: 600,
            reason: "test: IPv6 suspicious traffic".to_string(),
            timestamp: now,
            nonce: "00112233445566778899aabbccddeeff".to_string(),
        }
    }

    fn setup() -> (MlDsa65, PublicKey, SecretKey) {
        let dsa = MlDsa65;
        let (pk, sk) = dsa.generate_keypair().expect("keygen must succeed");
        (dsa, pk, sk)
    }

    // ---- Sign + verify roundtrip ----------------------------------------

    #[test]
    fn test_sign_verify_roundtrip_ipv4() {
        let (dsa, pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign must succeed");
        let verified = verify_bundle_signature(&wire, &pk, &dsa)
            .expect("verify must succeed");

        assert_eq!(verified.version, PROTOCOL_VERSION);
        assert_eq!(verified.network, "192.168.1.100/32");
        assert_eq!(verified.duration_secs, 300);
    }

    #[test]
    fn test_sign_verify_roundtrip_ipv6() {
        let (dsa, pk, sk) = setup();
        let bundle = make_test_bundle_ipv6();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign must succeed");
        let verified = verify_bundle_signature(&wire, &pk, &dsa)
            .expect("verify must succeed");

        assert_eq!(verified.network, "2001:db8::1/128");
        assert_eq!(verified.duration_secs, 600);
    }

    #[test]
    fn test_sign_verify_allow_action() {
        let (dsa, pk, sk) = setup();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();

        let bundle = RuleBundle {
            version: PROTOCOL_VERSION,
            action: RuleAction::Allow,
            network: "10.0.0.0/8".to_string(),
            duration_secs: 0,
            reason: "allowlist override".to_string(),
            timestamp: now,
            nonce: "ffeeddccbbaa99887766554433221100".to_string(),
        };

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");
        let verified = verify_bundle_signature(&wire, &pk, &dsa).expect("verify");

        assert!(
            matches!(verified.action, RuleAction::Allow),
            "action must roundtrip as Allow"
        );
    }

    // ---- Verification failures ------------------------------------------

    #[test]
    fn test_verify_fails_with_wrong_public_key() {
        let (dsa, _pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        // Different keypair.
        let (pk2, _sk2) = dsa.generate_keypair().expect("keygen 2");

        let result = verify_bundle_signature(&wire, &pk2, &dsa);
        assert!(
            result.is_err(),
            "verify with wrong public key must fail"
        );
    }

    #[test]
    fn test_verify_fails_on_tampered_payload() {
        let (dsa, pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        // Parse the wire JSON and tamper with the payload.
        let mut envelope: serde_json::Value =
            serde_json::from_str(&wire).expect("parse wire JSON");

        let original_payload = envelope["payload"]
            .as_str()
            .expect("payload string")
            .to_string();

        // Flip a hex character in the payload.
        let mut tampered = original_payload.into_bytes();
        if !tampered.is_empty() {
            let idx = tampered.len() / 2;
            tampered[idx] = if tampered[idx] == b'a' { b'b' } else { b'a' };
        }
        envelope["payload"] = serde_json::Value::String(
            String::from_utf8(tampered).expect("valid utf8"),
        );

        let tampered_wire = serde_json::to_string(&envelope).expect("serialize");

        let result = verify_bundle_signature(&tampered_wire, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with tampered payload must fail"
        );
    }

    #[test]
    fn test_verify_fails_on_tampered_signature() {
        let (dsa, pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        let mut envelope: serde_json::Value =
            serde_json::from_str(&wire).expect("parse wire JSON");

        let original_sig = envelope["signature"]
            .as_str()
            .expect("signature string")
            .to_string();

        let mut tampered = original_sig.into_bytes();
        if !tampered.is_empty() {
            let idx = tampered.len() / 2;
            tampered[idx] = if tampered[idx] == b'a' { b'b' } else { b'a' };
        }
        envelope["signature"] = serde_json::Value::String(
            String::from_utf8(tampered).expect("valid utf8"),
        );

        let tampered_wire = serde_json::to_string(&envelope).expect("serialize");

        let result = verify_bundle_signature(&tampered_wire, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with tampered signature must fail"
        );
    }

    #[test]
    fn test_verify_fails_on_invalid_json() {
        let (dsa, pk, _sk) = setup();

        let result = verify_bundle_signature("not json at all", &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with invalid JSON must fail"
        );
    }

    #[test]
    fn test_verify_fails_on_missing_payload_field() {
        let (dsa, pk, _sk) = setup();

        let wire = r#"{"signature":"aabb"}"#;
        let result = verify_bundle_signature(wire, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with missing payload field must fail"
        );
    }

    #[test]
    fn test_verify_fails_on_missing_signature_field() {
        let (dsa, pk, _sk) = setup();

        let wire = r#"{"payload":"aabb"}"#;
        let result = verify_bundle_signature(wire, &pk, &dsa);
        assert!(
            result.is_err(),
            "verify with missing signature field must fail"
        );
    }

    // ---- Wire format validation -----------------------------------------

    #[test]
    fn test_wire_format_has_correct_fields() {
        let (dsa, _pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        let parsed: serde_json::Value =
            serde_json::from_str(&wire).expect("parse wire JSON");

        assert!(
            parsed.get("payload").is_some(),
            "wire format must have 'payload' field"
        );
        assert!(
            parsed.get("signature").is_some(),
            "wire format must have 'signature' field"
        );
        assert!(
            parsed.get("payload").expect("payload").is_string(),
            "'payload' must be a string"
        );
        assert!(
            parsed.get("signature").expect("signature").is_string(),
            "'signature' must be a string"
        );
    }

    #[test]
    fn test_wire_format_payload_is_hex_encoded_json() {
        let (dsa, _pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        let parsed: serde_json::Value =
            serde_json::from_str(&wire).expect("parse wire JSON");

        let payload_hex = parsed["payload"].as_str().expect("payload string");

        // Decode hex -> should be valid JSON of a RuleBundle.
        let payload_bytes = hex::decode(payload_hex).expect("payload must be valid hex");
        let decoded_bundle: RuleBundle =
            serde_json::from_slice(&payload_bytes).expect("must be valid RuleBundle JSON");

        assert_eq!(decoded_bundle.version, PROTOCOL_VERSION);
        assert_eq!(decoded_bundle.network, bundle.network);
    }

    #[test]
    fn test_wire_format_signature_is_valid_hex() {
        let (dsa, _pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        let parsed: serde_json::Value =
            serde_json::from_str(&wire).expect("parse wire JSON");

        let sig_hex = parsed["signature"].as_str().expect("signature string");
        let sig_bytes = hex::decode(sig_hex).expect("signature must be valid hex");

        assert_eq!(
            sig_bytes.len(),
            spinal_cord::crypto::dsa::SIGNATURE_BYTES,
            "signature must be exactly SIGNATURE_BYTES (3309) bytes"
        );
    }

    // ---- Compatibility with spinal-cord handler -------------------------

    #[test]
    fn test_wire_format_deserializes_as_signed_bundle() {
        let (dsa, _pk, sk) = setup();
        let bundle = make_test_bundle();

        let wire = sign_bundle(&bundle, &sk, &dsa).expect("sign");

        // The wire format must be deserializable as spinal_cord's SignedBundle.
        let signed: spinal_cord::ipc::protocol::SignedBundle =
            serde_json::from_str(&wire).expect(
                "wire format must deserialize as SignedBundle (handler compatibility)"
            );

        // Verify the payload field is non-empty hex.
        assert!(
            !signed.payload.is_empty(),
            "payload must not be empty"
        );
        assert!(
            hex::decode(&signed.payload).is_ok(),
            "payload must be valid hex"
        );

        // Verify the signature field is non-empty hex.
        assert!(
            !signed.signature.is_empty(),
            "signature must not be empty"
        );
        assert!(
            hex::decode(&signed.signature).is_ok(),
            "signature must be valid hex"
        );
    }
}
