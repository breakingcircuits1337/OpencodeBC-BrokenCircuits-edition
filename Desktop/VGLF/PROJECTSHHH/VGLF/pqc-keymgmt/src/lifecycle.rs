//! Key lifecycle management -- generation, rotation, and metadata tracking.
//!
//! The [`KeyManager`] struct ties together a [`KeyStore`] backend and a
//! [`DigitalSignature`] implementation (always ML-DSA-65 in VGLF) to provide
//! high-level key lifecycle operations.
//!
//! # Rotation model
//!
//! When a key is rotated via [`KeyManager::rotate_keypair`], the old key is
//! **retained** in the store for a verification window.  This allows
//! in-flight signed bundles and model sidecars to be verified against the
//! previous key while new signatures are produced with the rotated key.
//! The caller is responsible for eventually calling
//! [`KeyManager::revoke_keypair`] to remove the old key once the window
//! closes.

use std::time::{SystemTime, UNIX_EPOCH};

use spinal_cord::crypto::traits::{CryptoError, DigitalSignature, PublicKey};

use crate::keystore::{KeyId, KeyStore, KeyStoreError};

// ---------------------------------------------------------------------------
// KeyMetadata
// ---------------------------------------------------------------------------

/// Metadata associated with a stored keypair.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMetadata {
    /// The unique key identifier.
    pub key_id: String,

    /// The algorithm identifier (e.g. `"ML-DSA-65"`).
    pub algorithm_id: String,

    /// Unix timestamp (seconds since epoch) when the key was generated.
    pub created_at: u64,

    /// Current lifecycle status.
    pub status: KeyStatus,
}

/// Lifecycle status of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyStatus {
    /// Key is the current active signing key.
    Active,
    /// Key has been superseded by a rotation but is still valid for
    /// verification during the grace window.
    Rotated,
    /// Key has been explicitly revoked and must not be used for any purpose.
    Revoked,
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("Active"),
            Self::Rotated => f.write_str("Rotated"),
            Self::Revoked => f.write_str("Revoked"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyManagerError
// ---------------------------------------------------------------------------

/// Errors from key lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyManagerError {
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Key store operation failed.
    #[error("key store error: {0}")]
    Store(#[from] KeyStoreError),
}

// ---------------------------------------------------------------------------
// KeyManager
// ---------------------------------------------------------------------------

/// High-level key lifecycle manager.
///
/// Wraps a [`KeyStore`] and a [`DigitalSignature`] implementation to provide
/// generate / rotate / revoke operations with metadata tracking.
///
/// The manager does not hold any key material in memory beyond what the
/// store returns on `load_*` calls.
pub struct KeyManager {
    store: Box<dyn KeyStore>,
    dsa: Box<dyn DigitalSignature>,
}

impl KeyManager {
    /// Create a new `KeyManager` with the given store and DSA implementation.
    #[must_use]
    pub fn new(store: Box<dyn KeyStore>, dsa: Box<dyn DigitalSignature>) -> Self {
        Self { store, dsa }
    }

    /// Return a reference to the underlying DSA implementation.
    ///
    /// Useful when callers need the trait object for signing/verification
    /// outside the lifecycle manager (e.g. model signing, bundle signing).
    #[must_use]
    pub fn dsa(&self) -> &dyn DigitalSignature {
        self.dsa.as_ref()
    }

    /// Return a reference to the underlying key store.
    #[must_use]
    pub fn store(&self) -> &dyn KeyStore {
        self.store.as_ref()
    }

    /// Generate a fresh ML-DSA-65 keypair and store it.
    ///
    /// Returns the [`PublicKey`] and [`KeyMetadata`] for the new key.
    /// The secret key is persisted in the store and never returned to the
    /// caller directly.
    ///
    /// # Errors
    ///
    /// Returns [`KeyManagerError::Crypto`] if key generation fails, or
    /// [`KeyManagerError::Store`] if the store rejects the key.
    pub fn generate_keypair(
        &self,
        key_id: &str,
    ) -> Result<(PublicKey, KeyMetadata), KeyManagerError> {
        let kid = KeyId::new(key_id)?;

        // Generate via the DigitalSignature trait -- never call aws-lc-rs
        // directly.  The MlDsa65 struct exposes generate_keypair() as an
        // inherent method; we need to downcast or use it.  Since the trait
        // does not expose keygen, we use the concrete MlDsa65 method via
        // the fact that we know the algorithm_id.  However, for crypto
        // agility, we keep the trait reference and use the concrete type
        // through a helper.
        //
        // NOTE: The DigitalSignature trait intentionally does not include
        // generate_keypair() -- that is an inherent method on MlDsa65.
        // We call it here through the concrete type.  This is acceptable
        // because KeyManager is the only entry point for key generation
        // in the lifecycle, and the algorithm is identified by algorithm_id().
        let dsa = spinal_cord::crypto::dsa::MlDsa65;
        let (pk, sk) = dsa.generate_keypair()?;

        self.store.store_keypair(&kid, &pk, &sk)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let metadata = KeyMetadata {
            key_id: key_id.to_string(),
            algorithm_id: self.dsa.algorithm_id().to_string(),
            created_at: now,
            status: KeyStatus::Active,
        };

        Ok((pk, metadata))
    }

    /// Rotate a keypair: generate a new key under `new_id`, retain the old
    /// key under `old_id` for verification during the grace window.
    ///
    /// The old key's status conceptually transitions to [`KeyStatus::Rotated`],
    /// but since the file store does not persist metadata alongside keys, the
    /// caller must track status externally (e.g. in a database or config).
    ///
    /// # Errors
    ///
    /// Returns an error if the old key does not exist, or if generating /
    /// storing the new key fails.
    #[allow(clippy::similar_names)] // old_kid/old_id are standard key-mgmt naming
    pub fn rotate_keypair(
        &self,
        old_id: &str,
        new_id: &str,
    ) -> Result<(PublicKey, KeyMetadata), KeyManagerError> {
        let old_kid = KeyId::new(old_id)?;

        // Verify the old key exists -- fail early if not.
        let _old_pk = self.store.load_public_key(&old_kid)?;

        // Generate and store the new key.
        let (new_pk, metadata) = self.generate_keypair(new_id)?;

        // The old key remains in the store for the verification window.
        // It is not deleted here -- the caller must explicitly revoke it
        // via revoke_keypair() when the window closes.

        Ok((new_pk, metadata))
    }

    /// Revoke and delete a keypair from the store.
    ///
    /// After this call, the key material is removed from the backend.
    /// For [`FileKeyStore`], the secret key file is overwritten before
    /// deletion (via `fs::remove_dir_all`).
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist or cannot be deleted.
    pub fn revoke_keypair(&self, key_id: &str) -> Result<(), KeyManagerError> {
        let kid = KeyId::new(key_id)?;
        self.store.delete_keypair(&kid)?;
        Ok(())
    }

    /// List all key IDs in the store.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot enumerate keys.
    pub fn list_keys(&self) -> Result<Vec<KeyId>, KeyManagerError> {
        Ok(self.store.list_key_ids()?)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::FileKeyStore;
    use spinal_cord::crypto::dsa::MlDsa65;
    use tempfile::TempDir;

    fn make_manager(dir: &std::path::Path) -> KeyManager {
        let store = FileKeyStore::new(dir).expect("create store");
        let dsa = MlDsa65;
        KeyManager::new(Box::new(store), Box::new(dsa))
    }

    // ---- generate_keypair -----------------------------------------------

    #[test]
    fn test_generate_keypair_stores_and_returns_pk() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        let (pk, meta) = mgr
            .generate_keypair("gen-test-1")
            .expect("generate must succeed");

        assert_eq!(meta.key_id, "gen-test-1");
        assert_eq!(meta.algorithm_id, "ML-DSA-65");
        assert_eq!(meta.status, KeyStatus::Active);
        assert!(meta.created_at > 0, "created_at must be a positive timestamp");

        // Verify the public key is loadable from the store.
        let kid = KeyId::new("gen-test-1").expect("valid key ID");
        let stored_pk = mgr.store().load_public_key(&kid).expect("load pk");
        assert_eq!(stored_pk.0, pk.0, "stored pk must match returned pk");
    }

    #[test]
    fn test_generate_keypair_produces_valid_signing_key() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        let (pk, _meta) = mgr
            .generate_keypair("sign-test")
            .expect("generate must succeed");

        // Load the secret key and sign a message.
        let kid = KeyId::new("sign-test").expect("valid key ID");
        let sk = mgr.store().load_secret_key(&kid).expect("load sk");

        let msg = b"VGLF lifecycle test message";
        let sig = mgr.dsa().sign(&sk, msg).expect("sign must succeed");
        mgr.dsa()
            .verify(&pk, msg, &sig)
            .expect("verify must succeed with generated key");
    }

    #[test]
    fn test_generate_keypair_rejects_duplicate_id() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        mgr.generate_keypair("dup-id").expect("first generate");
        let result = mgr.generate_keypair("dup-id");
        assert!(
            result.is_err(),
            "generating with duplicate key ID must fail"
        );
    }

    #[test]
    fn test_generate_keypair_rejects_invalid_id() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        let result = mgr.generate_keypair("../escape");
        assert!(
            result.is_err(),
            "path traversal key ID must be rejected"
        );
    }

    // ---- rotate_keypair -------------------------------------------------

    #[test]
    fn test_rotate_keypair_creates_new_and_retains_old() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        let (old_pk, _) = mgr
            .generate_keypair("rotate-old")
            .expect("generate old key");
        let (new_pk, new_meta) = mgr
            .rotate_keypair("rotate-old", "rotate-new")
            .expect("rotate must succeed");

        assert_eq!(new_meta.key_id, "rotate-new");
        assert_eq!(new_meta.status, KeyStatus::Active);

        // Old key must still be loadable (verification window).
        let old_kid = KeyId::new("rotate-old").expect("valid key ID");
        let loaded_old_pk = mgr
            .store()
            .load_public_key(&old_kid)
            .expect("old pk must still be loadable");
        assert_eq!(loaded_old_pk.0, old_pk.0);

        // New key must be different from old key.
        assert_ne!(
            old_pk.0, new_pk.0,
            "rotated key must differ from old key"
        );

        // Both keys must be listed.
        let ids = mgr.list_keys().expect("list keys");
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_rotate_keypair_fails_if_old_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        let result = mgr.rotate_keypair("nonexistent", "new-key");
        assert!(
            result.is_err(),
            "rotating from nonexistent key must fail"
        );
    }

    // ---- revoke_keypair -------------------------------------------------

    #[test]
    fn test_revoke_keypair_removes_key() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        mgr.generate_keypair("revoke-test")
            .expect("generate must succeed");
        mgr.revoke_keypair("revoke-test")
            .expect("revoke must succeed");

        let kid = KeyId::new("revoke-test").expect("valid key ID");
        assert!(
            mgr.store().load_public_key(&kid).is_err(),
            "revoked key must not be loadable"
        );
    }

    #[test]
    fn test_revoke_nonexistent_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        let result = mgr.revoke_keypair("ghost");
        assert!(
            result.is_err(),
            "revoking nonexistent key must fail"
        );
    }

    // ---- Full lifecycle: generate -> rotate -> revoke old ---------------

    #[test]
    fn test_full_lifecycle() {
        let tmp = TempDir::new().expect("tempdir");
        let mgr = make_manager(tmp.path());

        // 1. Generate initial key.
        let (pk_v1, _) = mgr.generate_keypair("key-v1").expect("gen v1");

        // 2. Sign with v1.
        let kid_v1 = KeyId::new("key-v1").expect("valid");
        let sk_v1 = mgr.store().load_secret_key(&kid_v1).expect("load sk v1");
        let msg = b"lifecycle test message";
        let sig_v1 = mgr.dsa().sign(&sk_v1, msg).expect("sign v1");
        mgr.dsa()
            .verify(&pk_v1, msg, &sig_v1)
            .expect("verify v1");

        // 3. Rotate to v2.
        let (pk_v2, _) = mgr.rotate_keypair("key-v1", "key-v2").expect("rotate");

        // 4. Verify v1 signature still works (verification window).
        mgr.dsa()
            .verify(&pk_v1, msg, &sig_v1)
            .expect("v1 sig must still verify during grace window");

        // 5. Sign with v2.
        let kid_v2 = KeyId::new("key-v2").expect("valid");
        let sk_v2 = mgr.store().load_secret_key(&kid_v2).expect("load sk v2");
        let sig_v2 = mgr.dsa().sign(&sk_v2, msg).expect("sign v2");
        mgr.dsa()
            .verify(&pk_v2, msg, &sig_v2)
            .expect("verify v2");

        // 6. Cross-key verification must fail.
        assert!(
            mgr.dsa().verify(&pk_v1, msg, &sig_v2).is_err(),
            "v2 signature must not verify with v1 public key"
        );

        // 7. Revoke v1.
        mgr.revoke_keypair("key-v1").expect("revoke v1");

        // 8. Only v2 remains.
        let ids = mgr.list_keys().expect("list");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str(), "key-v2");
    }

    // ---- KeyMetadata ----------------------------------------------------

    #[test]
    fn test_key_metadata_serialization() {
        let meta = KeyMetadata {
            key_id: "test-key".to_string(),
            algorithm_id: "ML-DSA-65".to_string(),
            created_at: 1_740_000_000,
            status: KeyStatus::Active,
        };

        let json = serde_json::to_string(&meta).expect("serialize metadata");
        let deserialized: KeyMetadata =
            serde_json::from_str(&json).expect("deserialize metadata");

        assert_eq!(deserialized.key_id, "test-key");
        assert_eq!(deserialized.algorithm_id, "ML-DSA-65");
        assert_eq!(deserialized.created_at, 1_740_000_000);
        assert_eq!(deserialized.status, KeyStatus::Active);
    }

    #[test]
    fn test_key_status_display() {
        assert_eq!(format!("{}", KeyStatus::Active), "Active");
        assert_eq!(format!("{}", KeyStatus::Rotated), "Rotated");
        assert_eq!(format!("{}", KeyStatus::Revoked), "Revoked");
    }
}
