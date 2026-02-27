//! Key storage backends for ML-DSA-65 keypairs.
//!
//! # Trust model
//!
//! The [`KeyStore`] trait abstracts over the actual storage mechanism.  Three
//! implementations are provided:
//!
//! | Backend          | Status     | Production? | Notes                       |
//! |------------------|------------|-------------|-----------------------------|
//! | [`FileKeyStore`] | Functional | **NO**      | Dev only; warns on creation |
//! | [`TpmKeyStore`]  | Stub       | Yes (future)| TPM 2.0 via `tss-esapi`     |
//! | [`VaultKeyStore`]| Stub       | Yes (future)| `HashiCorp` Vault transit     |
//!
//! # Key format on disk (`FileKeyStore` only)
//!
//! ```text
//! <base_dir>/<key_id>/pk.hex   -- hex-encoded ML-DSA-65 public key (1952 bytes)
//! <base_dir>/<key_id>/sk.hex   -- hex-encoded ML-DSA-65 seed (32 bytes)
//! ```
//!
//! The secret key file is created with `0o600` permissions (owner read/write
//! only).  This is a **minimal** protection -- not a substitute for TPM/Vault.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tracing::warn;

use spinal_cord::crypto::traits::{PublicKey, SecretKey};

// ---------------------------------------------------------------------------
// KeyId -- validated key identifier
// ---------------------------------------------------------------------------

/// A validated key identifier.
///
/// Constraints:
/// - Non-empty
/// - Maximum 64 characters
/// - Characters: ASCII alphanumeric plus hyphen (`-`) and underscore (`_`)
///
/// This prevents path traversal attacks when used as a directory name in
/// [`FileKeyStore`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Maximum length of a key identifier in characters.
    pub const MAX_LEN: usize = 64;

    /// Create a new `KeyId` after validation.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::InvalidKeyId`] if the input is empty, exceeds
    /// [`Self::MAX_LEN`] characters, or contains characters outside
    /// `[a-zA-Z0-9_-]`.
    pub fn new(id: &str) -> Result<Self, KeyStoreError> {
        if id.is_empty() {
            return Err(KeyStoreError::InvalidKeyId(
                "key ID must not be empty".to_string(),
            ));
        }
        if id.len() > Self::MAX_LEN {
            return Err(KeyStoreError::InvalidKeyId(format!(
                "key ID exceeds {} characters: got {}",
                Self::MAX_LEN,
                id.len()
            )));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(KeyStoreError::InvalidKeyId(format!(
                "key ID contains invalid characters (allowed: [a-zA-Z0-9_-]): {id}"
            )));
        }
        Ok(Self(id.to_string()))
    }

    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// KeyStoreError
// ---------------------------------------------------------------------------

/// Errors from key storage operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// The key identifier failed validation.
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),

    /// The requested key was not found in the store.
    #[error("key not found: {0}")]
    NotFound(String),

    /// An I/O error occurred during storage operations.
    #[error("key store I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Hex encoding/decoding failed (corrupted key file).
    #[error("hex codec error: {0}")]
    HexCodec(String),

    /// The backend is not yet implemented.
    #[error("backend not implemented: {0}")]
    NotImplemented(String),

    /// A key with this ID already exists.
    #[error("key already exists: {0}")]
    AlreadyExists(String),
}

// ---------------------------------------------------------------------------
// KeyStore trait
// ---------------------------------------------------------------------------

/// Abstraction over PQC key storage backends.
///
/// All implementations must be `Send + Sync` for safe use across Tokio tasks
/// and Rayon threads (via `crossbeam::channel` at the boundary).
pub trait KeyStore: Send + Sync {
    /// Store a keypair under `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::AlreadyExists`] if a key with this ID is
    /// already stored, or [`KeyStoreError::Io`] on storage failure.
    fn store_keypair(
        &self,
        key_id: &KeyId,
        pk: &PublicKey,
        sk: &SecretKey,
    ) -> Result<(), KeyStoreError>;

    /// Load the public key for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::NotFound`] if the key does not exist.
    fn load_public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyStoreError>;

    /// Load the secret key for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::NotFound`] if the key does not exist.
    fn load_secret_key(&self, key_id: &KeyId) -> Result<SecretKey, KeyStoreError>;

    /// Delete the keypair for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::NotFound`] if the key does not exist.
    fn delete_keypair(&self, key_id: &KeyId) -> Result<(), KeyStoreError>;

    /// List all stored key IDs.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::Io`] on storage failure.
    fn list_key_ids(&self) -> Result<Vec<KeyId>, KeyStoreError>;
}

// ---------------------------------------------------------------------------
// FileKeyStore -- development only
// ---------------------------------------------------------------------------

/// File-system backed key store for **development use only**.
///
/// Stores keys as hex-encoded files under a base directory.  This backend
/// is NOT suitable for production -- private keys reside as files on disk.
/// Production deployments must use TPM 2.0 or `HashiCorp` Vault transit
/// (Security Invariant #7 in CLAUDE.md).
///
/// A `tracing::warn!` is emitted on construction to make accidental
/// production use visible in logs.
pub struct FileKeyStore {
    base_dir: PathBuf,
}

impl FileKeyStore {
    /// Create a new `FileKeyStore` rooted at `base_dir`.
    ///
    /// Emits a `WARN`-level tracing event.  The directory is created if it
    /// does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::Io`] if the directory cannot be created.
    pub fn new(base_dir: &Path) -> Result<Self, KeyStoreError> {
        warn!(
            path = %base_dir.display(),
            "FileKeyStore is for DEVELOPMENT ONLY -- \
             never use in production (Security Invariant #7)"
        );
        fs::create_dir_all(base_dir)?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Return the directory path for a given key ID.
    fn key_dir(&self, key_id: &KeyId) -> PathBuf {
        self.base_dir.join(key_id.as_str())
    }

    /// Return the public key file path.
    fn pk_path(&self, key_id: &KeyId) -> PathBuf {
        self.key_dir(key_id).join("pk.hex")
    }

    /// Return the secret key file path.
    fn sk_path(&self, key_id: &KeyId) -> PathBuf {
        self.key_dir(key_id).join("sk.hex")
    }
}

impl KeyStore for FileKeyStore {
    fn store_keypair(
        &self,
        key_id: &KeyId,
        pk: &PublicKey,
        sk: &SecretKey,
    ) -> Result<(), KeyStoreError> {
        let dir = self.key_dir(key_id);

        if dir.exists() {
            return Err(KeyStoreError::AlreadyExists(key_id.to_string()));
        }

        fs::create_dir_all(&dir)?;

        // Write public key as hex.
        let pk_hex = hex::encode(&pk.0);
        fs::write(self.pk_path(key_id), pk_hex.as_bytes())?;

        // Write secret key as hex with restricted permissions.
        let sk_hex = hex::encode(&sk.0);
        let sk_path = self.sk_path(key_id);
        fs::write(&sk_path, sk_hex.as_bytes())?;
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))?;

        Ok(())
    }

    fn load_public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyStoreError> {
        let path = self.pk_path(key_id);
        if !path.exists() {
            return Err(KeyStoreError::NotFound(key_id.to_string()));
        }
        let hex_str = fs::read_to_string(&path)?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| KeyStoreError::HexCodec(format!("pk decode: {e}")))?;
        Ok(PublicKey(bytes))
    }

    fn load_secret_key(&self, key_id: &KeyId) -> Result<SecretKey, KeyStoreError> {
        let path = self.sk_path(key_id);
        if !path.exists() {
            return Err(KeyStoreError::NotFound(key_id.to_string()));
        }
        let hex_str = fs::read_to_string(&path)?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| KeyStoreError::HexCodec(format!("sk decode: {e}")))?;
        Ok(SecretKey(bytes))
    }

    fn delete_keypair(&self, key_id: &KeyId) -> Result<(), KeyStoreError> {
        let dir = self.key_dir(key_id);
        if !dir.exists() {
            return Err(KeyStoreError::NotFound(key_id.to_string()));
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    fn list_key_ids(&self) -> Result<Vec<KeyId>, KeyStoreError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    // Only include directories that pass KeyId validation
                    // (skip any stray files/dirs that don't match our naming).
                    if let Ok(kid) = KeyId::new(name) {
                        ids.push(kid);
                    }
                }
            }
        }
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(ids)
    }
}

// ---------------------------------------------------------------------------
// TpmKeyStore -- stub for TPM 2.0 backend
// ---------------------------------------------------------------------------

/// TPM 2.0 key storage backend (stub -- not yet implemented).
///
/// Production deployments should use this backend via the `tss-esapi` crate.
/// Key material never leaves the TPM chip.
pub struct TpmKeyStore;

impl KeyStore for TpmKeyStore {
    fn store_keypair(
        &self,
        _key_id: &KeyId,
        _pk: &PublicKey,
        _sk: &SecretKey,
    ) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "TPM 2.0 backend".to_string(),
        ))
    }

    fn load_public_key(&self, _key_id: &KeyId) -> Result<PublicKey, KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "TPM 2.0 backend".to_string(),
        ))
    }

    fn load_secret_key(&self, _key_id: &KeyId) -> Result<SecretKey, KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "TPM 2.0 backend".to_string(),
        ))
    }

    fn delete_keypair(&self, _key_id: &KeyId) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "TPM 2.0 backend".to_string(),
        ))
    }

    fn list_key_ids(&self) -> Result<Vec<KeyId>, KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "TPM 2.0 backend".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// VaultKeyStore -- stub for `HashiCorp` Vault transit
// ---------------------------------------------------------------------------

/// `HashiCorp` Vault transit key storage backend (stub -- not yet implemented).
///
/// Production deployments should use this as a secondary backend when TPM 2.0
/// is not available.  Uses `vaultrs` crate for API access.
pub struct VaultKeyStore;

impl KeyStore for VaultKeyStore {
    fn store_keypair(
        &self,
        _key_id: &KeyId,
        _pk: &PublicKey,
        _sk: &SecretKey,
    ) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "`HashiCorp` Vault transit".to_string(),
        ))
    }

    fn load_public_key(&self, _key_id: &KeyId) -> Result<PublicKey, KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "`HashiCorp` Vault transit".to_string(),
        ))
    }

    fn load_secret_key(&self, _key_id: &KeyId) -> Result<SecretKey, KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "`HashiCorp` Vault transit".to_string(),
        ))
    }

    fn delete_keypair(&self, _key_id: &KeyId) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "`HashiCorp` Vault transit".to_string(),
        ))
    }

    fn list_key_ids(&self) -> Result<Vec<KeyId>, KeyStoreError> {
        Err(KeyStoreError::NotImplemented(
            "`HashiCorp` Vault transit".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spinal_cord::crypto::dsa::MlDsa65;
    use tempfile::TempDir;

    fn make_test_keypair() -> (PublicKey, SecretKey) {
        let dsa = MlDsa65;
        dsa.generate_keypair().expect("keygen must succeed")
    }

    // ---- KeyId validation -----------------------------------------------

    #[test]
    fn test_key_id_valid_alphanumeric() {
        let kid = KeyId::new("vglf-signing-key-2026").expect("valid key ID");
        assert_eq!(kid.as_str(), "vglf-signing-key-2026");
    }

    #[test]
    fn test_key_id_valid_with_underscores() {
        let kid = KeyId::new("model_signer_v1").expect("valid key ID");
        assert_eq!(kid.as_str(), "model_signer_v1");
    }

    #[test]
    fn test_key_id_valid_single_char() {
        let kid = KeyId::new("a").expect("single char is valid");
        assert_eq!(kid.as_str(), "a");
    }

    #[test]
    fn test_key_id_valid_max_length() {
        let long_id = "a".repeat(KeyId::MAX_LEN);
        let kid = KeyId::new(&long_id).expect("max length is valid");
        assert_eq!(kid.as_str().len(), KeyId::MAX_LEN);
    }

    #[test]
    fn test_key_id_rejects_empty() {
        assert!(
            KeyId::new("").is_err(),
            "empty key ID must be rejected"
        );
    }

    #[test]
    fn test_key_id_rejects_too_long() {
        let long_id = "a".repeat(KeyId::MAX_LEN + 1);
        assert!(
            KeyId::new(&long_id).is_err(),
            "key ID exceeding MAX_LEN must be rejected"
        );
    }

    #[test]
    fn test_key_id_rejects_path_traversal() {
        assert!(
            KeyId::new("../etc/passwd").is_err(),
            "path traversal characters must be rejected"
        );
    }

    #[test]
    fn test_key_id_rejects_spaces() {
        assert!(
            KeyId::new("my key").is_err(),
            "spaces must be rejected"
        );
    }

    #[test]
    fn test_key_id_rejects_dots() {
        assert!(
            KeyId::new("key.id").is_err(),
            "dots must be rejected to prevent path traversal"
        );
    }

    #[test]
    fn test_key_id_rejects_slashes() {
        assert!(
            KeyId::new("key/id").is_err(),
            "slashes must be rejected"
        );
    }

    #[test]
    fn test_key_id_rejects_null_byte() {
        assert!(
            KeyId::new("key\0id").is_err(),
            "null bytes must be rejected"
        );
    }

    // ---- FileKeyStore: store/load/delete/list roundtrip -----------------

    #[test]
    fn test_file_keystore_store_and_load_roundtrip() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let (pk, sk) = make_test_keypair();
        let kid = KeyId::new("test-key-1").expect("valid key ID");

        store
            .store_keypair(&kid, &pk, &sk)
            .expect("store must succeed");

        let got_pub = store.load_public_key(&kid).expect("load pk");
        let got_sec = store.load_secret_key(&kid).expect("load sk");

        assert_eq!(got_pub.0, pk.0, "public key roundtrip must match");
        assert_eq!(got_sec.0, sk.0, "secret key roundtrip must match");
    }

    #[test]
    fn test_file_keystore_store_rejects_duplicate() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let (pk, sk) = make_test_keypair();
        let kid = KeyId::new("dup-test").expect("valid key ID");

        store
            .store_keypair(&kid, &pk, &sk)
            .expect("first store must succeed");

        let result = store.store_keypair(&kid, &pk, &sk);
        assert!(
            result.is_err(),
            "storing duplicate key ID must fail"
        );
    }

    #[test]
    fn test_file_keystore_delete() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let (pk, sk) = make_test_keypair();
        let kid = KeyId::new("delete-test").expect("valid key ID");

        store
            .store_keypair(&kid, &pk, &sk)
            .expect("store must succeed");
        store.delete_keypair(&kid).expect("delete must succeed");

        assert!(
            store.load_public_key(&kid).is_err(),
            "loading deleted key must fail"
        );
        assert!(
            store.load_secret_key(&kid).is_err(),
            "loading deleted secret key must fail"
        );
    }

    #[test]
    fn test_file_keystore_delete_nonexistent_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let kid = KeyId::new("ghost-key").expect("valid key ID");

        assert!(
            store.delete_keypair(&kid).is_err(),
            "deleting nonexistent key must fail"
        );
    }

    #[test]
    fn test_file_keystore_list_key_ids() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");

        let ids_empty = store.list_key_ids().expect("list empty");
        assert!(ids_empty.is_empty(), "empty store must list no keys");

        let (pk1, sk1) = make_test_keypair();
        let (pk2, sk2) = make_test_keypair();
        let kid1 = KeyId::new("alpha").expect("valid key ID");
        let kid2 = KeyId::new("beta").expect("valid key ID");

        store
            .store_keypair(&kid1, &pk1, &sk1)
            .expect("store 1 must succeed");
        store
            .store_keypair(&kid2, &pk2, &sk2)
            .expect("store 2 must succeed");

        let ids = store.list_key_ids().expect("list");
        assert_eq!(ids.len(), 2, "must list both stored keys");

        // list_key_ids sorts alphabetically.
        assert_eq!(ids[0].as_str(), "alpha");
        assert_eq!(ids[1].as_str(), "beta");
    }

    #[test]
    fn test_file_keystore_load_nonexistent_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let kid = KeyId::new("no-such-key").expect("valid key ID");

        assert!(
            store.load_public_key(&kid).is_err(),
            "loading nonexistent public key must fail"
        );
        assert!(
            store.load_secret_key(&kid).is_err(),
            "loading nonexistent secret key must fail"
        );
    }

    #[test]
    fn test_file_keystore_sk_permissions() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let (pk, sk) = make_test_keypair();
        let kid = KeyId::new("perm-test").expect("valid key ID");

        store
            .store_keypair(&kid, &pk, &sk)
            .expect("store must succeed");

        let sk_path = store.sk_path(&kid);
        let metadata = fs::metadata(&sk_path).expect("sk file must exist");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "secret key file must have 0o600 permissions, got {mode:#o}"
        );
    }

    // ---- Stub backends --------------------------------------------------

    #[test]
    fn test_tpm_keystore_returns_not_implemented() {
        let store = TpmKeyStore;
        let kid = KeyId::new("test").expect("valid key ID");
        let (pk, sk) = make_test_keypair();

        assert!(store.store_keypair(&kid, &pk, &sk).is_err());
        assert!(store.load_public_key(&kid).is_err());
        assert!(store.load_secret_key(&kid).is_err());
        assert!(store.delete_keypair(&kid).is_err());
        assert!(store.list_key_ids().is_err());
    }

    #[test]
    fn test_vault_keystore_returns_not_implemented() {
        let store = VaultKeyStore;
        let kid = KeyId::new("test").expect("valid key ID");
        let (pk, sk) = make_test_keypair();

        assert!(store.store_keypair(&kid, &pk, &sk).is_err());
        assert!(store.load_public_key(&kid).is_err());
        assert!(store.load_secret_key(&kid).is_err());
        assert!(store.delete_keypair(&kid).is_err());
        assert!(store.list_key_ids().is_err());
    }

    // ---- Multiple store/delete cycles -----------------------------------

    #[test]
    fn test_file_keystore_reuse_id_after_delete() {
        let tmp = TempDir::new().expect("tempdir");
        let store = FileKeyStore::new(tmp.path()).expect("create store");
        let kid = KeyId::new("recycle").expect("valid key ID");

        let (pk1, sk1) = make_test_keypair();
        store
            .store_keypair(&kid, &pk1, &sk1)
            .expect("store 1 must succeed");
        store.delete_keypair(&kid).expect("delete must succeed");

        // Re-store with different keys.
        let (pk2, sk2) = make_test_keypair();
        store
            .store_keypair(&kid, &pk2, &sk2)
            .expect("re-store after delete must succeed");

        let loaded_pk = store.load_public_key(&kid).expect("load pk");
        assert_eq!(
            loaded_pk.0, pk2.0,
            "re-stored key must return the new public key"
        );
    }
}
