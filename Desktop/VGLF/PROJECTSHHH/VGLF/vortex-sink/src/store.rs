//! AES-256-GCM encrypted at-rest segment storage.
//!
//! # Storage model
//!
//! Each log segment is stored as an individual encrypted file on disk:
//!
//! ```text
//! base_dir/
//! ├── 000000000000.seg     ← encrypted segment 0
//! ├── 000000000001.seg     ← encrypted segment 1
//! ├── ...
//! └── chain.json           ← last known hash + index for chain resumption
//! ```
//!
//! # Encryption
//!
//! Each segment is encrypted with AES-256-GCM (already PQ-secure per CLAUDE.md):
//! - A fresh 96-bit (12-byte) nonce is generated per segment.
//! - The segment index is included as additional authenticated data (AAD)
//!   to bind the ciphertext to its position in the chain.
//! - The encrypted file format: `nonce (12) || ciphertext || tag (16)`.
//!
//! # Key management
//!
//! The encryption key is provided externally (from `pqc-keymgmt` in production).
//! This module never generates or stores encryption keys.

use std::fs;
use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
    NONCE_LEN,
};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::merkle::SegmentHash;

/// AES-256-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the segment store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encryption failed")]
    EncryptFailed,

    #[error("decryption failed (tampered or wrong key)")]
    DecryptFailed,

    #[error("segment file too short to contain nonce + tag")]
    FileTooShort,

    #[error("chain state file corrupted: {0}")]
    ChainStateCorrupt(String),
}

// ---------------------------------------------------------------------------
// Chain state (for resumption after restart)
// ---------------------------------------------------------------------------

/// Persisted chain state for resumption after service restart.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainState {
    /// Hex-encoded SHA3-256 hash of the last segment.
    pub last_hash: String,

    /// Index to assign to the next segment.
    pub next_index: u64,
}

// ---------------------------------------------------------------------------
// Single-nonce provider for AES-256-GCM sealing/opening
// ---------------------------------------------------------------------------

/// A `NonceSequence` that returns a single pre-generated nonce exactly once.
///
/// AES-256-GCM requires a unique nonce per encryption.  We generate a fresh
/// random nonce for each segment, then wrap it in this type to satisfy the
/// `NonceSequence` trait required by `aws-lc-rs`.
struct SingleNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(Unspecified)
    }
}

// ---------------------------------------------------------------------------
// SegmentStore
// ---------------------------------------------------------------------------

/// Encrypted segment store backed by the local filesystem.
///
/// Each segment is encrypted with AES-256-GCM before writing.  The store
/// never holds key material — it receives a 32-byte key reference per
/// operation and does not cache it.
pub struct SegmentStore {
    /// Base directory for segment files and chain state.
    base_dir: PathBuf,
}

impl SegmentStore {
    /// Create a new segment store at the given directory.
    ///
    /// Creates the directory if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if the directory cannot be created.
    pub fn new(base_dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(base_dir)?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Write an encrypted segment to disk.
    ///
    /// # Parameters
    ///
    /// - `index` — the segment index (used for filename and AAD).
    /// - `plaintext` — the raw segment data.
    /// - `key` — the 32-byte AES-256-GCM key (caller must zeroize after use).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on encryption or I/O failure.
    pub fn write_segment(
        &self,
        index: u64,
        plaintext: &[u8],
        key: &[u8; KEY_LEN],
    ) -> Result<(), StoreError> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| StoreError::EncryptFailed)?;

        // AAD = segment index as little-endian u64.
        // This binds the ciphertext to its position in the chain.
        let aad = Aad::from(index.to_le_bytes());

        // Encrypt: plaintext is modified in-place and a tag is appended.
        let unbound_key =
            UnboundKey::new(&AES_256_GCM, key).map_err(|_| StoreError::EncryptFailed)?;
        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(aad, &mut in_out)
            .map_err(|_| StoreError::EncryptFailed)?;

        // File format: nonce (12) || ciphertext+tag
        let path = self.segment_path(index);
        let mut file_data = Vec::with_capacity(NONCE_LEN + in_out.len());
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&in_out);

        fs::write(&path, &file_data)?;

        info!(index, path = ?path, "segment written (encrypted)");
        Ok(())
    }

    /// Read and decrypt a segment from disk.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O, decryption failure, or tampering.
    pub fn read_segment(
        &self,
        index: u64,
        key: &[u8; KEY_LEN],
    ) -> Result<Vec<u8>, StoreError> {
        let path = self.segment_path(index);
        let file_data = fs::read(&path)?;

        if file_data.len() < NONCE_LEN + TAG_LEN {
            return Err(StoreError::FileTooShort);
        }

        let (nonce_bytes, ciphertext_and_tag) = file_data.split_at(NONCE_LEN);

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce_bytes);

        let aad = Aad::from(index.to_le_bytes());

        let unbound_key =
            UnboundKey::new(&AES_256_GCM, key).map_err(|_| StoreError::DecryptFailed)?;
        let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(Some(nonce_arr)));

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = opening_key
            .open_in_place(aad, &mut in_out)
            .map_err(|_| StoreError::DecryptFailed)?;

        Ok(plaintext.to_vec())
    }

    /// Check whether a segment file exists on disk.
    #[must_use]
    pub fn segment_exists(&self, index: u64) -> bool {
        self.segment_path(index).exists()
    }

    /// Save the chain state for later resumption.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] on write failure.
    pub fn save_chain_state(&self, hash: &SegmentHash, next_index: u64) -> Result<(), StoreError> {
        let state = ChainState {
            last_hash: hash.to_hex(),
            next_index,
        };
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| StoreError::ChainStateCorrupt(e.to_string()))?;
        let path = self.base_dir.join("chain.json");
        fs::write(&path, json)?;
        info!(next_index, "chain state saved");
        Ok(())
    }

    /// Load the chain state from disk.
    ///
    /// Returns `None` if the chain state file does not exist (fresh start).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the file exists but is corrupted.
    pub fn load_chain_state(&self) -> Result<Option<(SegmentHash, u64)>, StoreError> {
        let path = self.base_dir.join("chain.json");
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path)?;
        let state: ChainState = serde_json::from_str(&json)
            .map_err(|e| StoreError::ChainStateCorrupt(e.to_string()))?;

        let hash = SegmentHash::from_hex(&state.last_hash)
            .map_err(|e| StoreError::ChainStateCorrupt(e.to_string()))?;

        Ok(Some((hash, state.next_index)))
    }

    /// Returns the file path for a segment by index.
    fn segment_path(&self, index: u64) -> PathBuf {
        self.base_dir.join(format!("{index:012}.seg"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_key() -> [u8; KEY_LEN] {
        // Deterministic test key — NOT for production use.
        let mut key = [0u8; KEY_LEN];
        #[allow(clippy::cast_possible_truncation)] // index is always < 32
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        key
    }

    fn make_store() -> (SegmentStore, TempDir) {
        let tmp = TempDir::new().expect("temp dir");
        let store = SegmentStore::new(tmp.path()).expect("store");
        (store, tmp)
    }

    // ---- Encrypt/decrypt roundtrip ------------------------------------------

    #[test]
    fn test_write_read_roundtrip() {
        let (store, _tmp) = make_store();
        let key = test_key();
        let data = b"VGLF segment data for testing";

        store.write_segment(0, data, &key).expect("write");
        let recovered = store.read_segment(0, &key).expect("read");

        assert_eq!(recovered, data, "decrypted data must match original");
    }

    #[test]
    fn test_multiple_segments() {
        let (store, _tmp) = make_store();
        let key = test_key();

        for i in 0..5_u64 {
            let data = format!("segment {i} data");
            store.write_segment(i, data.as_bytes(), &key).expect("write");
        }

        for i in 0..5_u64 {
            let expected = format!("segment {i} data");
            let recovered = store.read_segment(i, &key).expect("read");
            assert_eq!(recovered, expected.as_bytes());
        }
    }

    // ---- Wrong key -----------------------------------------------------------

    #[test]
    fn test_wrong_key_fails() {
        let (store, _tmp) = make_store();
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0xFF; // flip one byte

        store.write_segment(0, b"secret data", &key1).expect("write");
        let result = store.read_segment(0, &key2);

        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    // ---- Wrong index (AAD mismatch) -----------------------------------------

    #[test]
    fn test_wrong_index_fails() {
        let (store, _tmp) = make_store();
        let key = test_key();

        store.write_segment(0, b"data", &key).expect("write");

        // Read with the wrong index — AAD mismatch should cause decryption failure.
        // We need to manually read the file and try to decrypt with wrong AAD.
        // Since read_segment uses the provided index for AAD, trying to read
        // segment 0's file as segment 1 should fail.
        let path_0 = store.base_dir.join("000000000000.seg");
        let path_1 = store.base_dir.join("000000000001.seg");
        fs::copy(&path_0, &path_1).expect("copy");

        let result = store.read_segment(1, &key);
        assert!(
            result.is_err(),
            "decryption with wrong segment index (AAD) must fail"
        );
    }

    // ---- Tampered ciphertext ------------------------------------------------

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (store, _tmp) = make_store();
        let key = test_key();

        store.write_segment(0, b"original", &key).expect("write");

        // Tamper with the encrypted file.
        let path = store.segment_path(0);
        let mut data = fs::read(&path).expect("read file");
        if data.len() > NONCE_LEN + 5 {
            data[NONCE_LEN + 3] ^= 0xFF; // flip a byte in the ciphertext
        }
        fs::write(&path, &data).expect("write tampered");

        let result = store.read_segment(0, &key);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }

    // ---- File too short -----------------------------------------------------

    #[test]
    fn test_file_too_short() {
        let (store, _tmp) = make_store();
        let key = test_key();

        let path = store.segment_path(0);
        fs::write(&path, [0u8; 5]).expect("write short file");

        let result = store.read_segment(0, &key);
        assert!(result.is_err());
    }

    // ---- Segment existence --------------------------------------------------

    #[test]
    fn test_segment_exists() {
        let (store, _tmp) = make_store();
        let key = test_key();

        assert!(!store.segment_exists(0));
        store.write_segment(0, b"data", &key).expect("write");
        assert!(store.segment_exists(0));
        assert!(!store.segment_exists(1));
    }

    // ---- Chain state persistence --------------------------------------------

    #[test]
    fn test_chain_state_roundtrip() {
        let (store, _tmp) = make_store();
        let hash = SegmentHash([0xAB; 32]);

        store.save_chain_state(&hash, 42).expect("save");
        let loaded = store.load_chain_state().expect("load");

        let (loaded_hash, loaded_index) = loaded.expect("state should exist");
        assert_eq!(loaded_hash, hash);
        assert_eq!(loaded_index, 42);
    }

    #[test]
    fn test_chain_state_none_on_fresh() {
        let (store, _tmp) = make_store();
        let loaded = store.load_chain_state().expect("load");
        assert!(loaded.is_none(), "fresh store should have no chain state");
    }

    // ---- Empty segment ------------------------------------------------------

    #[test]
    fn test_empty_segment_roundtrip() {
        let (store, _tmp) = make_store();
        let key = test_key();

        store.write_segment(0, b"", &key).expect("write empty");
        let recovered = store.read_segment(0, &key).expect("read empty");
        assert!(recovered.is_empty());
    }

    // ---- Large segment ------------------------------------------------------

    #[test]
    fn test_large_segment_roundtrip() {
        let (store, _tmp) = make_store();
        let key = test_key();
        let data = vec![0xCDu8; 256 * 1024]; // 256 KiB

        store.write_segment(0, &data, &key).expect("write large");
        let recovered = store.read_segment(0, &key).expect("read large");
        assert_eq!(recovered, data);
    }
}
