//! SHA3-256 Merkle hash chain for log segment integrity.
//!
//! # Integrity model
//!
//! Each log segment's hash is computed as:
//!
//! ```text
//! segment_hash = SHA3-256( prev_hash || segment_index || segment_data )
//! ```
//!
//! This creates a hash chain where:
//! - Modifying any segment invalidates all subsequent hashes.
//! - Silently deleting a segment breaks the chain at the deletion point.
//! - Reordering segments is detectable because the index is bound into the hash.
//!
//! The chain root (genesis) uses `[0u8; 32]` as the `prev_hash`.
//!
//! # Signing
//!
//! Each segment hash is signed with ML-DSA-65 via the [`DigitalSignature`] trait.
//! The signature covers the hash, not the raw data — this allows efficient
//! verification without re-reading potentially large segment payloads.

use sha3::{Digest, Sha3_256};

use spinal_cord::crypto::traits::{
    CryptoError, DigitalSignature, PublicKey, SecretKey, Signature,
};

/// The genesis (initial) previous hash — all zeros.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Segment hash
// ---------------------------------------------------------------------------

/// A 32-byte SHA3-256 hash of a log segment in the Merkle chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHash(pub [u8; 32]);

impl SegmentHash {
    /// Returns the hash as a hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a hex string into a segment hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not exactly 64 hex characters.
    pub fn from_hex(s: &str) -> Result<Self, MerkleError> {
        let bytes = hex::decode(s).map_err(|_| MerkleError::InvalidHashHex)?;
        if bytes.len() != 32 {
            return Err(MerkleError::InvalidHashHex);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// Signed segment
// ---------------------------------------------------------------------------

/// A signed segment entry in the hash chain.
#[derive(Debug, Clone)]
pub struct SignedSegment {
    /// Zero-based index of this segment in the chain.
    pub index: u64,

    /// SHA3-256 hash of this segment: `H(prev_hash || index || data)`.
    pub hash: SegmentHash,

    /// ML-DSA-65 signature over the segment hash bytes.
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// Merkle chain
// ---------------------------------------------------------------------------

/// A running SHA3-256 Merkle hash chain with ML-DSA-65 signatures.
///
/// This struct maintains the chain state (current hash and next index).
/// It does NOT store segments — that is the responsibility of the `store` module.
pub struct MerkleChain {
    /// Hash of the most recent segment (or `GENESIS_HASH` if empty).
    prev_hash: SegmentHash,

    /// Index to assign to the next segment.
    next_index: u64,
}

/// Errors produced by the Merkle chain module.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    #[error("invalid hex string for segment hash")]
    InvalidHashHex,

    #[error("segment index mismatch: expected {expected}, got {got}")]
    IndexMismatch { expected: u64, got: u64 },

    #[error("hash chain broken at segment {index}: expected {expected}, computed {computed}")]
    ChainBroken {
        index: u64,
        expected: String,
        computed: String,
    },

    #[error("signature verification failed at segment {index}: {source}")]
    SignatureInvalid {
        index: u64,
        source: CryptoError,
    },
}

impl MerkleChain {
    /// Create a new chain starting from the genesis hash.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prev_hash: SegmentHash(GENESIS_HASH),
            next_index: 0,
        }
    }

    /// Resume a chain from a known state.
    ///
    /// Used when restarting the service — load the last known hash and index
    /// from the segment store.
    #[must_use]
    pub fn resume(prev_hash: SegmentHash, next_index: u64) -> Self {
        Self {
            prev_hash,
            next_index,
        }
    }

    /// Returns the current head hash of the chain.
    #[must_use]
    pub fn head_hash(&self) -> &SegmentHash {
        &self.prev_hash
    }

    /// Returns the index that will be assigned to the next segment.
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Append a new segment to the chain.
    ///
    /// Computes the segment hash, signs it, advances the chain state,
    /// and returns the signed segment entry.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    ///
    /// # Panics
    ///
    /// Panics if the segment index overflows `u64::MAX` (unreachable in
    /// practice — would require appending 2^64 segments).
    pub fn append(
        &mut self,
        data: &[u8],
        sk: &SecretKey,
        dsa: &dyn DigitalSignature,
    ) -> Result<SignedSegment, CryptoError> {
        let index = self.next_index;
        let hash = compute_segment_hash(&self.prev_hash, index, data);

        // Sign the hash bytes (not the raw data).
        let signature = dsa.sign(sk, &hash.0)?;

        let segment = SignedSegment {
            index,
            hash: hash.clone(),
            signature,
        };

        // Advance chain state.
        self.prev_hash = hash;
        self.next_index = index.checked_add(1).expect("segment index overflow");

        Ok(segment)
    }
}

impl Default for MerkleChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a sequence of signed segments forms a valid chain.
///
/// Checks:
/// 1. Segment indices are sequential starting from `start_index`.
/// 2. Each segment hash matches `SHA3-256(prev_hash || index || data)`.
/// 3. Each ML-DSA-65 signature over the hash is valid.
///
/// # Parameters
///
/// - `segments` — the signed segment entries in order.
/// - `data_slices` — the raw data for each segment (same length as `segments`).
/// - `start_prev_hash` — the hash of the segment before the first entry
///   (`GENESIS_HASH` for a chain starting at index 0).
/// - `start_index` — expected index of the first segment.
/// - `pk` — the ML-DSA-65 public key for signature verification.
/// - `dsa` — the digital signature scheme.
///
/// # Errors
///
/// Returns [`MerkleError`] on any integrity violation.
///
/// # Panics
///
/// Panics if `segments` and `data_slices` have different lengths.
pub fn verify_chain(
    segments: &[SignedSegment],
    data_slices: &[&[u8]],
    start_prev_hash: &SegmentHash,
    start_index: u64,
    pk: &PublicKey,
    dsa: &dyn DigitalSignature,
) -> Result<(), MerkleError> {
    assert_eq!(
        segments.len(),
        data_slices.len(),
        "segments and data_slices must have the same length"
    );

    let mut prev_hash = start_prev_hash.clone();
    let mut expected_index = start_index;

    for (seg, data) in segments.iter().zip(data_slices.iter()) {
        // Check index continuity.
        if seg.index != expected_index {
            return Err(MerkleError::IndexMismatch {
                expected: expected_index,
                got: seg.index,
            });
        }

        // Recompute the hash and compare.
        let computed = compute_segment_hash(&prev_hash, seg.index, data);
        if computed != seg.hash {
            return Err(MerkleError::ChainBroken {
                index: seg.index,
                expected: seg.hash.to_hex(),
                computed: computed.to_hex(),
            });
        }

        // Verify ML-DSA-65 signature over the hash.
        dsa.verify(pk, &seg.hash.0, &seg.signature)
            .map_err(|e| MerkleError::SignatureInvalid {
                index: seg.index,
                source: e,
            })?;

        prev_hash = seg.hash.clone();
        expected_index += 1;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a single segment hash.
///
/// `hash = SHA3-256( prev_hash || index_le_bytes || data )`
///
/// The index is encoded as little-endian u64 to ensure a canonical byte
/// representation that does not depend on architecture.
fn compute_segment_hash(prev: &SegmentHash, index: u64, data: &[u8]) -> SegmentHash {
    let mut hasher = Sha3_256::new();
    hasher.update(prev.0);
    hasher.update(index.to_le_bytes());
    hasher.update(data);
    let digest = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    SegmentHash(arr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use spinal_cord::crypto::dsa::MlDsa65;

    fn dsa_and_keys() -> (MlDsa65, PublicKey, SecretKey) {
        let dsa = MlDsa65;
        let (pk, sk) = dsa.generate_keypair().expect("keygen");
        (dsa, pk, sk)
    }

    // ---- SegmentHash --------------------------------------------------------

    #[test]
    fn test_segment_hash_hex_roundtrip() {
        let hash = SegmentHash([0xAB; 32]);
        let hex_str = hash.to_hex();
        let parsed = SegmentHash::from_hex(&hex_str).expect("parse hex");
        assert_eq!(parsed, hash);
    }

    #[test]
    fn test_segment_hash_invalid_hex() {
        assert!(SegmentHash::from_hex("not-valid-hex").is_err());
        assert!(SegmentHash::from_hex("aabb").is_err()); // too short
    }

    // ---- Chain construction -------------------------------------------------

    #[test]
    fn test_new_chain_starts_at_genesis() {
        let chain = MerkleChain::new();
        assert_eq!(chain.head_hash().0, GENESIS_HASH);
        assert_eq!(chain.next_index(), 0);
    }

    #[test]
    fn test_append_advances_chain() {
        let (dsa, _pk, sk) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let seg0 = chain.append(b"segment zero data", &sk, &dsa).expect("append 0");
        assert_eq!(seg0.index, 0);
        assert_ne!(seg0.hash.0, GENESIS_HASH);
        assert_eq!(chain.next_index(), 1);

        let seg1 = chain.append(b"segment one data", &sk, &dsa).expect("append 1");
        assert_eq!(seg1.index, 1);
        assert_ne!(seg1.hash, seg0.hash);
        assert_eq!(chain.next_index(), 2);
    }

    #[test]
    fn test_same_data_different_index_different_hash() {
        let (dsa, _pk, sk) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let seg0 = chain.append(b"same data", &sk, &dsa).expect("append 0");
        let seg1 = chain.append(b"same data", &sk, &dsa).expect("append 1");

        assert_ne!(
            seg0.hash, seg1.hash,
            "same data at different indices must produce different hashes"
        );
    }

    // ---- Chain verification -------------------------------------------------

    #[test]
    fn test_verify_valid_chain() {
        let (dsa, pk, sk) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let data_0 = b"first segment";
        let data_1 = b"second segment";
        let data_2 = b"third segment";

        let seg0 = chain.append(data_0, &sk, &dsa).expect("append 0");
        let seg1 = chain.append(data_1, &sk, &dsa).expect("append 1");
        let seg2 = chain.append(data_2, &sk, &dsa).expect("append 2");

        let segments = [seg0, seg1, seg2];
        let data_slices: Vec<&[u8]> = vec![data_0, data_1, data_2];
        let genesis = SegmentHash(GENESIS_HASH);

        verify_chain(&segments, &data_slices, &genesis, 0, &pk, &dsa)
            .expect("valid chain must verify");
    }

    #[test]
    fn test_verify_detects_tampered_data() {
        let (dsa, pk, sk) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let data_0 = b"original data";
        let seg0 = chain.append(data_0, &sk, &dsa).expect("append");

        // Tamper: verify with different data.
        let segments = [seg0];
        let data_slices: Vec<&[u8]> = vec![b"tampered data"];
        let genesis = SegmentHash(GENESIS_HASH);

        let result = verify_chain(&segments, &data_slices, &genesis, 0, &pk, &dsa);
        assert!(result.is_err(), "tampered data must break chain verification");
    }

    #[test]
    fn test_verify_detects_wrong_index() {
        let (dsa, pk, sk) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let data_0 = b"segment";
        let mut seg0 = chain.append(data_0, &sk, &dsa).expect("append");

        // Tamper: change the index.
        seg0.index = 42;

        let segments = [seg0];
        let data_slices: Vec<&[u8]> = vec![data_0];
        let genesis = SegmentHash(GENESIS_HASH);

        let result = verify_chain(&segments, &data_slices, &genesis, 0, &pk, &dsa);
        assert!(result.is_err(), "wrong index must be detected");
    }

    #[test]
    fn test_verify_detects_wrong_signature_key() {
        let (dsa, _pk1, sk1) = dsa_and_keys();
        let (_, pk2, _sk2) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let data_0 = b"signed with key 1";
        let seg0 = chain.append(data_0, &sk1, &dsa).expect("append");

        let segments = [seg0];
        let data_slices: Vec<&[u8]> = vec![data_0];
        let genesis = SegmentHash(GENESIS_HASH);

        // Verify with the wrong public key.
        let result = verify_chain(&segments, &data_slices, &genesis, 0, &pk2, &dsa);
        assert!(result.is_err(), "wrong public key must fail verification");
    }

    // ---- Resume -------------------------------------------------------------

    #[test]
    fn test_resume_chain() {
        let (dsa, pk, sk) = dsa_and_keys();
        let mut chain = MerkleChain::new();

        let data_0 = b"pre-restart";
        let seg0 = chain.append(data_0, &sk, &dsa).expect("append 0");

        // Simulate restart: resume from seg0's hash.
        let mut resumed = MerkleChain::resume(seg0.hash.clone(), 1);
        let data_1 = b"post-restart";
        let seg1 = resumed.append(data_1, &sk, &dsa).expect("append 1");

        // Verify the full chain.
        let segments = [seg0, seg1];
        let data_slices: Vec<&[u8]> = vec![data_0, data_1];
        let genesis = SegmentHash(GENESIS_HASH);

        verify_chain(&segments, &data_slices, &genesis, 0, &pk, &dsa)
            .expect("resumed chain must verify");
    }

    // ---- Empty chain --------------------------------------------------------

    #[test]
    fn test_verify_empty_chain() {
        let (dsa, pk, _sk) = dsa_and_keys();
        let genesis = SegmentHash(GENESIS_HASH);
        let empty: Vec<SignedSegment> = vec![];
        let empty_data: Vec<&[u8]> = vec![];

        verify_chain(&empty, &empty_data, &genesis, 0, &pk, &dsa)
            .expect("empty chain is trivially valid");
    }
}
