# NIST Post-Quantum Cryptography Test Vectors

KAT (Known Answer Test) vectors are **required** before any commit touching
`spinal-cord/src/crypto/`. CI blocks merges if vectors are missing.

## Download

From the NIST PQC project: https://csrc.nist.gov/projects/post-quantum-cryptography

### ML-KEM-768 (FIPS 203)

```bash
# Download: kat_kem.tar.gz from NIST PQC Additional Files
curl -O https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/kat_kem.tar.gz
tar xf kat_kem.tar.gz
cp PQCkemKAT_2400.rsp tests/pqc-vectors/mlkem768/
```

Expected file: `tests/pqc-vectors/mlkem768/PQCkemKAT_2400.rsp`
Entry format:
```
count = 0
seed  = <64 hex bytes>
pk    = <1184 hex bytes>
sk    = <2400 hex bytes>
ct    = <1088 hex bytes>
ss    = <32 hex bytes>
```

### ML-DSA-65 (FIPS 204)

```bash
# Download from NIST PQC Additional Files
cp PQCsignKAT_4896.rsp tests/pqc-vectors/mldsa65/
```

Expected file: `tests/pqc-vectors/mldsa65/PQCsignKAT_4896.rsp`

## Integration in test suite

```rust
// tests/pqc_vectors.rs
const MLKEM_KAT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/pqc-vectors/mlkem768/PQCkemKAT_2400.rsp"
);

#[test]
fn ml_kem_768_nist_kat() {
    if !std::path::Path::new(MLKEM_KAT).exists() {
        panic!("NIST KAT vectors missing — see tests/pqc-vectors/README.md");
    }
    // ... parse and verify each entry
}
```

## CI gate

```bash
test -f tests/pqc-vectors/mlkem768/PQCkemKAT_2400.rsp || \
  { echo "MISSING: ML-KEM-768 KAT vectors"; exit 1; }
test -f tests/pqc-vectors/mldsa65/PQCsignKAT_4896.rsp  || \
  { echo "MISSING: ML-DSA-65 KAT vectors";  exit 1; }
```
