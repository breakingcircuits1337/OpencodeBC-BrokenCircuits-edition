# VGLF Model Directory

Every `.onnx` file in this directory **requires** both sidecar files before it will load.
The Rust `verify_and_load_model()` function hard-fails if either sidecar is missing or invalid.

## Required sidecars per model

| File | Purpose |
|---|---|
| `<model>.onnx` | The ONNX model weights |
| `<model>.sha256` | SHA-256 hash: `sha256:<hex>` |
| `<model>.mldsa65.sig` | ML-DSA-65 signature over the model bytes |

## Adding a new model

```bash
# 1. Compute hash
sha256sum reflex.onnx | awk '{print "sha256:" $1}' > reflex.sha256

# 2. Sign with ML-DSA-65 key (from pqc-keymgmt, key stored in TPM/Vault — never flat file)
vglf-sign --model reflex.onnx --out reflex.mldsa65.sig

# 3. Run canary validation (F1 must be >= 0.95)
python tests/canary/validate.py --model models/reflex.onnx --threshold 0.95

# 4. Only commit all three files together — never .onnx without sidecars
git add models/reflex.onnx models/reflex.sha256 models/reflex.mldsa65.sig
```

## CI enforcement

The CI pipeline blocks merge if any `.onnx` exists without both sidecars:
```bash
find models/ -name '*.onnx' | while read f; do
  base="${f%.onnx}"
  test -f "${base}.sha256"     || { echo "MISSING: ${base}.sha256";    exit 1; }
  test -f "${base}.mldsa65.sig" || { echo "MISSING: ${base}.mldsa65.sig"; exit 1; }
done
```
