# /validate-model [path] — Run Canary Suite Before Model Promotion

Validates an ONNX model against the signed canary test suite before it can be promoted to production.

## Steps:
1. Verify model SHA-256 matches `.sha256` sidecar
2. Verify ML-DSA-65 signature on model file
3. Run canary validation: `python tests/canary/validate.py --model $path --threshold 0.95`
4. Report F1 score, precision, recall
5. If F1 < 0.95: REJECT — do not promote, flag for investigation
6. If PASS: output signed promotion token

## Never skip this before deploying a new model to production.
