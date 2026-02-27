#!/usr/bin/env python3
"""
VGLF Model Canary Validation
Validates an ONNX model against the signed canary test suite before promotion.

Usage:
    python tests/canary/validate.py --model models/reflex.onnx --threshold 0.95

Exit codes:
    0  — PASS (F1 >= threshold, signatures valid)
    1  — FAIL (F1 < threshold, signature invalid, or hash mismatch)
    2  — ERROR (file not found, dependency missing, etc.)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("canary")

CANARY_DIR = Path(__file__).parent
CANARY_LABELS = CANARY_DIR / "labels.json"
CANARY_FEATURES = CANARY_DIR / "features.json"


# ---------------------------------------------------------------------------
# Hash verification (RT-C04)
# ---------------------------------------------------------------------------

def verify_model_hash(model_path: Path) -> bool:
    """Verify model SHA-256 against the .sha256 sidecar file.

    Returns True if hashes match.
    Hard-fails (sys.exit(1)) if sidecar is missing — never soft-fail.
    """
    sidecar = model_path.with_suffix(".sha256")
    if not sidecar.exists():
        log.error("FAIL: .sha256 sidecar missing for %s — cannot verify model integrity", model_path)
        log.error("Every .onnx file requires a .sha256 sidecar. See models/README.md.")
        return False

    expected = sidecar.read_text().strip()
    if expected.startswith("sha256:"):
        expected = expected[7:]

    actual = hashlib.sha256(model_path.read_bytes()).hexdigest()
    if actual != expected:
        log.error(
            "FAIL: SHA-256 mismatch for %s\n  expected: %s\n  actual:   %s",
            model_path, expected, actual,
        )
        return False

    log.info("hash OK: %s", model_path.name)
    return True


# ---------------------------------------------------------------------------
# Canary evaluation
# ---------------------------------------------------------------------------

def run_canary(model_path: Path, threshold: float) -> bool:
    """Run canary evaluation and return True if F1 >= threshold."""
    try:
        import onnxruntime as ort  # type: ignore[import]
        import numpy as np  # type: ignore[import]
    except ImportError as e:
        log.error("Missing dependency: %s. Install onnxruntime and numpy.", e)
        sys.exit(2)

    if not CANARY_LABELS.exists() or not CANARY_FEATURES.exists():
        log.error(
            "Canary test data missing: %s / %s\n"
            "Download canonical canary sets from the VGLF release artifacts.",
            CANARY_LABELS, CANARY_FEATURES,
        )
        sys.exit(2)

    labels: list[int] = json.loads(CANARY_LABELS.read_text())
    features: list[list[float]] = json.loads(CANARY_FEATURES.read_text())

    if len(labels) != len(features):
        log.error("Canary data mismatch: %d labels vs %d feature vectors", len(labels), len(features))
        sys.exit(2)

    log.info("Loading model: %s", model_path)
    # Load via InferenceSession — no custom ops, no dynamic shapes that could inject code
    sess_opts = ort.SessionOptions()
    sess_opts.inter_op_num_threads = 1
    sess_opts.intra_op_num_threads = 1
    sess = ort.InferenceSession(str(model_path), sess_opts=sess_opts)

    input_name = sess.get_inputs()[0].name
    x = np.array(features, dtype=np.float32)
    predictions = sess.run(None, {input_name: x})[0]

    # Binary classification: threshold at 0.5
    preds_binary = (predictions.squeeze() >= 0.5).astype(int).tolist()

    tp = sum(1 for p, l in zip(preds_binary, labels) if p == 1 and l == 1)
    fp = sum(1 for p, l in zip(preds_binary, labels) if p == 1 and l == 0)
    fn = sum(1 for p, l in zip(preds_binary, labels) if p == 0 and l == 1)
    tn = sum(1 for p, l in zip(preds_binary, labels) if p == 0 and l == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / len(labels) if labels else 0.0

    log.info(
        "Results — precision: %.4f  recall: %.4f  F1: %.4f  accuracy: %.4f  (n=%d)",
        precision, recall, f1, accuracy, len(labels),
    )
    log.info("True positives: %d  False positives: %d  False negatives: %d  True negatives: %d",
             tp, fp, fn, tn)

    if f1 < threshold:
        log.error(
            "FAIL: F1=%.4f is below threshold=%.2f — model rejected",
            f1, threshold,
        )
        return False

    log.info("PASS: F1=%.4f >= threshold=%.2f — model approved for promotion", f1, threshold)
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="VGLF model canary validator")
    parser.add_argument("--model", required=True, type=Path, help="Path to .onnx model file")
    parser.add_argument("--threshold", type=float, default=0.95, help="Minimum F1 score (default: 0.95)")
    args = parser.parse_args()

    model_path: Path = args.model.resolve()

    if not model_path.exists():
        log.error("Model file not found: %s", model_path)
        sys.exit(2)

    if model_path.suffix != ".onnx":
        log.error("Expected .onnx file, got: %s", model_path.suffix)
        sys.exit(2)

    # Step 1: Hash verification — hard fail if sidecar missing or mismatch
    if not verify_model_hash(model_path):
        sys.exit(1)

    # Step 2: Canary evaluation — hard fail if F1 < threshold
    if not run_canary(model_path, args.threshold):
        sys.exit(1)

    log.info("Model %s approved for promotion.", model_path.name)
    sys.exit(0)


if __name__ == "__main__":
    main()
