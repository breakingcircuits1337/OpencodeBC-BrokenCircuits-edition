"""
VGLF Cortex Engine — IPC Client (Rust Spinal Cord Interface)

Sends signed rule bundles to the Rust Spinal Cord via Unix domain socket.

Security invariants enforced here (Invariant #1, RT-C01):
- Rule updates ALWAYS go through the Unix socket, NEVER via subprocess/exec/eval
- The socket path is not constructed from untrusted data
- No shell=True, no Popen, no os.system — ever
- Timeout on the socket prevents indefinite blocking
- Only "APPLIED" ACK is treated as success; anything else is a failure

Signing note:
- TODO: MUST be replaced with ML-DSA-65 signature from pqc-keymgmt before production
  The stub below inserts a placeholder signature field. The Rust IPC handler
  currently accepts unsigned bundles in development mode only. Production builds
  must have the pqc-keymgmt crate integrated and will REJECT unsigned bundles.
"""

from __future__ import annotations

import json
import logging
import socket as sock
import time
from typing import Any

logger = logging.getLogger(__name__)

# ACK string the Rust handler sends on successful rule application.
_APPLIED_ACK: str = "APPLIED"

# Connection and send/receive timeout in seconds.
# Must be short enough to not stall the analysis loop, but long enough
# for the Rust handler to process the rule bundle and respond.
_SOCKET_TIMEOUT_SECONDS: float = 5.0

# Maximum ACK response size we will read. We only expect "APPLIED" or "REJECTED".
_MAX_ACK_BYTES: int = 64


def _build_rule_bundle(
    ip: str,
    action: str,
    reason: str,
    decision_source: str = "cortex-llm",
) -> dict[str, Any]:
    """
    Construct a SignedRuleBundle dict ready for JSON serialisation.

    The 'signature' field is currently a stub.

    TODO: MUST be replaced with ML-DSA-65 signature from pqc-keymgmt before
    production deployment. The pqc-keymgmt crate will sign the canonical JSON
    representation of the rule payload using the operator's ML-DSA-65 private key
    (stored in TPM 2.0 or Vault transit — never on disk). The Rust IPC handler
    must verify this signature before applying any rule. Until that integration
    is complete, the Rust handler operates in development mode only and MUST NOT
    be deployed to production.

    Args:
        ip:              Validated canonical IP string (already checked by validator).
        action:          "BLOCK" or "ALLOW".
        reason:          Human-readable reason string (logged by Rust, not executed).
        decision_source: Identifies which subsystem made the decision.

    Returns:
        Dict suitable for json.dumps() and transmission over the Unix socket.
    """
    return {
        "version": 1,
        "timestamp_utc": int(time.time()),
        "payload": {
            "ip": ip,
            "action": action,
            "reason": reason,
            "decision_source": decision_source,
        },
        # STUB: Replace with real ML-DSA-65 signature bytes (base64-encoded) from pqc-keymgmt.
        # TODO: MUST be replaced with ML-DSA-65 signature from pqc-keymgmt before production.
        "signature": {
            "algorithm": "ML-DSA-65",
            "value": "STUB_NOT_SIGNED_DO_NOT_DEPLOY_TO_PRODUCTION",
            "key_id": "STUB",
        },
    }


def push_rule(
    rule_payload: dict[str, Any],
    socket_path: str = "/var/run/vglf/rules.sock",
) -> bool:
    """
    Send a rule bundle to the Rust Spinal Cord via Unix domain socket.

    SECURITY: This is the ONLY permitted mechanism for pushing rules from the
    Python Cortex to the Rust Spinal Cord. subprocess, exec, os.system, and
    eval are NEVER used (Invariant #1 / RT-C01).

    The socket path comes from CortexConfig and is never constructed from
    LLM output or untrusted data.

    Args:
        rule_payload: Dict containing ip, action, reason (pre-validated by caller).
                      Must NOT be constructed directly from raw LLM output —
                      the caller (analyzer.py) is responsible for validation.
        socket_path:  Path to the Rust IPC Unix socket.

    Returns:
        True if the Rust handler responded with "APPLIED".
        False on any error (connection failure, timeout, wrong ACK, etc.).
    """
    ip: str = str(rule_payload.get("ip", "<unknown>"))
    action: str = str(rule_payload.get("action", "<unknown>"))

    bundle = _build_rule_bundle(
        ip=ip,
        action=action,
        reason=str(rule_payload.get("reason", "")),
        decision_source=str(rule_payload.get("decision_source", "cortex-llm")),
    )

    try:
        # AF_UNIX + SOCK_STREAM: reliable, ordered, local-only.
        # No network exposure — the socket file is in /var/run/vglf/ which is
        # only accessible to the vglf system user.
        with sock.socket(sock.AF_UNIX, sock.SOCK_STREAM) as s:
            s.settimeout(_SOCKET_TIMEOUT_SECONDS)
            s.connect(socket_path)

            payload_bytes = (json.dumps(bundle) + "\n").encode("utf-8")
            s.sendall(payload_bytes)

            ack_raw = s.recv(_MAX_ACK_BYTES)
            ack = ack_raw.decode("utf-8", errors="replace").strip()

            if ack == _APPLIED_ACK:
                logger.info("Rule APPLIED by Rust handler: action=%s ip=%s", action, ip)
                return True
            else:
                # Log the unexpected ACK safely (no raw injection into log format string).
                safe_ack = ack[:32].replace("\n", "\\n").replace("\r", "\\r")
                logger.error(
                    "Rust handler returned unexpected ACK %r for action=%s ip=%s — rule NOT applied",
                    safe_ack,
                    action,
                    ip,
                )
                return False

    except FileNotFoundError:
        logger.error(
            "IPC socket not found at %r — is the Rust Spinal Cord running?",
            socket_path,
        )
        return False
    except ConnectionRefusedError:
        logger.error("IPC socket connection refused at %r", socket_path)
        return False
    except TimeoutError:
        logger.error("IPC socket timed out after %.1fs waiting for ACK", _SOCKET_TIMEOUT_SECONDS)
        return False
    except OSError as exc:
        logger.error("IPC socket OS error: %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001 — broad catch: never propagate IPC errors to caller
        logger.error("Unexpected IPC error: %s", exc)
        return False
