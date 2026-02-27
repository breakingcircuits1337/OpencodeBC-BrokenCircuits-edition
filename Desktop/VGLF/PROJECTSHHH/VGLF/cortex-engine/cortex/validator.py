"""
VGLF Cortex Engine — Deterministic Validator

Non-LLM gate that runs BEFORE any rule is pushed to the Rust IPC handler.
This is a belt-and-suspenders layer: the Rust IPC handler also enforces
sacrosanct IPs, but we enforce them here first so that the Rust layer
is never even presented with an invalid request.

Security invariants enforced here (Invariants #4, #5, #7):
- IP string validated with ipaddress.ip_address() before any action
- Sacrosanct IPs (loopback, link-local, config-listed) → always False
- decision=None → always False (never auto-block on LLM failure)
- decision != "BLOCK" → False (only explicit BLOCK decisions can block)
- No subprocess, exec, eval, or I/O of any kind in this module
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def validate_block_decision(
    ip_str: str,
    decision: Optional[str],
    sacrosanct: frozenset[str],
) -> bool:
    """
    Deterministic gate: returns True only if it is safe to block *ip_str*.

    This function is the authoritative Python-layer enforcement point for
    the sacrosanct IP invariant. It must be called before EVERY rule push.
    The Rust IPC handler provides a second independent enforcement layer.

    Args:
        ip_str:     Raw IP string from DuckDB query results. May be malformed
                    if an attacker has injected data into the log pipeline.
        decision:   LLM decision string. Must be exactly "BLOCK" to proceed.
                    None (LLM failure) → False by design (Invariant #7).
        sacrosanct: Frozenset of IP strings that can never be blocked.
                    Loaded from CortexConfig — always includes "127.0.0.1"
                    and "::1" regardless of config file contents.

    Returns:
        True if and only if ALL of the following hold:
            1. decision == "BLOCK" (not None, not "ALLOW")
            2. ip_str is a valid IPv4 or IPv6 address
            3. The address is not in the sacrosanct set
            4. The address is not loopback (redundant with sacrosanct but explicit)
            5. The address is not link-local (169.254.x.x / fe80::/10)

    Security note: this function intentionally does NOT raise exceptions.
    Any error condition returns False — in doubt, do not block.
    """
    # --- Gate 1: Only explicit BLOCK decisions proceed ---
    if decision != "BLOCK":
        if decision is None:
            logger.info(
                "validate_block_decision: LLM returned None (failure) for %r — not blocking "
                "(Invariant #7: never auto-block on model failure)",
                ip_str,
            )
        else:
            logger.debug(
                "validate_block_decision: decision=%r for %r — not BLOCK, skipping",
                decision,
                ip_str,
            )
        return False

    # --- Gate 2: Parse and validate the IP address ---
    # ipaddress.ip_address() rejects ANY non-IP string including shell metacharacters,
    # SQL injection attempts, hostnames, CIDR notation, and whitespace-padded strings
    # (after strip). This is the primary injection defence for Invariant #4.
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        logger.error(
            "validate_block_decision: invalid IP string %r — rejecting (possible injection attempt)",
            ip_str,
        )
        return False

    # Canonical string form (strips leading zeros, normalises IPv6) for set lookup.
    canonical = str(addr)

    # --- Gate 3: Sacrosanct set check (Invariant #5) ---
    if canonical in sacrosanct:
        logger.warning(
            "SACROSANCT IP rejected at Python validation layer: %s — "
            "this is a belt-and-suspenders check; Rust IPC also enforces this",
            canonical,
        )
        return False

    # --- Gate 4: Loopback check (belt-and-suspenders alongside sacrosanct) ---
    # 127.0.0.0/8 and ::1 are loopback. These should already be in sacrosanct,
    # but we check explicitly to guard against config file omissions.
    if addr.is_loopback:
        logger.warning(
            "Loopback address %s rejected at Python validation layer (not in sacrosanct set — "
            "check your sacrosanct.toml configuration)",
            canonical,
        )
        return False

    # --- Gate 5: Link-local check ---
    # 169.254.0.0/16 (IPv4) and fe80::/10 (IPv6) are link-local.
    # Blocking these would disrupt network management protocols (ARP, ND, DHCP).
    if addr.is_link_local:
        logger.warning(
            "Link-local address %s rejected — blocking link-local addresses "
            "would disrupt ARP/ND and management protocols",
            canonical,
        )
        return False

    logger.info("validate_block_decision: APPROVED block of %s", canonical)
    return True
