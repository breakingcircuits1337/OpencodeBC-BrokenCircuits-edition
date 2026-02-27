"""
VGLF Cortex Engine — Configuration

Loads configuration from TOML. Enforces LOCAL_LLM_URL locality check at load time
so the process hard-fails before touching any LLM endpoint if misconfigured.

Security invariants:
- LOCAL_LLM_URL must resolve to loopback or RFC-1918 range (Invariant #6)
- VGLF_ALLOW_CLOUD_LLM=true env var required to override (operator consent)
- Sacrosanct IPs merged from config file + hardcoded defaults (Invariant #5)
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import logging

logger = logging.getLogger(__name__)

# Hardcoded defaults that are ALWAYS in the sacrosanct set regardless of config.
# These cannot be overridden by any config file — they are a compile-time invariant.
_HARDCODED_SACROSANCT: frozenset[str] = frozenset({
    "127.0.0.1",
    "::1",
})

# Default local LLM URL — Ollama on localhost
_DEFAULT_LLM_URL = "http://localhost:11434/v1"


def _validate_llm_url(url: str) -> None:
    """
    Verify that *url* points to a loopback or private-range host.

    Raises RuntimeError if the host resolves outside loopback/private and
    VGLF_ALLOW_CLOUD_LLM is not set to 'true'.

    This is a hard gate: if we cannot confirm locality, we refuse to start.
    Never soft-fail silently — fail loudly so operators notice.
    """
    parsed = urllib.parse.urlparse(url)
    hostname: str = parsed.hostname or ""

    allow_cloud = os.environ.get("VGLF_ALLOW_CLOUD_LLM", "false").strip().lower() == "true"

    try:
        addr = ipaddress.ip_address(hostname)
        if not (addr.is_loopback or addr.is_private):
            if not allow_cloud:
                raise RuntimeError(
                    f"LOCAL_LLM_URL {url!r} resolves to a non-private address {addr!r}. "
                    "Set VGLF_ALLOW_CLOUD_LLM=true to override (requires explicit operator "
                    "consent). This is a hard security boundary — no soft override exists."
                )
            logger.warning(
                "SECURITY WARNING: Using cloud LLM endpoint %r. "
                "Operator override VGLF_ALLOW_CLOUD_LLM=true is active.",
                url,
            )
    except ValueError:
        # hostname is a name (e.g. "localhost"), not a bare IP — resolve it.
        if hostname not in ("localhost", ""):
            try:
                addrinfo = socket.getaddrinfo(hostname, None)
                resolved_str = addrinfo[0][4][0]
                resolved_addr = ipaddress.ip_address(resolved_str)
                if not (resolved_addr.is_loopback or resolved_addr.is_private):
                    if not allow_cloud:
                        raise RuntimeError(
                            f"LLM hostname {hostname!r} resolves to {resolved_addr!r}, "
                            "which is not loopback or private. "
                            "Set VGLF_ALLOW_CLOUD_LLM=true to override (requires operator consent)."
                        )
                    logger.warning(
                        "SECURITY WARNING: LLM hostname %r resolves to non-private %r. "
                        "Operator override is active.",
                        hostname,
                        resolved_addr,
                    )
            except socket.gaierror as exc:
                # Cannot resolve — refuse to proceed. Unknown locality = untrusted.
                raise RuntimeError(
                    f"Cannot resolve LLM hostname {hostname!r}: {exc}. "
                    "VGLF will not start with an unresolvable LLM endpoint."
                ) from exc
        # "localhost" and "" are implicitly trusted — they resolve to loopback by definition.


@dataclass
class CortexConfig:
    """
    Immutable runtime configuration for the Cortex engine.

    All fields are validated at construction time. Constructing this object is
    the single authoritative point for security envelope checks — if it succeeds,
    the rest of the engine can assume invariants hold.
    """

    llm_url: str = _DEFAULT_LLM_URL
    llm_model: str = "llama3.2"
    ipc_socket: str = "/var/run/vglf/rules.sock"
    vortex_glob: str = "/var/lib/vglf/logs/*.parquet"
    suspicious_threshold: int = 100
    sacrosanct_ips: frozenset[str] = field(default_factory=lambda: _HARDCODED_SACROSANCT)
    dry_run: bool = False
    log_level: str = "info"

    def __post_init__(self) -> None:
        # --- LLM URL locality enforcement (Invariant #6) ---
        _validate_llm_url(self.llm_url)

        # --- Sacrosanct set must always include hardcoded defaults (Invariant #5) ---
        # Merge with hardcoded defaults — config file cannot remove loopback addresses.
        merged = frozenset(self.sacrosanct_ips) | _HARDCODED_SACROSANCT
        self.sacrosanct_ips = merged

        # --- Validate sacrosanct IPs are all parseable (fail loud on misconfiguration) ---
        for ip_str in self.sacrosanct_ips:
            try:
                ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise ValueError(
                    f"Sacrosanct IP {ip_str!r} is not a valid IP address: {exc}"
                ) from exc

        if self.suspicious_threshold < 1:
            raise ValueError(
                f"suspicious_threshold must be >= 1, got {self.suspicious_threshold}"
            )

        logger.info(
            "CortexConfig loaded: llm_url=%r model=%r ipc_socket=%r "
            "threshold=%d sacrosanct_count=%d dry_run=%s",
            self.llm_url,
            self.llm_model,
            self.ipc_socket,
            self.suspicious_threshold,
            len(self.sacrosanct_ips),
            self.dry_run,
        )


def _load_sacrosanct_toml(path: Path) -> set[str]:
    """
    Load sacrosanct IPs from a TOML file.

    Supports two formats:

    Format 1 (Cortex-native, preferred):
        [sacrosanct]
        ips = ["192.168.1.1", "10.0.0.1"]

    Format 2 (VGLF project legacy, [[networks]] with cidr entries):
        [[networks]]
        cidr = "10.0.1.1/32"
        description = "SCADA gateway"

    For Format 2, only /32 (IPv4) and /128 (IPv6) entries are loaded as sacrosanct
    single-host IPs. CIDR ranges wider than a single host are NOT supported at this
    layer — the Rust IPC handler handles range matching.

    Returns an empty set on any error — the hardcoded defaults always apply.
    Missing file is not an error at this level (caller decides).
    """
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning(
                "tomli not installed and Python < 3.11; cannot parse sacrosanct TOML. "
                "Hardcoded defaults only."
            )
            return set()

    try:
        with open(path, "rb") as f:
            data: dict[str, Any] = tomllib.load(f)

        result: set[str] = set()

        # --- Format 1: [sacrosanct] ips = [...] ---
        raw_ips: list[Any] = data.get("sacrosanct", {}).get("ips", [])
        for raw in raw_ips:
            if not isinstance(raw, str):
                logger.warning("Non-string entry in sacrosanct.toml ips list: %r — skipping", raw)
                continue
            try:
                ipaddress.ip_address(raw.strip())
                result.add(raw.strip())
            except ValueError:
                logger.error(
                    "Invalid IP %r in sacrosanct.toml ips list — skipping (will not be protected!)",
                    raw,
                )

        # --- Format 2: [[networks]] cidr = "x.x.x.x/32" ---
        # Only extract single-host CIDRs (/32 for IPv4, /128 for IPv6).
        # Wider ranges cannot be represented as single IPs at this layer.
        networks: list[Any] = data.get("networks", [])
        if isinstance(networks, list):
            for entry in networks:
                if not isinstance(entry, dict):
                    continue
                cidr_str = entry.get("cidr", "")
                if not isinstance(cidr_str, str) or not cidr_str:
                    continue
                try:
                    net = ipaddress.ip_network(cidr_str.strip(), strict=False)
                    # Only single-host networks are sacrosanct IPs at this layer
                    if net.num_addresses == 1:
                        host_ip = str(net.network_address)
                        result.add(host_ip)
                        logger.debug("Sacrosanct CIDR /32 or /128 loaded: %s → %s", cidr_str, host_ip)
                    else:
                        logger.info(
                            "Sacrosanct CIDR %r is a range (not /32 or /128) — "
                            "range matching is enforced by the Rust IPC handler, not Python Cortex. "
                            "Only the network address will be individually protected.",
                            cidr_str,
                        )
                        # Add the network address itself as a belt-and-suspenders measure
                        result.add(str(net.network_address))
                except ValueError:
                    logger.error(
                        "Invalid CIDR %r in sacrosanct.toml networks — skipping",
                        cidr_str,
                    )

        if result:
            logger.info("Loaded %d sacrosanct IPs from %s", len(result), path)
        return result

    except FileNotFoundError:
        logger.info("Sacrosanct TOML not found at %s — using hardcoded defaults only.", path)
        return set()
    except Exception as exc:
        logger.error(
            "Failed to parse sacrosanct TOML at %s: %s — using hardcoded defaults only.",
            path,
            exc,
        )
        return set()


def _load_main_toml(path: Path) -> dict[str, Any]:
    """
    Load a TOML config file. Returns empty dict on any error.
    All keys are optional — CortexConfig dataclass provides safe defaults.
    """
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning("tomli not installed and Python < 3.11; cannot parse config TOML.")
            return {}

    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        logger.warning("Config file not found at %s — using all defaults.", path)
        return {}
    except Exception as exc:
        raise RuntimeError(f"Failed to parse config file {path}: {exc}") from exc


def load_config(
    config_path: str = "config/cortex.toml",
    sacrosanct_path: str = "config/sacrosanct.toml",
) -> CortexConfig:
    """
    Load CortexConfig from TOML files.

    Sacrosanct IPs from sacrosanct_path are merged with hardcoded defaults.
    LLM URL locality is validated in CortexConfig.__post_init__.
    """
    raw = _load_main_toml(Path(config_path))
    sacrosanct_from_file = _load_sacrosanct_toml(Path(sacrosanct_path))

    # Layer: env overrides > config file > dataclass defaults
    llm_url = os.environ.get("LOCAL_LLM_URL", raw.get("llm_url", _DEFAULT_LLM_URL))
    llm_model = raw.get("llm_model", "llama3.2")
    ipc_socket = raw.get("ipc_socket", "/var/run/vglf/rules.sock")
    vortex_glob = raw.get("vortex_glob", "/var/lib/vglf/logs/*.parquet")
    threshold = int(raw.get("suspicious_threshold", 100))
    dry_run = bool(raw.get("dry_run", False)) or os.environ.get("VGLF_DRY_RUN", "false").lower() == "true"
    log_level = raw.get("log_level", "info")

    # Sacrosanct: file-loaded IPs are merged with hardcoded defaults inside __post_init__
    combined_sacrosanct: frozenset[str] = frozenset(sacrosanct_from_file)

    return CortexConfig(
        llm_url=llm_url,
        llm_model=llm_model,
        ipc_socket=ipc_socket,
        vortex_glob=vortex_glob,
        suspicious_threshold=threshold,
        sacrosanct_ips=combined_sacrosanct,
        dry_run=dry_run,
        log_level=log_level,
    )
