"""
VGLF Cortex Engine — DuckDB Query Layer

Reads Vortex-compressed Parquet log files to find suspicious IPs.

Security invariants enforced here (Invariant #2, RT-C03):
- DuckDB always opened as in-memory (:memory:) session
- disabled_filesystems set BEFORE any data query — blocks LocalFileSystem and HTTPFileSystem
- ALL queries use parameterized form ONLY: con.execute(query, [params])
  NEVER f-strings, .format(), or string concatenation in SQL
- read_parquet() path comes from CortexConfig, not from user/LLM input
- Both IPv4 (src_ip) and IPv6 (src_ipv6) columns handled for parity (Invariant #8)
- No write operations — this module is query-only

DuckDB in-memory note (from CLAUDE.md):
  read_only=False is required for in-memory DuckDB sessions.
  The disabled_filesystems directive IS the read-only enforcement for Vortex files.
  NEVER substitute a file path for ":memory:" without also passing read_only=True.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import duckdb

logger = logging.getLogger(__name__)

# The query that finds suspicious IPs by packet count threshold.
# Parameterized with ? placeholders — never string-interpolated.
# Two variants: IPv4 and IPv6. They are run separately and results merged
# to maintain IPv6 parity (Invariant #8 from CLAUDE.md).
#
# Column names match the VGLF Vortex log schema:
#   src_ip     TEXT   — source IPv4 address (may be NULL for pure-IPv6 sessions)
#   src_ipv6   TEXT   — source IPv6 address (may be NULL for pure-IPv4 sessions)
#   timestamp  TIMESTAMP (or equivalent) — event timestamp
#   dst_port   INTEGER — destination port

_QUERY_SUSPICIOUS_IPV4 = """
SELECT
    src_ip              AS ip_addr,
    COUNT(*)            AS event_count,
    MAX(timestamp)      AS last_seen,
    LIST(DISTINCT dst_port) AS dst_ports
FROM read_parquet(?)
WHERE src_ip IS NOT NULL
  AND src_ip != ''
GROUP BY src_ip
HAVING COUNT(*) > ?
ORDER BY event_count DESC
"""

_QUERY_SUSPICIOUS_IPV6 = """
SELECT
    src_ipv6            AS ip_addr,
    COUNT(*)            AS event_count,
    MAX(timestamp)      AS last_seen,
    LIST(DISTINCT dst_port) AS dst_ports
FROM read_parquet(?)
WHERE src_ipv6 IS NOT NULL
  AND src_ipv6 != ''
GROUP BY src_ipv6
HAVING COUNT(*) > ?
ORDER BY event_count DESC
"""


def _setup_duckdb_session() -> Any:
    """
    Create a hardened in-memory DuckDB session with filesystem access disabled.

    SECURITY NOTE: read_only=False is intentional and required for in-memory sessions.
    DuckDB's read_only flag applies to persistent file databases; in-memory sessions
    cannot be opened read_only. The filesystem restriction below IS the read-only
    enforcement mechanism for the Vortex parquet files. The session has no write path
    to any persistent storage.

    The disabled_filesystems setting blocks:
      - LocalFileSystem: prevents arbitrary file reads via read_csv/read_json/etc.
      - HTTPFileSystem: prevents data exfiltration or SSRF via httpfs extension.

    This must be called before ANY data operation in the session.
    """
    # SECURITY: database=":memory:" is mandatory. Never replace with a file path
    # unless read_only=True is also set.
    con = duckdb.connect(database=":memory:", read_only=False)

    # SECURITY: This is the primary filesystem access control.
    # Must be executed before any query that touches parquet files.
    # read_parquet() uses the registered VFS, not LocalFileSystem directly,
    # so it remains available. This blocks dangerous file-reading functions
    # like read_csv('/etc/passwd') or duckdb_httpfs_fetch(...).
    con.execute("SET disabled_filesystems='LocalFileSystem,HTTPFileSystem'")

    return con


def get_suspicious_ips(
    vortex_glob: str,
    threshold: int,
) -> list[dict[str, Any]]:
    """
    Query Vortex Parquet log files for IPs exceeding the event count threshold.

    Runs two separate queries (IPv4 + IPv6) for full IPv6 parity and merges
    results. Deduplicates on canonical IP string.

    Args:
        vortex_glob: Glob pattern for Vortex Parquet files, e.g.
                     "/var/lib/vglf/logs/*.parquet". Comes from CortexConfig —
                     NOT from LLM output or user input.
        threshold:   Minimum event count to flag an IP as suspicious.
                     Parameterized into the query — never string-interpolated.

    Returns:
        List of dicts with keys: {src_ip, count, last_seen, dst_ports}
        Empty list on any error (fail safe — errors are logged).

    NEVER call this with values derived from LLM output. The vortex_glob and
    threshold come from CortexConfig, which is loaded from operator-controlled
    TOML files validated at startup.
    """
    con: Optional[Any] = None
    results: list[dict[str, Any]] = []

    try:
        con = _setup_duckdb_session()

        seen_ips: set[str] = set()

        for query_label, query in (
            ("IPv4", _QUERY_SUSPICIOUS_IPV4),
            ("IPv6", _QUERY_SUSPICIOUS_IPV6),
        ):
            try:
                # SECURITY: Both vortex_glob and threshold are query parameters,
                # not string-interpolated. This is the ONLY safe way to include
                # variable data in DuckDB queries.
                rows = con.execute(query, [vortex_glob, threshold]).fetchall()
            except duckdb.IOException as exc:
                # No parquet files matched the glob — not an error in normal operation.
                logger.debug("DuckDB %s query: no files matched or I/O error: %s", query_label, exc)
                continue
            except duckdb.Error as exc:
                logger.error("DuckDB %s query error: %s", query_label, exc)
                continue

            for row in rows:
                ip_addr, event_count, last_seen, dst_ports = row
                if ip_addr is None:
                    continue

                ip_str = str(ip_addr).strip()
                if not ip_str or ip_str in seen_ips:
                    continue

                seen_ips.add(ip_str)
                results.append({
                    "src_ip": ip_str,
                    "count": int(event_count) if event_count is not None else 0,
                    "last_seen": str(last_seen) if last_seen is not None else "",
                    "dst_ports": list(dst_ports) if dst_ports is not None else [],
                })

            logger.debug(
                "DuckDB %s query complete (total results so far: %d, threshold=%d)",
                query_label,
                len(results),
                threshold,
            )

        logger.info(
            "DuckDB query complete: %d total suspicious IPs found (threshold=%d, glob=%r)",
            len(results),
            threshold,
            vortex_glob,
        )

    except Exception as exc:  # noqa: BLE001 — never propagate DB errors to analysis loop
        logger.error("Unexpected error in get_suspicious_ips: %s", exc)
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:  # noqa: BLE001
                pass

    return results
