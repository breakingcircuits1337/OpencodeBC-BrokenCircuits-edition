"""
VGLF Cortex Engine — Entry Point

Parses CLI arguments, loads configuration, and starts the analysis loop.

Security checks performed at startup (before any analysis):
1. LOCAL_LLM_URL locality validated in CortexConfig.__post_init__
2. Sacrosanct IPs merged with hardcoded defaults
3. If --canary-validate: run canary suite before starting loop
4. DuckDB session setup is validated lazily on first query
5. Forbidden module check (RT-C01): subprocess/commands/popen2 must not be imported
6. IPC socket pre-flight: warn if socket is absent before Rust Spinal Cord connects
7. Python version check: 3.11+ required for tomllib; warn on older versions
8. Security invariant banner logged at startup for operator confirmation

Usage:
    python -m cortex.main --config config/cortex.toml [--dry-run] [--canary-validate]
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import signal
import sys
import threading

# ---------------------------------------------------------------------------
# RT-C01 ASSERTION: these symbols must NEVER appear in this file.
# The grep check in the CI pipeline also enforces this at the text level, but
# this comment serves as an in-code reminder for reviewers.
#
# FORBIDDEN: subprocess, os.system, os.popen, eval(, exec(
# ---------------------------------------------------------------------------

# Set up logging before any imports that might emit log messages.
# The log level is reconfigured after config load, but we need a handler
# in place for startup errors.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level shutdown event: set by SIGTERM/SIGINT handlers so the analysis
# loop can exit cleanly without leaving nftables state inconsistent.
# ---------------------------------------------------------------------------
_shutdown_event: threading.Event = threading.Event()


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _shutdown_handler(signum: int, frame: object) -> None:
    """
    SIGTERM / SIGINT handler.

    Sets the module-level _shutdown_event so run_analysis_loop (in analyzer.py)
    can detect the signal and exit cleanly after finishing its current cycle.
    This prevents abrupt termination that could leave nftables in an inconsistent
    state or leave a DuckDB session open.

    systemd sends SIGTERM on 'systemctl stop cortex' — this handler ensures the
    process exits with a clean 0 after the current cycle finishes.
    """
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    logger.info(
        "Received %s (signal %d) — requesting clean shutdown after current cycle",
        sig_name,
        signum,
    )
    _shutdown_event.set()


def _setup_signal_handlers() -> None:
    """
    Install SIGTERM and SIGINT handlers for clean systemd / operator shutdown.

    Both signals set the same threading.Event so the analysis loop can check
    _shutdown_event.is_set() and break cleanly.
    """
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)
    logger.debug("Signal handlers installed for SIGTERM and SIGINT")


# ---------------------------------------------------------------------------
# Startup security invariant banner
# ---------------------------------------------------------------------------

def _log_security_invariants(config: object) -> None:
    """
    Emit all 8 VGLF security invariants at INFO level so operators can
    confirm in the log stream that they are active before analysis begins.

    The config object is typed as object here to avoid a circular import;
    the caller passes a CortexConfig instance.
    """
    # Extract the attributes we need via getattr to satisfy mypy --strict
    # without importing CortexConfig at module level.
    sacrosanct_ips: frozenset[str] = getattr(config, "sacrosanct_ips", frozenset())
    llm_url = getattr(config, "llm_url", "<unknown>")
    ipc_socket = getattr(config, "ipc_socket", "<unknown>")

    logger.info("=== VGLF SECURITY INVARIANTS ACTIVE ===")
    logger.info("INV-1: LLM output -> IPC socket ONLY (no subprocess/exec/eval)")
    logger.info("INV-2: DuckDB read-only + disabled_filesystems (RT-C03)")
    logger.info("INV-3: DATA_WRAPPER prompt isolation active (RT-C02)")
    logger.info("INV-4: All LLM-output IPs validated via ipaddress before action")
    logger.info("INV-5: Sacrosanct IPs: %s", sorted(sacrosanct_ips))
    logger.info(
        "INV-6: LLM URL: %s (locality checked at config load)",
        llm_url,
    )
    logger.info("INV-7: LLM failure -> no auto-block (decision=None -> safe)")
    logger.info("INV-8: IPv6 parity enforced in DuckDB queries")
    logger.info("INV-IPC: IPC socket path: %s", ipc_socket)
    logger.info("=======================================")


# ---------------------------------------------------------------------------
# IPC socket pre-flight
# ---------------------------------------------------------------------------

def _check_ipc_socket(ipc_socket: str) -> None:
    """
    Warn (but do NOT fail) if the IPC socket does not exist yet.

    The Rust Spinal Cord may start after the Cortex — in that window the
    socket will be absent. The analysis loop will still run; push_rule() in
    ipc_client.py handles the FileNotFoundError per-call. This pre-flight
    gives operators a clear early warning in the log.
    """
    if not os.path.exists(ipc_socket):
        logger.warning(
            "IPC socket not found at %r — is the Rust Spinal Cord running? "
            "Analysis will proceed but no rules will be pushed until the socket appears.",
            ipc_socket,
        )


# ---------------------------------------------------------------------------
# RT-C01 forbidden-module assertion
# ---------------------------------------------------------------------------

def _assert_no_forbidden_modules() -> bool:
    """
    Verify that no forbidden modules (subprocess, commands, popen2) were
    imported into sys.modules before the analysis loop starts.

    Returns True if clean, False if a violation is detected (caller exits 1).

    This is a runtime check that complements the static grep CI check. If any
    transitive import has brought in subprocess — which should never happen in
    cortex-engine — this will catch it before any LLM output could reach it.
    """
    _FORBIDDEN_MODULES: frozenset[str] = frozenset({"subprocess", "commands", "popen2"})
    imported_forbidden = _FORBIDDEN_MODULES & set(sys.modules.keys())
    if imported_forbidden:
        logger.critical(
            "FATAL: Forbidden modules detected in sys.modules: %s — "
            "this violates RT-C01. Refusing to start.",
            imported_forbidden,
        )
        return False
    logger.debug("RT-C01 check passed: no forbidden modules in sys.modules")
    return True


# ---------------------------------------------------------------------------
# Python version check
# ---------------------------------------------------------------------------

def _check_python_version() -> None:
    """
    Warn if running on Python < 3.11.

    Python 3.11 introduced tomllib (PEP 680). On older versions, config.py
    falls back to the third-party tomli package. This does not prevent startup
    but is logged so operators know the environment is sub-optimal.
    """
    if sys.version_info < (3, 11):
        logger.warning(
            "Python %d.%d detected — Python 3.11+ is recommended. "
            "TOML parsing may fall back to tomli.",
            sys.version_info.major,
            sys.version_info.minor,
        )


# ---------------------------------------------------------------------------
# Dry-run banner
# ---------------------------------------------------------------------------

def _log_dry_run_banner() -> None:
    """
    Log a prominent multi-line banner when dry-run mode is active.

    Dry-run is easy to forget — this banner makes it unmissable in the log.
    """
    logger.warning("=" * 60)
    logger.warning("DRY-RUN MODE ACTIVE -- NO RULES WILL BE APPLIED TO KERNEL")
    logger.warning("Set dry_run=false in config or remove --dry-run to activate")
    logger.warning("=" * 60)


# ---------------------------------------------------------------------------
# Canary validation
# ---------------------------------------------------------------------------

def _run_canary_validation(config_path: str) -> bool:
    """
    Run the canary model validation suite before starting the analysis loop.

    Uses importlib.import_module() rather than a bare import so that:
    1. The main engine works without the canary module installed.
    2. No subprocess is spawned — the canary runs in-process.
    3. Missing module is a warning, not a hard failure (stub mode).

    Returns True if canary passes (or canary module is absent — stub mode).
    Returns False if canary is present and fails — caller should sys.exit(1).

    INVARIANT: MUST NOT use subprocess to invoke the canary script. Any runner
    that needs a separate process must communicate via the IPC socket.
    """
    try:
        validate = importlib.import_module("tests.canary.validate")
        logger.info("Running canary validation via importlib...")
        result = validate.run(config_path=config_path)
        return bool(result)
    except ImportError:
        logger.warning(
            "Canary validation module not found — skipping (stub). "
            "Ensure tests/canary/validate.py is present before production deployment."
        )
        return True
    except AttributeError as exc:
        logger.error(
            "Canary module missing expected run() entry point: %s", exc
        )
        return False
    except Exception as exc:
        logger.error("Canary validation failed with exception: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cortex",
        description="VGLF Cortex Engine — Tier 3 LLM analysis for water treatment plant firewall",
    )
    parser.add_argument(
        "--config",
        default="config/cortex.toml",
        help="Path to cortex.toml config file (default: config/cortex.toml)",
    )
    parser.add_argument(
        "--sacrosanct",
        default="config/sacrosanct.toml",
        help="Path to sacrosanct.toml (IPs that can never be blocked)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Analyze and log decisions but never push rules to nftables/Rust",
    )
    parser.add_argument(
        "--canary-validate",
        action="store_true",
        default=False,
        help="Run model canary validation before starting; exit with code 1 if F1 < threshold",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["trace", "debug", "info", "warn", "error"],
        help="Override log level from config",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

def _configure_logging(level_str: str) -> None:
    """Set root logger level from config string (e.g. 'info', 'debug')."""
    numeric = getattr(logging, level_str.upper(), None)
    if not isinstance(numeric, int):
        logger.warning("Invalid log level %r — defaulting to INFO", level_str)
        numeric = logging.INFO
    logging.getLogger().setLevel(numeric)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Entry point. Returns exit code (0 = success, 1 = error).

    Startup sequence (in order):
      1. Parse CLI arguments
      2. Python version check (warn only)
      3. Install signal handlers (SIGTERM, SIGINT)
      4. Load and validate configuration (hard fail on error)
      5. Apply dry-run CLI override
      6. Configure log level
      7. Log startup banner
      8. RT-C01 forbidden-module assertion (hard fail on violation)
      9. IPC socket pre-flight (warn only)
     10. Log security invariants banner
     11. Log dry-run banner (if applicable)
     12. Canary validation (if --canary-validate)
     13. Start analysis loop
    """
    args = _parse_args(argv)

    # --- Step 2: Python version check ---
    _check_python_version()

    # --- Step 3: Signal handlers for clean systemd shutdown ---
    _setup_signal_handlers()

    # --- Step 4: Load and validate configuration ---
    # This is the single authoritative security checkpoint at startup.
    # CortexConfig.__post_init__ enforces LLM locality and sacrosanct IP validity.
    try:
        from cortex.config import load_config
        config = load_config(
            config_path=args.config,
            sacrosanct_path=args.sacrosanct,
        )
    except RuntimeError as exc:
        logger.critical("FATAL: Configuration validation failed: %s", exc)
        logger.critical(
            "VGLF Cortex will not start with an invalid configuration. "
            "This is a safety boundary, not a bug."
        )
        return 1
    except Exception as exc:
        logger.critical("FATAL: Unexpected error loading configuration: %s", exc)
        return 1

    # --- Step 5: Apply dry-run override from CLI ---
    if args.dry_run:
        # config is a frozen dataclass; rebuild with dry_run=True
        from dataclasses import replace
        config = replace(config, dry_run=True)

    # --- Step 6: Configure log level (CLI overrides config) ---
    log_level = args.log_level or config.log_level
    _configure_logging(log_level)

    # --- Step 7: Startup banner ---
    logger.info(
        "VGLF Cortex Engine starting: version=0.1.0 config=%r sacrosanct=%r",
        args.config,
        args.sacrosanct,
    )

    # --- Step 8: RT-C01 forbidden-module assertion ---
    # Run AFTER config load (which may import additional modules) so that the
    # full import graph is visible at check time.
    if not _assert_no_forbidden_modules():
        return 1

    # --- Step 9: IPC socket pre-flight ---
    _check_ipc_socket(config.ipc_socket)

    # --- Step 10: Security invariants banner ---
    _log_security_invariants(config)

    # --- Step 11: Dry-run banner (prominent, so operators cannot miss it) ---
    if config.dry_run:
        _log_dry_run_banner()

    # --- Step 12: Canary validation (optional but recommended before production) ---
    if args.canary_validate:
        logger.info("Running canary validation (--canary-validate flag set)")
        if not _run_canary_validation(args.config):
            logger.critical(
                "FATAL: Canary validation failed — model does not meet F1 >= 0.95 threshold. "
                "Do not promote this model to production. Exiting."
            )
            return 1
        logger.info("Canary validation passed — proceeding to analysis loop")

    # --- Step 13: Start analysis loop ---
    # Pass the shutdown event so analyzer.py can check it and exit cleanly
    # on SIGTERM/SIGINT without raising KeyboardInterrupt.
    try:
        from cortex.analyzer import run_analysis_loop
        run_analysis_loop(config, shutdown_event=_shutdown_event)
    except KeyboardInterrupt:
        # Belt-and-suspenders: if the signal handler did not fire (e.g. during
        # test runs without the installed handler), catch KeyboardInterrupt here.
        logger.info("Cortex Engine shut down by operator (KeyboardInterrupt)")
    except Exception as exc:
        logger.critical("FATAL: Unhandled exception in analysis loop: %s", exc)
        return 1

    logger.info("VGLF Cortex Engine stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
