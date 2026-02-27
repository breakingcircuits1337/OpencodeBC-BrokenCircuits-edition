"""
VGLF Cortex Engine — LLM Client

Thin, hardened wrapper around an OpenAI-compatible local LLM client.

Security invariants enforced here:
- temperature=0.0 ALWAYS — not configurable by caller
- max_tokens=10 ALWAYS — limits model output surface
- Only "BLOCK" or "ALLOW" are valid responses; anything else → None
- Network/API errors → None (never auto-block on failure, Invariant #7)
- The caller (analyzer.py) is responsible for DATA_WRAPPER prompt construction
- This module NEVER constructs SQL, file paths, or system commands from LLM output
"""

from __future__ import annotations

import logging
from typing import Optional

import openai

logger = logging.getLogger(__name__)

# The only two valid decisions. Any other LLM output is treated as a failure.
_VALID_DECISIONS: frozenset[str] = frozenset({"BLOCK", "ALLOW"})

# Hard constants — NOT caller-configurable. These are security boundaries, not options.
_LLM_TEMPERATURE: float = 0.0
_LLM_MAX_TOKENS: int = 10


class LLMClient:
    """
    OpenAI-compatible client locked to the parameters required by VGLF security policy.

    The client is intentionally narrow: it accepts a prompt string and returns
    "BLOCK", "ALLOW", or None. It exposes no way to change temperature or max_tokens.
    These are compile-time constants, not runtime parameters.
    """

    def __init__(self, base_url: str, model: str) -> None:
        """
        Initialise the client.

        Args:
            base_url: OpenAI-compatible API base URL. Must already have been
                      validated as loopback/private by CortexConfig before this
                      object is constructed. This module does not re-validate —
                      single point of truth is config.py.
            model:    Model identifier string (e.g. "llama3.2").
        """
        self._model = model
        # api_key="ollama" is the conventional placeholder for local Ollama installs.
        # It is never sent to a cloud endpoint — config.py enforces locality.
        self._client = openai.OpenAI(base_url=base_url, api_key="ollama")
        logger.info("LLMClient initialised: base_url=%r model=%r", base_url, model)

    @property
    def model(self) -> str:
        """Return the configured model identifier."""
        return self._model

    def decide(self, prompt: str) -> Optional[str]:
        """
        Send *prompt* to the local LLM and return a firewall decision.

        Returns:
            "BLOCK" or "ALLOW" if the model returns a valid decision.
            None on any LLM error, timeout, or ambiguous response.

        Invariants enforced:
            - temperature is ALWAYS 0.0 (deterministic output)
            - max_tokens is ALWAYS 10 (minimise attack surface of output)
            - Any response other than "BLOCK"/"ALLOW" → None (not auto-block)
            - All exceptions are caught and logged; None is returned (Invariant #7)
        """
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                # SECURITY: these two parameters are HARD-CODED constants, not variables.
                # They are defined as module-level constants above and must never be
                # replaced with caller-supplied values. Temperature 0.0 ensures
                # deterministic, reproducible decisions. max_tokens=10 caps the
                # output surface so injection via long completions is impossible.
                temperature=_LLM_TEMPERATURE,
                max_tokens=_LLM_MAX_TOKENS,
            )
        except openai.APIConnectionError as exc:
            logger.error("LLM connection error (is Ollama running?): %s", exc)
            return None
        except openai.APITimeoutError as exc:
            logger.error("LLM request timed out: %s", exc)
            return None
        except openai.APIStatusError as exc:
            logger.error("LLM API error %s: %s", exc.status_code, exc.message)
            return None
        except Exception as exc:  # noqa: BLE001 — broad catch intentional; never raise to caller
            logger.error("Unexpected LLM error: %s", exc)
            return None

        try:
            raw: str = response.choices[0].message.content.strip().upper()
        except (AttributeError, IndexError) as exc:
            logger.error("Malformed LLM response structure: %s", exc)
            return None

        if raw not in _VALID_DECISIONS:
            # Log the unexpected output for forensics but do NOT act on it.
            # Truncate to 50 chars in the log to avoid log injection.
            safe_log = raw[:50].replace("\n", "\\n").replace("\r", "\\r")
            logger.warning(
                "LLM returned unexpected output (not BLOCK/ALLOW): %r — treating as None",
                safe_log,
            )
            return None

        logger.debug("LLM decision: %s", raw)
        return raw
