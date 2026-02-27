"""
VGLF Cortex Engine — Tier 3 Cognitive Analysis Engine
Protects water treatment plant infrastructure via LLM-assisted network analysis.

Security invariants enforced at this layer:
- LLM output NEVER reaches subprocess, exec, or eval
- DuckDB always in-memory with disabled_filesystems
- DATA_WRAPPER isolation on all LLM-analyzed payloads
- All IPs validated via ipaddress before any action
- Sacrosanct IPs can never be blocked
- LOCAL_LLM_URL defaults to localhost; cloud requires explicit flag
- LLM failure (None decision) never auto-blocks
- temperature=0.0 and max_tokens=10 on all block/allow calls
"""

__version__ = "0.1.0"
