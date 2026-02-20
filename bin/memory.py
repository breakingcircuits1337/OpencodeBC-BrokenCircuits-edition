#!/usr/bin/env python3
"""
Memory Loader Function
Reads all memory files in order: LONG → MEDIUM → SHORT
Usage: python /home/bc/bin/memory.py
"""

import os
from pathlib import Path

MEMORY_DIR = Path("/home/bc")
FILES = {
    "LONG-TERM": MEMORY_DIR / "CLAUDE.md",
    "SOUL": MEMORY_DIR / "SOUL.md",
    "USER": MEMORY_DIR / "USER.md",
    "TOOLS": MEMORY_DIR / "TOOLS.md",
    "AGENTS": MEMORY_DIR / "AGENTS.md",
    "MEDIUM-TERM": MEMORY_DIR / "MEDIUM_TERM.md",
    "SHORT-TERM": MEMORY_DIR / "SHORT_TERM.md",
}

def load_memory():
    """Load all memory files and return as dict."""
    memory = {}
    for name, path in FILES.items():
        if path.exists():
            memory[name] = path.read_text()
        else:
            memory[name] = f"<!-- {name} file not found: {path} -->"
    return memory

def print_memory():
    """Print all memory files in hierarchical order."""
    memory = load_memory()
    
    print("=" * 60)
    print("MEMORY LOADED")
    print("=" * 60)
    
    for name, content in memory.items():
        print(f"\n{'='*20} {name} {'='*20}")
        print(content)
        print()

if __name__ == "__main__":
    print_memory()
