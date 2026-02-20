# TOOLS.md - Local Notes

Skills define *how* tools work. This file is for *your* specifics — the stuff that's unique to your setup.

## TTS (Text-to-Speech)
- **Script:** `/home/bc/bin/speak`
- **Usage:** `/home/bc/bin/speak "text to speak"`
- **ALWAYS USE:** Speak every response via TTS after responding

## STT (Voice Input)
- **Script:** `/home/bc/bin/listen.py`
- **Usage:** `python /home/bc/bin/listen.py [duration_seconds]`
- Uses Azure Speech SDK

## SSH
- **hexstrike_key:** `~/.ssh/hexstrike_key` (GitHub authorized)

## AI Models
- **mistral.py:** Call Mistral 3 Large via Azure
- **kimi.py:** Call Kimi K2 Thinking via Azure
- **Usage:** `python models/mistral.py "prompt"`

## Memory System
- **Script:** `/home/bc/bin/memory.py`
- Loads: CLAUDE.md → MEDIUM_TERM.md → SHORT_TERM.md

---

Add whatever helps you do your job. This is your cheat sheet.
