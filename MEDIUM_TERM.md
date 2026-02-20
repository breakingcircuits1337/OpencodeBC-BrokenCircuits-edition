# Medium-Term Memory (Cross-Session Context)

This file stores context that persists across sessions but isn't permanent - project progress, recent learnings, things to follow up on, and mid-term context.

---

## Last Updated: 2026-02-20

## Projects In Progress

- **Knowledge System MVP**: Lightweight RAG stack with Chroma + sentence-transformers
  - Todo: Install Chroma + sentence-transformers, create knowledge/ dir, build indexing script, add bc-query CLI
  - Architecture: Document chunking → Embed → Vector store → Query with sources

## Recent Learnings

- Memory function: Created ~/bin/memory.py to load memory files in order
- TTS always-on: Configured to speak every response via ~/bin/speak
- Voice Input: Created ~/bin/listen.py using Azure Speech SDK for STT
- Ollama Skill: Created ~/skills/ollama/ for free offline local LLM inference
- BC Plan: Created opencodeBC-MAIN/BC_PLAN.md with strategy to beat OpenCLAW and Claude Code
- System Tray: Added to desktop app (src-tauri/src/tray.rs)
- Magnitude: Created self-improvement skill with research, search, debate commands
- **Brainstorming (2026-02-20)**: Designed knowledge system with RAG stack (Chroma + embeddings) for deeper knowledge, research, learning, and Q&A

## Follow-ups

<!-- Things to follow up on from previous sessions -->

## Mid-Term Context

<!-- Context that spans multiple sessions but isn't permanent -->

---

## Update History

- **2026-02-20**: Created memory system with SHORT_TERM.md and MEDIUM_TERM.md alongside CLAUDE.md (long-term)
- **2026-02-20**: User emphasized actively using memory files during development
