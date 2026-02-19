# CLAUDE.md - User Context & Memory

This file stores persistent information about the user and their preferences for AI assistance.

---

## User Profile

- **Name**: User (bc)
- **Email (for OSINT tests)**: joebruce1313@gmail.com
- **Sock puppet identity**: joebruce1313 (used for obfuscating main identity)
  - Associated with: Hugging Face, GitHub (joe-bruce), Honda CRX forums
  - Interests: AI/ML, classic Honda cars (CRX)

---

## Preferences

### File Storage
- **Documents**: Save .md files to `~/Documents`
- **Images**: Save images to `~/Pictures`

### Editor
- **Preferred Editor**: VS Code
- **VS Code Version**: 1.109.4

### Programming Languages
- **Primary**: Python 3.12.3
- **Package Manager**: pip 24.0
- **Python venv**: `/home/bc/.venvs/base`
- **Installed Tools**: ipython, black, flake8, mypy, ruff

### JavaScript/Node.js
- **Node.js Version**: v24.13.0
- **npm Version**: 11.6.2
- **Global Tools**: typescript, eslint, prettier, yarn, pnpm

### VS Code Settings
- **Config Location**: `/home/bc/.config/Code/User/settings.json`
- **Default Python**: `/home/bc/.venvs/base/bin/python`
- **Linting**: flake8 enabled
- **Formatting**: black
- **Rulers**: 88, 120 columns

### Text-to-Speech
- **TTS Tool**: Google TTS (gTTS) - natural sounding female voice
- **Script**: `/home/bc/bin/speak`
- **Usage**: `/home/bc/bin/speak "text to speak"`
- **Packages**: gTTS, pygame (installed in venv)

### AI API Keys
- **Config File**: `/home/bc/.env`
- **Hugging Face**: User "breakingcircuits" (free image generation)
- **Replicate**: User "breakingcircuits1337" (FLUX and models)
- **Azure AI Foundry** (east2):
  - Mistral Large 3
  - Kimi-K2-Thinking

### GitHub
- **User**: breakingcircuits1337
- **SSH Key**: `~/.ssh/hexstrike_key` (authorized)
- **Tools**: xclip (clipboard access)
- **Repo**: OpencodeBC-BrokenCircuits-edition (public)

### Custom Models
- **Models Directory**: `/home/bc/models/`
- **mistral.py** - Call Mistral 3 Large via Azure
- **kimi.py** - Call Kimi K2 Thinking via Azure
- **Usage**: `python models/mistral.py "prompt"`

### Custom Skills Created
- **azure-llm-bridge** - Skill for calling Azure LLMs from CLI
  - Location: `/home/bc/skills/azure-llm-bridge/`
  - Package: `/home/bc/skills/azure-llm-bridge.skill`
  - Scripts: `mistral.py`, `kimi.py`
  - Provides easy CLI interface to Mistral 3 Large and Kimi K2 Thinking
- **azure-cli** - Skill for Azure resource management
  - Location: `/home/bc/skills/azure-cli/`
  - Package: `/home/bc/skills/azure-cli.skill`
  - Scripts: `az-login.sh`, `check-ai-foundry.sh`, `monitor-credits.sh`
  - Helps manage $4500 Azure credit budget and AI deployments

---

## Project Notes

### Digital Flora (2026-02-19)
- Created design philosophy "Digital Flora" - generative botanical patterns
- Generated artwork: `/home/bc/digital-flora.png`
- Philosophy document: `/home/bc/digital-flora-philosophy.md`

### Image Generation (2026-02-19)
- Generated first AI image: `/home/bc/test_image.png`
- Used Stable Diffusion XL via Hugging Face
- FLUX requires paid credits on both HF and Replicate

---

## Memory Instructions

1. Read this file at session start to recall user context
2. Update with new preferences, projects, or important info
3. Use this for remembering:
   - User preferences
   - Project context
   - Previously discussed topics
   - Setup configurations

---

*Last updated: 2026-02-19*
