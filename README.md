<!-- markdownlint-disable -->
<p align="center">
  <img src="Pictures/opencode-readme.png" alt="OpenCode BC - BrokenCircuits Edition" width="800"/>
</p>

<h1 align="center">OpenCode BC</h1>
<h3 align="center">BrokenCircuits Edition</h3>
<h4 align="center" style="color: orange;">⚠️ Beta - Expect Some Bumps</h4>

<p align="center">
  <a href="https://github.com/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition">
    <img src="https://img.shields.io/github/repo-size/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition?color=blue&label=Size" alt="Repo Size"/>
  </a>
  <a href="https://github.com/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition">
    <img src="https://img.shields.io/github/license/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition?color=green&label=License" alt="License"/>
  </a>
  <a href="https://github.com/breakingcircuits1337">
    <img src="https://img.shields.io/github/followers/breakingcircuits1337?color=purple&label=Follow" alt="GitHub followers"/>
  </a>
</p>

---

## Quick Install (One Command)

```bash
curl -fsSL https://raw.githubusercontent.com/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition/main/install.sh | bash
```

Or clone and run manually:

```bash
git clone git@github.com:breakingcircuits1337/OpencodeBC-BrokenCircuits-edition.git ~/opencode-bc
cd ~/opencode-bc
bash install.sh
```

---

## ⚠️ Beta Notice

> **This project is in early beta.** Things may break, APIs may change, and documentation may be incomplete. Please [report issues](https://github.com/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition/issues) as you find them!

### Known Limitations
- Build process requires Bun 1.3.9+
- Some skills may require additional setup
- Azure integration requires valid API keys

### What's Working
- OpenCode CLI builds and runs
- Basic skills loaded
- TTS speak command
- GitHub SSH integration

---

## About This Project

This is a customized distribution of **OpenCode CLI** - the AI assistant that lives in your terminal. The BrokenCircuits Edition includes pre-configured tools, skills, and setup for AI-powered development.

### Two-Repo System

| Repo | Purpose |
|------|---------|
| [opencodeBC-MAIN](https://github.com/breakingcircuits1337/opencodeBC-MAIN) | Fork of OpenCode - build from source |
| [OpencodeBC-BrokenCircuits-edition](https://github.com/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition) | Configs, skills, and install scripts |

### Features

- 🤖 **AI-Powered Assistance** - OpenCode CLI built from source
- 🐍 **Python Development** - Full Python environment with venv, black, flake8, mypy, ruff
- 💻 **JavaScript/Node.js** - TypeScript, ESLint, Prettier, Yarn, PNPM
- 🎨 **AI Image Generation** - Stable Diffusion XL via Hugging Face
- 🔊 **Text-to-Speech** - Natural Google TTS voice
- 🔐 **GitHub Integration** - SSH authentication ready
- 💾 **Persistent Memory** - CLAUDE.md for context retention
- 🛠️ **20+ Specialized Skills** - For development, testing, media, and more

---

## What's Included

```
OpencodeBC-BrokenCircuits-edition/
├── install.sh                 # One-command installer
├── README.md                  # This file
├── CLAUDE.md                  # Persistent memory template
├── opencode.jsonc             # OpenCode configuration
├── skills/                    # Custom skills
│   ├── azure-llm-bridge/     # Azure Mistral/Kimi scripts
│   ├── azure-cli/            # Azure management
│   └── proxmox-manager/     # Proxmox VM management
├── bin/
│   └── speak                 # TTS voice script
├── .config/
│   └── Code/
│       └── User/
│           └── settings.json # VS Code configuration
└── .gitignore
```

---

## Installation

### Prerequisites

- Linux (Ubuntu, Debian, Kali, Arch, Fedora)
- Git
- SSH key added to GitHub

### Quick Install

```bash
# Clone this repo
git clone git@github.com:breakingcircuits1337/OpencodeBC-BrokenCircuits-edition.git ~/opencode-bc
cd ~/opencode-bc

# Run installer
bash install.sh
```

The installer will:
1. Install system dependencies
2. Install Bun (JavaScript runtime)
3. Clone and build OpenCode from opencodeBC-MAIN fork
4. Install OpenCode binary to ~/.local/bin/
5. Setup configs and skills
6. Create ~/.env template

### Manual Setup

If you prefer manual installation:

```bash
# 1. Install Bun
curl -fsSL https://bun.sh/install | bash

# 2. Clone OpenCode fork
git clone git@github.com:breakingcircuits1337/opencodeBC-MAIN.git
cd opencodeBC-MAIN
bun install
cd packages/opencode
bun run build

# 3. Install binary
cp dist/opencode-linux-x64/bin/opencode ~/.local/bin/opencode
chmod +x ~/.local/bin/opencode

# 4. Clone configs
cd ~
git clone git@github.com:breakingcircuits1337/OpencodeBC-BrokenCircuits-edition.git
```

---

## Configuration

### API Keys

Edit `~/.env` to add your keys:

```bash
# Hugging Face
HUGGING_FACE_TOKEN=your_hf_token

# Replicate  
REPLICATE_API_TOKEN=your_replicate_token

# Azure AI Foundry
AZURE_API_KEY=your_azure_key
AZURE_REGION=east2
```

### OpenCode Config

The included `opencode.jsonc` provides:
- Azure AI Foundry integration (Mistral Large 3, Kimi K2 Thinking)
- Custom keybindings
- Model preferences

---

## Available Skills

This setup includes 20+ specialized skills:

| Category | Skills |
|----------|--------|
| **Development** | spawn-team, browser-automation, mcp-integration, subagent-driven-development |
| **AI & Media** | agent-tools, ai-avatar-video, ai-video-generation, canvas-design |
| **Testing** | webapp-testing, audit-website, seo-audit |
| **Process** | brainstorming, systematic-debugging, test-driven-development, finishing-a-development-branch |
| **Creative** | copywriting, marketing-psychology |
| **Research** | OSINT |
| **Operations** | product-operations, operations-optimizer |

See [opencode-skills-catalog.md](opencode-skills-catalog.md) for full list.

---

## Text-to-Speech

The `speak` command uses Google TTS:

```bash
speak "Hello! I'm your AI assistant."
```

---

## Updating

```bash
# Update configs and skills
cd ~/opencode-bc
git pull

# Update OpenCode source
cd ~/opencodeBC-MAIN
git pull
bun install
cd packages/opencode
bun run build

# Reinstall binary
cp dist/opencode-linux-x64/bin/opencode ~/.local/bin/opencode
```

---

## Troubleshooting

### Build fails
- Ensure Bun is installed: `bun --version`
- Try: `cd ~/opencodeBC-MAIN && bun install && bun run build`

### OpenCode not found
- Check PATH: `echo $PATH`
- Add manually: `export PATH="$HOME/.local/bin:$PATH"`

### SSH clone fails
- Ensure SSH key is added to GitHub
- Or use HTTPS: `https://github.com/breakingcircuits1337/...`

---

## Tech Stack

- **Runtime**: Bun 1.3.9
- **Languages**: Python 3.12, Node.js, TypeScript
- **AI**: Azure AI Foundry (Mistral, Kimi), Hugging Face, Replicate
- **Editor**: VS Code
- **TTS**: Google gTTS

---

## Author

**BreakingCircuits** (@breakingcircuits1337)

- GitHub: [breakingcircuits1337](https://github.com/breakingcircuits1337)
- Hugging Face: [breakingcircuits](https://huggingface.co/breakingcircuits)

---

## Support This Project

If you find this helpful, consider supporting!

### Ways to Support

- ⭐ **Star the repo** - Helps visibility
- 🍴 **Fork and customize** - Make it your own
- 📢 **Share** - Tell others about it
- 💵 **Donate** - Help cover server costs

<a href="https://buymeacoffee.com/breakingcircuits" target="_blank">
  <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Donate-yellow?style=for-the-badge&logo=buy-me-a-coffee" alt="Buy Me a Coffee"/>
</a>

---

## License

MIT License - Feel free to use and modify!

---

<p align="center">
  <em>Built with 🤖 by OpenCode + BreakingCircuits</em>
</p>
