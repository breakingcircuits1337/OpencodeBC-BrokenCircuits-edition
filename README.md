<!-- markdownlint-disable -->
<p align="center">
  <img src="Pictures/opencode-readme.png" alt="OpenCode BC - BrokenCircuits Edition" width="800"/>
</p>

<h1 align="center">OpenCode BC</h1>
<h3 align="center">BrokenCircuits Edition</h3>

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

## About This Project

This is a customized configuration for **OpenCode CLI** - the AI assistant that lives in your terminal. This edition, "BrokenCircuits," includes pre-configured tools, skills, and setup for AI-powered development.

### Features

- 🤖 **AI-Powered Assistance** - OpenCode CLI with 20+ specialized skills
- 🐍 **Python Development** - Full Python environment with venv, black, flake8, mypy, ruff
- 💻 **JavaScript/Node.js** - TypeScript, ESLint, Prettier, Yarn, PNPM
- 🎨 **AI Image Generation** - Stable Diffusion XL via Hugging Face
- 🔊 **Text-to-Speech** - Natural Google TTS voice
- 🔐 **GitHub Integration** - SSH authentication ready
- 📋 **Clipboard Tools** - xclip for seamless copy/paste
- 💾 **Persistent Memory** - CLAUDE.md for context retention

---

## What's Included

```
OpencodeBC-BrokenCircuits-edition/
├── CLAUDE.md                 # Persistent memory & preferences
├── bin/
│   └── speak               # TTS voice script
├── .config/
│   └── Code/
│       └── User/
│           └── settings.json  # VS Code configuration
├── opencode-skills-catalog.md  # Available skills
└── .gitignore
```

---

## Quick Start

### 1. Clone This Setup

```bash
git clone git@github.com:breakingcircuits1337/OpencodeBC-BrokenCircuits-edition.git ~/opencode-bc
cd ~/opencode-bc
```

### 2. Install Dependencies

**Python:**
```bash
mkdir -p ~/.venvs
python3 -m venv ~/.venvs/base
~/.venvs/base/bin/pip install ipython black flake8 mypy ruff gTTS pygame
```

**Node.js:**
```bash
npm install -g typescript eslint prettier yarn pnpm
```

**System Tools:**
```bash
sudo apt-get install -y xclip xsel
```

### 3. Configure GitHub SSH

Add your SSH key to GitHub:
```bash
cat ~/.ssh/your_key.pub
# Copy and add to GitHub → Settings → SSH Keys
```

### 4. Set Up API Keys (Optional)

Create `~/.env`:
```bash
HUGGING_FACE_TOKEN=your_hf_token
REPLICATE_API_TOKEN=your_replicate_token
```

---

## Available Skills

This setup includes access to 20+ specialized skills:

| Category | Skills |
|----------|--------|
| **Development** | spawn-team, browser-automation, mcp-integration |
| **AI & Media** | agent-tools, ai-avatar-video, ai-video-generation |
| **Testing** | webapp-testing, audit-website, seo-audit |
| **Process** | brainstorming, systematic-debugging, test-driven-development |
| **Creative** | canvas-design, copywriting, marketing-psychology |
| **Research** | OSINT |

See [opencode-skills-catalog.md](opencode-skills-catalog.md) for full list.

---

## Text-to-Speech

The `speak` script uses Google TTS for natural voice output:

```bash
# Add to your path
export PATH="$PATH:~/opencode-bc/bin"

# Use it
speak "Hello! I'm your AI assistant."
```

---

## Image Generation

Generate AI images using Stable Diffusion XL:

```python
from huggingface_hub import InferenceClient

client = InferenceClient(
    "stabilityai/stable-diffusion-xl-base-1.0",
    token="your_hf_token"
)

image = client.text_to_image("your prompt here")
image.save("output.png")
```

---

## Configuration Highlights

### VS Code Settings
- Python: black formatting, flake8 linting
- JavaScript/TypeScript: Prettier on save
- Rulers at 88 and 120 columns

### Python Tools
- **black** - Code formatting
- **flake8** - Linting
- **mypy** - Type checking
- **ruff** - Fast linter/formatter

### Memory System
The `CLAUDE.md` file stores preferences and context. OpenCode reads it at session start to remember:
- User preferences
- Project context
- Setup configurations
- Previously discussed topics

---

## Screenshots

<p align="center">
  <img src="Pictures/opencode-readme.png" alt="AI Terminal" width="600"/>
</p>

---

## Tech Stack

- **Runtime**: OpenCode CLI
- **Languages**: Python 3.12, Node.js 24
- **AI**: Hugging Face, Replicate
- **Editor**: VS Code
- **TTS**: Google gTTS

---

## Author

**BreakingCircuits** (@breakingcircuits1337)

- GitHub: [breakingcircuits1337](https://github.com/breakingcircuits1337)
- Hugging Face: [breakingcircuits](https://huggingface.co/breakingcircuits)

---

## License

MIT License - Feel free to use and modify!

---

<p align="center">
  <em>Built with 🤖 by OpenCode + BreakingCircuits</em>
</p>
