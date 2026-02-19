#!/bin/bash
# OpenCode BC Setup Script for Kali Linux VM
# Run this on the Kali VM through Proxmox console
# Usage: bash setup-opencode-bc.sh

echo "🚀 Setting up OpenCode BC Environment on Kali Linux"
echo "=================================================="
echo ""

# Update system
echo "📦 Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install essential tools
echo "🔧 Installing essential tools..."
sudo apt-get install -y \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    code \
    xclip \
    xsel \
    espeak \
    firefox-esr \
    ssh \
    htop \
    vim \
    nano

# Create directories
echo "📁 Creating directory structure..."
mkdir -p ~/bin
mkdir -p ~/.venvs
mkdir -p ~/skills
mkdir -p ~/Documents
mkdir -p ~/Pictures
mkdir -p ~/models
mkdir -p ~/.config/Code/User
mkdir -p ~/.claude/homunculus

# Setup Python virtual environment
echo "🐍 Setting up Python environment..."
python3 -m venv ~/.venvs/base
source ~/.venvs/base/bin/activate

# Install Python packages
echo "📚 Installing Python packages..."
pip install --upgrade pip
pip install \
    ipython \
    black \
    flake8 \
    mypy \
    ruff \
    gTTS \
    pygame \
    requests \
    proxmoxer \
    huggingface_hub \
    replicate \
    openai

# Install Node.js tools
echo "📦 Installing Node.js tools..."
sudo npm install -g \
    typescript \
    eslint \
    prettier \
    yarn \
    pnpm

# Install OpenCode
echo "💻 Installing OpenCode CLI..."
curl -fsSL https://cli.opencode.ai/install.sh | bash

# Create .env file template
echo "🔐 Creating environment configuration..."
cat > ~/.env << 'ENVFILE'
# API Keys - Add your keys here
HUGGING_FACE_TOKEN=your_huggingface_token_here
REPLICATE_API_TOKEN=your_replicate_token_here

# Azure AI Foundry
AZURE_API_KEY=your_azure_api_key_here
AZURE_REGION=east2
MISTRAL_ENDPOINT=https://your-resource.cognitiveservices.azure.com/openai/deployments/Mistral-Large-3/chat/completions?api-version=2024-05-01-preview
KIMI_ENDPOINT=https://your-resource.cognitiveservices.azure.com/openai/deployments/Kimi-K2-Thinking/chat/completions?api-version=2024-05-01-preview

# Proxmox
PROXMOX_HOST=192.168.1.115
PROXMOX_PORT=8006
PROXMOX_USER=root@pam
PROXMOX_PASS=your_proxmox_password_here
ENVFILE

# Create CLAUDE.md
echo "📝 Creating CLAUDE.md memory file..."
cat > ~/CLAUDE.md << 'CLAUDEMD'
# CLAUDE.md - User Context & Memory

## User Profile
- **Name**: User (sarah)
- **Location**: Kali Linux VM - Agent-1337
- **Host**: Proxmox Dell R720 XD at 192.168.1.115

## Preferences

### File Storage
- **Documents**: ~/Documents
- **Images**: ~/Pictures

### Editor
- **Preferred Editor**: VS Code

### Programming Languages
- **Primary**: Python 3.12
- **Package Manager**: pip
- **Python venv**: ~/.venvs/base
- **Installed Tools**: ipython, black, flake8, mypy, ruff

### JavaScript/Node.js
- **Global Tools**: typescript, eslint, prettier, yarn, pnpm

### AI API Keys
- **Config File**: ~/.env
- **Azure AI Foundry**: Configured for east2 region
- **Proxmox**: Dell R720 XD at 192.168.1.115:8006

### Custom Models
- **Models Directory**: ~/models/
- Scripts for Mistral 3 Large and Kimi K2 Thinking

## Memory Instructions
1. Read this file at session start to recall user context
2. Update with new preferences, projects, or important info

*Last updated: $(date)*
CLAUDEMD

# Create VS Code settings
echo "⚙️  Configuring VS Code..."
cat > ~/.config/Code/User/settings.json << 'VSCODE'
{
    "editor.formatOnSave": true,
    "editor.rulers": [88, 120],
    "editor.tabSize": 4,
    "python.defaultInterpreterPath": "~/.venvs/base/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "terminal.integrated.defaultProfile.linux": "bash"
}
VSCODE

# Create TTS speak script
echo "🔊 Creating TTS script..."
cat > ~/bin/speak << 'SPEAKSCRIPT'
#!/bin/bash
# Text-to-Speech using gTTS

if [ $# -eq 0 ]; then
    echo "Usage: speak 'text to speak'"
    exit 1
fi

source ~/.venvs/base/bin/activate
python3 -c "
from gtts import gTTS
import tempfile
import os

text = ' '.join('$@'.split())
tts = gTTS(text, lang='en-us')

with tempfile.NamedTemporaryFile(suffix='.mp3', delete=False) as f:
    temp_file = f.name
    tts.save(temp_file)

print(f'Playing: {text}')
os.system(f'cvlc {temp_file} --play-and-exit 2>/dev/null || mpg321 {temp_file} 2>/dev/null || echo TTS: {text}')
os.remove(temp_file)
"
SPEAKSCRIPT

chmod +x ~/bin/speak

# Create Azure model scripts
echo "🤖 Creating Azure model scripts..."

# Mistral script
cat > ~/models/mistral.py << 'MISTRAL'
#!/usr/bin/env python3
import sys
import os
import requests

AZURE_KEY = os.getenv("AZURE_API_KEY")
AZURE_ENDPOINT = os.getenv("MISTRAL_ENDPOINT", "https://your-resource.cognitiveservices.azure.com/openai/deployments/Mistral-Large-3/chat/completions?api-version=2024-05-01-preview")

def call_mistral(prompt):
    if not AZURE_KEY:
        print("Error: AZURE_API_KEY not set")
        sys.exit(1)
    
    headers = {
        "Content-Type": "application/json",
        "api-key": AZURE_KEY
    }
    
    payload = {
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "temperature": 0.7
    }
    
    response = requests.post(AZURE_ENDPOINT, headers=headers, json=payload)
    response.raise_for_status()
    
    return response.json()["choices"][0]["message"]["content"]

if __name__ == "__main__":
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read().strip()
    if not prompt:
        print("Usage: python3 mistral.py 'your prompt'")
        sys.exit(1)
    
    print(call_mistral(prompt))
MISTRAL

chmod +x ~/models/mistral.py

# Create aliases
echo "🔗 Creating shell aliases..."
cat >> ~/.bashrc << 'ALIASES'

# OpenCode BC Aliases
alias mistral="python3 ~/models/mistral.py"
alias opencode-bc="opencode"
export PATH="$PATH:$HOME/bin"
export EDITOR="code"

# Load environment variables
if [ -f ~/.env ]; then
    set -a
    source ~/.env
    set +a
fi
ALIASES

# Create GitHub SSH setup reminder
echo "🔑 Creating SSH key setup script..."
cat > ~/bin/setup-github-ssh.sh << 'GITHUBSSH'
#!/bin/bash
# Setup GitHub SSH key

if [ ! -f ~/.ssh/id_ed25519 ]; then
    echo "Generating SSH key..."
    ssh-keygen -t ed25519 -C "sarah@agent-1337" -f ~/.ssh/id_ed25519 -N ""
    eval "$(ssh-agent -s)"
    ssh-add ~/.ssh/id_ed25519
    echo ""
    echo "Add this public key to GitHub:"
    cat ~/.ssh/id_ed25519.pub
    echo ""
    echo "Go to: https://github.com/settings/keys"
else
    echo "SSH key already exists"
fi
GITHUBSSH

chmod +x ~/bin/setup-github-ssh.sh

# Create skills directory structure
echo "📚 Setting up skills directory..."
mkdir -p ~/skills

# Create README
echo "📖 Creating README..."
cat > ~/README.md << 'README'
# OpenCode BC - Agent-1337

Kali Linux VM with OpenCode BC environment.

## Quick Start

```bash
# Activate Python environment
source ~/.venvs/base/bin/activate

# Use TTS
speak "Hello from Agent-1337"

# Call Azure models
python3 ~/models/mistral.py "Your prompt"

# Start OpenCode
opencode
```

## Configuration

Edit `~/.env` to add your API keys.

## Installed Tools

- Python 3.12 with venv
- Node.js & npm
- VS Code
- OpenCode CLI
- Git, curl, wget
- TTS (gTTS)
- Azure, HuggingFace, Replicate libraries

## Directory Structure

```
~/
├── bin/              # Custom scripts
├── models/           # Azure model scripts
├── skills/           # Custom skills
├── Documents/        # Documentation
├── Pictures/         # Images
├── .venvs/base/      # Python environment
└── .env              # API keys (not in git)
```
README

# Final setup
echo ""
echo "✅ Setup Complete!"
echo "=================="
echo ""
echo "📋 NEXT STEPS:"
echo "1. Edit ~/.env and add your API keys"
echo "2. Run: source ~/.bashrc"
echo "3. Test: speak 'Hello from Agent-1337'"
echo "4. Setup GitHub SSH: ~/bin/setup-github-ssh.sh"
echo ""
echo "🌐 Proxmox Web Interface: https://192.168.1.115:8006"
echo "🚀 Start OpenCode: opencode"
echo ""
echo "📁 Files created:"
echo "   ~/.env - API keys configuration"
echo "   ~/CLAUDE.md - Memory file"
echo "   ~/models/mistral.py - Azure Mistral script"
echo "   ~/bin/speak - TTS tool"
echo ""
