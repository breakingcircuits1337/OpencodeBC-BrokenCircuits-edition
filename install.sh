#!/bin/bash
# OpenCode BC - BrokenCircuits Edition
# One-command installation script
# Run: curl -fsSL https://raw.githubusercontent.com/breakingcircuits1337/OpencodeBC-BrokenCircuits-edition/main/install.sh | bash
#
# This script installs OpenCode from source (opencodeBC-MAIN fork) 
# with BrokenCircuits configurations and skills

set -e

echo "💀 Deploying OpenCode BC - The Defender's Arsenal"
echo "================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="$HOME/opencode-bc"
OPENCODE_REPO="git@github.com:breakingcircuits1337/opencodeBC-MAIN.git"
CONFIG_REPO="git@github.com:breakingcircuits1337/OpencodeBC-BrokenCircuits-edition.git"

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "📋 System: $OS ($ARCH)"
echo "📁 Install directory: $INSTALL_DIR"
echo ""

# Step 1: Install system dependencies
echo "Injecting system dependencies..."

if [ "$OS" = "Linux" ]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq git curl build-essential libssl-dev pkg-config ffmpeg
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm git curl base-devel openssl ffmpeg
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y git curl openssl-devel ffmpeg
    fi
fi

# Step 2: Install Bun (required for building OpenCode)
echo "🐰 Installing Bun..."

if ! command -v bun &> /dev/null; then
    curl -fsSL https://bun.sh/install | bash
    export BUN_INSTALL="$HOME/.bun"
    export PATH="$BUN_INSTALL/bin:$PATH"
fi

echo "✅ Bun version: $(bun --version)"

# Step 3: Clone or update opencodeBC-MAIN (the OpenCode fork)
echo "📥 Setting up OpenCode source (opencodeBC-MAIN)..."

if [ -d "$HOME/opencodeBC-MAIN" ]; then
    echo "   Updating existing fork..."
    cd "$HOME/opencodeBC-MAIN"
    git pull origin dev 2>/dev/null || git pull origin main 2>/dev/null || true
else
    git clone "$OPENCODE_REPO" "$HOME/opencodeBC-MAIN"
    cd "$HOME/opencodeBC-MAIN"
    git checkout dev 2>/dev/null || true
fi

# Step 4: Install OpenCode dependencies and build
echo "🔨 Building OpenCode..."

cd "$HOME/opencodeBC-MAIN"
bun install --frozen-lockfile 2>/dev/null || bun install

cd packages/opencode
OPENCODE_CHANNEL=bc bun run build

# Find and install the binary
echo "📥 Installing OpenCode binary..."

if [ "$ARCH" = "x86_64" ]; then
    BINARY="$HOME/opencodeBC-MAIN/packages/opencode/dist/opencode-linux-x64/bin/opencode-bc"
elif [ "$ARCH" = "aarch64" ]; then
    BINARY="$HOME/opencodeBC-MAIN/packages/opencode/dist/opencode-linux-arm64/bin/opencode-bc"
else
    echo -e "${YELLOW}⚠️ Unknown architecture: $ARCH${NC}"
    echo "   Attempting to find any available binary..."
    BINARY=$(find "$HOME/opencodeBC-MAIN/packages/opencode/dist" -name "opencode-bc" -type f 2>/dev/null | head -1)
fi

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    echo -e "${RED}❌ Failed to find built binary${NC}"
    echo "   You may need to build manually. See opencodeBC-MAIN"
    exit 1
fi

mkdir -p "$HOME/.local/bin"
cp "$BINARY" "$HOME/.local/bin/opencode-bc"
chmod +x "$HOME/.local/bin/opencode-bc"

# Add to PATH if needed
BASHRC="$HOME/.bashrc"
if ! grep -q ".local/bin/opencode-bc" "$BASHRC" 2>/dev/null; then
    echo '' >> "$BASHRC"
    echo '# OpenCode BC' >> "$BASHRC"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$BASHRC"
fi

# Step 5: Clone BrokenCircuits configuration
echo "⚙️ Setting up BrokenCircuits configuration..."

if [ ! -d "$INSTALL_DIR" ]; then
    git clone "$CONFIG_REPO" "$INSTALL_DIR"
else
    cd "$INSTALL_DIR"
    git pull origin main 2>/dev/null || true
fi

# Step 6: Create environment file template
echo "🔐 Creating configuration files..."

if [ ! -f "$HOME/.env" ]; then
    cat > "$HOME/.env" << 'EOF'
# OpenCode BC - API Keys
# Add your keys here

# Hugging Face
HUGGING_FACE_TOKEN=

# Replicate
REPLICATE_API_TOKEN=

# Azure AI Foundry
AZURE_API_KEY=
AZURE_REGION=east2

# Azure OpenAI Endpoints
MISTRAL_ENDPOINT=
KIMI_ENDPOINT=
EOF
    echo "   Created ~/.env template - add your API keys"
fi

# Step 7: Setup OpenCode configuration
echo "📝 Configuring OpenCode..."

mkdir -p "$HOME/.config/opencode"
mkdir -p "$HOME/.local/share/opencode"

# Copy OpenCode config if exists
if [ -f "$INSTALL_DIR/opencode.jsonc" ]; then
    cp "$INSTALL_DIR/opencode.jsonc" "$HOME/.config/opencode/config.jsonc"
fi

# Copy skills
if [ -d "$INSTALL_DIR/skills" ]; then
    mkdir -p "$HOME/.config/opencode/skills"
    cp -r "$INSTALL_DIR/skills/"* "$HOME/.config/opencode/skills/" 2>/dev/null || true
fi

# Step 8: Copy CLAUDE.md
if [ -f "$INSTALL_DIR/CLAUDE.md" ]; then
    cp "$INSTALL_DIR/CLAUDE.md" "$HOME/CLAUDE.md"
    echo "   Copied CLAUDE.md"
fi

# Step 9: Create convenience scripts
echo "📜 Creating convenience scripts..."

mkdir -p "$HOME/bin"

# Speak script
if [ -f "$INSTALL_DIR/bin/speak" ]; then
    cp "$INSTALL_DIR/bin/speak" "$HOME/bin/speak"
    chmod +x "$HOME/bin/speak"
fi
    echo "   Installed speak script from repo"
else
if [ ! -f "$HOME/bin/speak" ]; then
    cat > "$HOME/bin/speak" << 'TTS'
#!/bin/bash
# Text-to-Speech using gTTS

if [ $# -eq 0 ]; then
    echo "Usage: speak 'text to speak'"
    exit 1
fi

python3 -c "
from gtts import gTTS
import tempfile
import os

text = ' '.join('$@'.split())
tts = gTTS(text, lang='en-us')

with tempfile.NamedTemporaryFile(suffix='.mp3', delete=False) as f:
    temp_file = f.name
    tts.save(temp_file)

print(f'Speaking: {text}')
os.system(f'ffplay -nodisp -autoexit -loglevel quiet {temp_file} 2>/dev/null || echo {text}')
os.remove(temp_file)
"
TTS
    chmod +x "$HOME/bin/speak"
fi
fi
    chmod +x "$HOME/bin/speak"
fi
fi

# Update PATH in bashrc
if ! grep -q "HOME/bin" "$BASHRC" 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/bin"' >> "$BASHRC"
fi

echo ""
echo -e "${GREEN}💀 Deployment Successful. Defense Grid Active.${NC}"
echo "================================"
echo ""
echo "📋 Next steps:"
echo "   1. Edit ~/.env and add your API keys"
echo "   2. Restart your terminal or run: source ~/.bashrc"
echo "   3. Run: opencode --version"
echo "   4. Start OpenCode: opencode"
echo ""
echo "📁 Installed to: $HOME/.local/bin/opencode"
echo "⚙️  Config: $HOME/.config/opencode/"
echo "🧠 Memory: $HOME/CLAUDE.md"
echo ""
echo "🔑 API Keys: Edit ~/.env to add your keys"
echo ""
echo "💡 To update later, run:"
echo "   cd $INSTALL_DIR && git pull"
echo "   cd $HOME/opencodeBC-MAIN && git pull && bun run build"
echo ""

# Launch Wake Sequence
if [ -f bin/wake_up.py ]; then
    python3 bin/wake_up.py
fi
