#!/bin/bash
# OpenCode Build & Install Script
# Pulls from opencodeBC-MAIN fork and builds OpenCode
# Run this on Kali VM: bash install-opencode.sh

set -e

OPENCODE_DIR="$HOME/opencodeBC-MAIN"
OPENCODE_REPO="git@github.com:breakingcircuits1337/opencodeBC-MAIN.git"

echo "🔨 Building OpenCode from fork..."
echo "================================"
echo ""

# Install bun if not present
if ! command -v bun &> /dev/null; then
    echo "📦 Installing Bun..."
    curl -fsSL https://bun.sh/install | bash
    export BUN_INSTALL="$HOME/.bun"
    export PATH="$BUN_INSTALL/bin:$PATH"
fi

# Clone or update the fork
if [ -d "$OPENCODE_DIR" ]; then
    echo "📥 Updating existing fork..."
    cd "$OPENCODE_DIR"
    git pull origin dev
else
    echo "📥 Cloning opencodeBC-MAIN fork..."
    git clone "$OPENCODE_REPO" "$OPENCODE_DIR"
    cd "$OPENCODE_DIR"
fi

# Install dependencies and build
echo "📦 Installing dependencies..."
bun install

echo "🔨 Building OpenCode..."
cd packages/opencode
bun run build

# Find the built binary
BINARY=""
if [ "$(uname -m)" = "x86_64" ]; then
    BINARY="$OPENCODE_DIR/packages/opencode/dist/opencode-linux-x64/bin/opencode"
elif [ "$(uname -m)" = "aarch64" ]; then
    BINARY="$OPENCODE_DIR/packages/opencode/dist/opencode-linux-arm64/bin/opencode"
fi

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    echo "❌ Failed to find built binary"
    exit 1
fi

# Install to local bin
echo "📥 Installing OpenCode..."
mkdir -p "$HOME/.local/bin"
cp "$BINARY" "$HOME/.local/bin/opencode"
chmod +x "$HOME/.local/bin/opencode"

# Add to PATH if not already
if ! grep -q ".local/bin" "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

echo ""
echo "✅ OpenCode installed successfully!"
echo "   Version: $($HOME/.local/bin/opencode --version)"
echo ""
echo "Run 'opencode' to start"
