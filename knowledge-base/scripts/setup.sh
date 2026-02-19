#!/bin/bash
# Knowledge Base Setup Script
# Installs and configures Redis and PostgreSQL

set -e

echo "🧠 Knowledge Base Setup"
echo "========================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "📦 Installing dependencies..."

# Update
apt update -y

# Install Redis
echo "Installing Redis..."
apt install -y redis-server redis-tools

# Install PostgreSQL
echo "Installing PostgreSQL..."
apt install -y postgresql postgresql-contrib

# Start services
echo "Starting services..."
systemctl start redis-server
systemctl start postgresql

# Enable on boot
systemctl enable redis-server
systemctl enable postgresql

# Configure PostgreSQL
echo "Configuring PostgreSQL..."

# Create database and user
sudo -u postgres psql << EOF
-- Create user
CREATE USER sarah WITH PASSWORD 'sarah' SUPERUSER;

-- Create database
CREATE DATABASE knowledge_base OWNER sarah;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE knowledge_base TO sarah;

-- Connect and grant schema access
\c knowledge_base
GRANT ALL ON SCHEMA public TO sarah;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO sarah;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO sarah;

\echo '✅ PostgreSQL configured'
EOF

# Configure Redis (optional: add password)
echo "Configuring Redis..."

# Create Redis config backup
cp /etc/redis/redis.conf /etc/redis/redis.conf.bak

# Uncomment bind to allow local connections
sed -i 's/bind 127.0.0.1 ::1/bind 127.0.0.1/' /etc/redis/redis.conf

# Restart Redis
systemctl restart redis-server

# Test connections
echo ""
echo "Testing connections..."

# Test Redis
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis: Connected"
else
    echo "❌ Redis: Failed"
fi

# Test PostgreSQL
if sudo -u sarah psql -d knowledge_base -c "SELECT 1" > /dev/null 2>&1; then
    echo "✅ PostgreSQL: Connected"
else
    echo "❌ PostgreSQL: Failed"
fi

echo ""
echo "🎉 Setup Complete!"
echo ""
echo "To start the knowledge base:"
echo "  cd ~/knowledge-base"
echo "  npm install"
echo "  node src/cli.js stats"
echo ""
echo "Commands available:"
echo "  node src/cli.js learn <key> <value>"
echo "  node src/cli.js recall <key>"
echo "  node src/cli.js search <query>"
echo "  node src/cli.js interactive"
