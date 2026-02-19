#!/bin/bash
# Quick Azure Login Script
# Usage: ./scripts/az-login.sh

echo "Logging into Azure..."
az login --use-device-code
echo "✅ Successfully logged into Azure"
echo ""
echo "Current subscription:"
az account show --query '{Name:name, ID:id, State:state}' -o table
