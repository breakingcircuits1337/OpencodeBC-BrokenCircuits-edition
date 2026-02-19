#!/bin/bash
# Check Azure AI Foundry deployments and status
# Usage: ./scripts/check-ai-foundry.sh [resource-group] [workspace-name]

RESOURCE_GROUP="${1:-brokencircuits-1334-resource}"
WORKSPACE="${2:-}"

echo "🔍 Checking Azure AI Foundry Resources..."
echo ""
echo "Resource Group: $RESOURCE_GROUP"
echo ""

# List all Azure OpenAI/Cognitive Services resources
echo "📋 AI Services Resources:"
az cognitiveservices account list -g "$RESOURCE_GROUP" -o table 2>/dev/null || echo "   No resources found or access denied"
echo ""

# Check deployments if workspace provided
if [ -n "$WORKSPACE" ]; then
    echo "🤖 Model Deployments in workspace '$WORKSPACE':"
    # This would need az ml CLI extension
    az ml model list -g "$RESOURCE_GROUP" -w "$WORKSPACE" -o table 2>/dev/null || echo "   Install 'ml' extension: az extension add -n ml"
    echo ""
fi

# Show current subscription credit info
echo "💰 Subscription Info:"
az account show --query '{Name:name, ID:id}' -o table
echo ""

echo "✅ Check complete!"
echo ""
echo "To interact with your Mistral/Kimi models, use:"
echo "  python3 /home/sarah/models/mistral.py 'your prompt'"
echo "  python3 /home/sarah/models/kimi.py 'your prompt'"
