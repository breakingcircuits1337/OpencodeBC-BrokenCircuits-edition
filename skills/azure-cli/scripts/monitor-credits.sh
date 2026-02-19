#!/bin/bash
# Monitor Azure credits and usage
# Usage: ./scripts/monitor-credits.sh

echo "💳 Azure Credit Monitor"
echo "======================"
echo ""

# Get subscription info
SUBSCRIPTION=$(az account show --query 'name' -o tsv)
SUB_ID=$(az account show --query 'id' -o tsv)

echo "Subscription: $SUBSCRIPTION"
echo "ID: $SUB_ID"
echo ""

# List all resource groups with their locations
echo "📦 Resource Groups:"
az group list --query '[].{Name:name, Location:location, Status:properties.provisioningState}' -o table

echo ""
echo "🔧 Quick Commands:"
echo "  List all resources:           az resource list -o table"
echo "  Check VM status:              az vm list -o table"
echo "  Check storage accounts:       az storage account list -o table"
echo "  Check AI services:            az cognitiveservices account list -o table"
echo ""
echo "💡 To track spending, visit: https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBlade"
