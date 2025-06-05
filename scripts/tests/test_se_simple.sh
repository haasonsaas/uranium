#!/bin/bash

echo "🔐 Testing Uranium Vault with Secure Enclave"
echo "==========================================="
echo ""

# Check status
echo "📊 Vault Status:"
curl -s http://localhost:8080/api/v1/status | jq
echo ""

# Store a smaller model
echo "💾 Storing model with Secure Enclave..."
RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/models \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-model-se",
    "data": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],
    "format": "SafeTensors"
  }')

echo "Response: $RESPONSE"
MODEL_ID=$(echo $RESPONSE | jq -r '.id')
echo ""

# Check if it was encrypted with SE
ENCRYPTED_WITH_SE=$(echo $RESPONSE | jq -r '.encrypted_with_se')
if [ "$ENCRYPTED_WITH_SE" = "true" ]; then
    echo "✅ Model was encrypted with Secure Enclave!"
else
    echo "❌ Model was NOT encrypted with Secure Enclave"
fi
echo ""

# List all models
echo "📋 All models in vault:"
curl -s http://localhost:8080/api/v1/models | jq '.[] | {name, encrypted_with_se}'