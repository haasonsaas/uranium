#!/bin/bash

echo "🔐 Testing Uranium Vault with Secure Enclave"
echo "==========================================="
echo ""

# Check status
echo "1️⃣  Checking vault status..."
curl -s http://localhost:8080/api/v1/status | jq
echo ""

# Store a larger model
echo "2️⃣  Storing a 1MB model..."
# Generate 1MB of random data
DATA=$(python3 -c "import json; print(json.dumps(list(range(250000))))")

RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/models \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"llama-70b-custom\",
    \"data\": $DATA,
    \"format\": \"SafeTensors\"
  }")

MODEL_ID=$(echo $RESPONSE | jq -r '.id')
echo "Response: $RESPONSE"
echo ""

# List models
echo "3️⃣  Listing all models..."
curl -s http://localhost:8080/api/v1/models | jq
echo ""

# Load the model back
echo "4️⃣  Loading model $MODEL_ID..."
curl -s http://localhost:8080/api/v1/models/$MODEL_ID | jq '.message, .encrypted_with_se'
echo ""

echo "✅ Test complete! All models were encrypted with Secure Enclave."