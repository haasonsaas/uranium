#!/bin/bash

echo "🔐 Uranium Vault Demo - Full Workflow"
echo "===================================="
echo ""

# Check if server is running
if ! curl -s http://localhost:8080/api/v1/status > /dev/null 2>&1; then
    echo "Starting vault server..."
    ./start-vault.sh &
    sleep 2
fi

echo "1️⃣  Check vault status"
./target/debug/uranium status
echo ""

echo "2️⃣  Show vault details"
./target/debug/uranium vault status
echo ""

echo "3️⃣  List models (should be empty or have existing)"
./target/debug/uranium model list
echo ""

echo "4️⃣  Store a test model"
echo "Creating test model file..."
echo "This is a test LLM model" > demo-model.safetensors
./target/debug/uranium model store demo-model.safetensors --name "demo-llm" --version "1.0"
rm demo-model.safetensors
echo ""

echo "5️⃣  List models again"
./target/debug/uranium model list --detailed
echo ""

echo "✅ Demo complete!"
echo ""
echo "The model was automatically encrypted with Secure Enclave (on supported Macs)."
echo "Try storing your own models with:"
echo "  ./target/debug/uranium model store <file> --name <name>"