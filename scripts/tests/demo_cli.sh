#!/bin/bash

# Demo script for Uranium CLI

echo "=== Uranium CLI Demo ==="
echo

# Check if the vault server is running
if ! curl -s http://localhost:8080/api/v1/status > /dev/null 2>&1; then
    echo "❌ Vault server is not running."
    echo "Please run './start-vault.sh' in another terminal first."
    exit 1
fi

echo "✅ Vault server is running"
echo

# Build the CLI
echo "Building CLI..."
cargo build -p uranium-cli --quiet
URANIUM="./target/debug/uranium"

# Initialize config
echo "1. Initializing Uranium configuration..."
echo "http://localhost:8080" | $URANIUM init

# Show status
echo
echo "2. Showing Uranium status..."
$URANIUM status

# List models
echo
echo "3. Listing models..."
$URANIUM model list

# Create a test model file
echo
echo "4. Creating test model file..."
echo "Test model data for Uranium demo" > test_model.safetensors

# Store the model
echo
echo "5. Storing model..."
$URANIUM model store test_model.safetensors --name "test-model" --version "1.0"

# List models again
echo
echo "6. Listing models after store..."
$URANIUM model list --detailed

# Get model info
echo
echo "7. Getting model info..."
# Extract the model ID from the list (this is a hack for demo purposes)
MODEL_ID=$($URANIUM model list 2>/dev/null | grep test-model | awk '{print $2}' | head -1)
if [ ! -z "$MODEL_ID" ]; then
    $URANIUM model info "$MODEL_ID"
fi

# Clean up
rm -f test_model.safetensors

echo
echo "✅ CLI demo completed!"