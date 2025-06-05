#!/usr/bin/env python3
"""
Basic usage example for Uranium Python SDK
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from uranium_sdk import VaultClient, ModelFormat, connect


def main():
    # Create client
    client = VaultClient("http://localhost:8080")
    
    # Authenticate
    print("Authenticating...")
    token = client.authenticate("admin", "changeme")
    print(f"✅ Authenticated successfully")
    print(f"Token: {token[:20]}...")
    
    # Check vault status
    print("\nChecking vault status...")
    status = client.status()
    print(f"Vault status: {status.vault_status}")
    print(f"Secure Enclave available: {status.secure_enclave_available}")
    print(f"Models count: {status.models_count}")
    
    # List models
    print("\nListing models...")
    models = client.list_models()
    if not models:
        print("No models found")
    else:
        for model in models:
            print(f"- {model.name} ({model.id})")
            print(f"  Size: {model.size} bytes")
            print(f"  Encrypted with SE: {model.encrypted_with_se}")
    
    # Store a model
    print("\nStoring a test model...")
    test_data = b"This is test model data"
    model_id = client.store_model(
        "test-model-python",
        test_data,
        ModelFormat.SAFETENSORS
    )
    print(f"✅ Model stored with ID: {model_id}")
    
    # Get model info
    print("\nGetting model info...")
    model_info = client.get_model(model_id)
    print(f"Model: {model_info.name}")
    print(f"Created: {model_info.created_at}")
    
    # Alternative: Use connect helper
    print("\n--- Using connect helper ---")
    client2 = connect("http://localhost:8080", "admin", "changeme")
    models2 = client2.list_models()
    print(f"Found {len(models2)} models")


if __name__ == "__main__":
    main()