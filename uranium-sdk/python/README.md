# Uranium Python SDK

Python client library for [Uranium Vault](https://github.com/haasonsaas/uranium) - secure storage for LLM weights.

## Installation

```bash
pip install uranium-sdk
```

## Quick Start

```python
from uranium_sdk import VaultClient, ModelFormat

# Connect to vault
client = VaultClient("http://localhost:8080")
client.authenticate("username", "password")

# List models
models = client.list_models()
for model in models:
    print(f"{model.name} - {model.size} bytes")

# Store a model
with open("model.safetensors", "rb") as f:
    data = f.read()

model_id = client.store_model(
    "my-llm-v1",
    data,
    ModelFormat.SAFETENSORS
)
print(f"Model stored with ID: {model_id}")

# Get model info
info = client.get_model(model_id)
print(f"Created at: {info.created_at}")
print(f"Encrypted with Secure Enclave: {info.encrypted_with_se}")
```

## Features

- 🔐 Secure authentication with JWT tokens
- 🚀 Simple API for model storage and retrieval
- 🔒 Hardware-backed encryption support (Secure Enclave on macOS)
- 📊 Model metadata and listing
- ⚡ Fast and efficient

## API Reference

### VaultClient

The main client class for interacting with Uranium Vault.

#### Methods

- `authenticate(username, password)` - Authenticate with the vault
- `store_model(name, data, format)` - Store a model
- `store_model_from_file(path, name, format)` - Store a model from file
- `list_models()` - List all models
- `get_model(model_id)` - Get model metadata
- `load_model(model_id)` - Load model data
- `delete_model(model_id)` - Delete a model
- `status()` - Get vault status

### Model Formats

- `ModelFormat.SAFETENSORS` - SafeTensors format
- `ModelFormat.ONNX` - ONNX format
- `ModelFormat.PYTORCH` - PyTorch format
- `ModelFormat.TENSORFLOW` - TensorFlow format

## Advanced Usage

### Using the connect helper

```python
from uranium_sdk import connect

# Connect and authenticate in one step
client = connect("http://localhost:8080", "username", "password")
```

### Handling errors

```python
try:
    client.authenticate("user", "wrong_password")
except RuntimeError as e:
    print(f"Authentication failed: {e}")
```

## Development

To install for development:

```bash
git clone https://github.com/haasonsaas/uranium.git
cd uranium/uranium-sdk/python
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

## License

MIT License - see LICENSE file for details.