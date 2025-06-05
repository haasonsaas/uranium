#!/bin/bash

# Uranium Vault Startup Script with Secure Enclave
# ================================================

set -e

echo "🔐 Uranium Vault Startup"
echo "======================="
echo ""

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "✅ Running on macOS"
    
    # Check architecture
    if [[ $(uname -m) == "arm64" ]]; then
        echo "✅ Apple Silicon detected - Secure Enclave available"
    else
        echo "ℹ️  Intel Mac detected - checking for T2 chip..."
    fi
else
    echo "⚠️  Not running on macOS - Secure Enclave unavailable"
fi

echo ""

# Configuration
export RUST_LOG=uranium_vault_demo=info,uranium_vault=info,uranium_core=info

# Check if config exists
if [ ! -f uranium.toml ]; then
    # Check if example exists
    if [ -f examples/uranium.toml.example ]; then
        echo "📝 Copying example configuration..."
        cp examples/uranium.toml.example uranium.toml
        echo "✅ Configuration copied from examples/uranium.toml.example"
    else
        echo "📝 Creating default configuration..."
        cat > uranium.toml << 'EOF'
[server]
host = "127.0.0.1"
port = 8080

[security]
encryption_algorithm = "ChaCha20Poly1305"
hash_algorithm = "Blake3"
enable_memory_protection = true
enable_secure_enclave = true  # Enable hardware-backed encryption on macOS
master_key_source = "Environment"
require_mfa = false

[storage]
base_path = "./vault/models"
database_url = "sqlite://vault.db?mode=rwc"
enable_compression = false
chunk_size_mb = 64

[auth]
jwt_secret = "change-me-in-production-use-long-random-string"
token_duration_hours = 24
session_timeout_minutes = 60
max_sessions_per_user = 5

[auth.password_requirements]
min_length = 12
require_uppercase = true
require_lowercase = true
require_numbers = true
require_special_chars = true

[audit]
backend = { tag = "Database" }
retention_days = 90
enable_security_monitoring = true

[performance]
cache_size_mb = 1024
max_concurrent_loads = 10
enable_metrics = true
metrics_port = 9090
EOF
        echo "✅ Configuration created"
    fi
fi

# Check which server to run
if command -v uranium-vault-server &> /dev/null; then
    echo "🚀 Starting production vault server..."
    echo ""
    uranium-vault-server
elif [ -f target/debug/uranium-vault-demo ]; then
    echo "🚀 Starting demo vault server..."
    echo ""
    echo "Server endpoints:"
    echo "  • Status: http://localhost:8080/api/v1/status"
    echo "  • Models: http://localhost:8080/api/v1/models"
    echo ""
    cargo run -p uranium-vault-demo
else
    echo "❌ No vault server found!"
    echo ""
    echo "To build the demo server:"
    echo "  cargo build -p uranium-vault-demo"
    echo ""
    echo "To build the production server:"
    echo "  cargo build --bin uranium-vault-server"
    exit 1
fi