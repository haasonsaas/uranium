#!/bin/bash

# Demo script for testing auth/audit integration

echo "=== Uranium Auth/Audit Demo ==="
echo

# Start the production vault server
echo "Starting production vault server..."
echo "Building server..."
SQLX_OFFLINE=true cargo build -p uranium-vault --bin uranium-vault-server --quiet

# Create config file
cat > uranium_test.toml << EOF
[server]
host = "127.0.0.1"
port = 8443

[storage]
base_path = "./test_vault"
database_url = "sqlite://test_vault.db"

[security]
encryption_algorithm = "ChaCha20Poly1305"
hash_algorithm = "Blake3"
enable_memory_protection = true
enable_secure_enclave = true

[auth]
jwt_secret = "test-secret-change-in-production"
token_duration_hours = 24

[cache]
size_mb = 100
EOF

# Run server in background
echo "Starting server..."
RUST_LOG=info ./target/debug/uranium-vault-server --config uranium_test.toml &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
echo "Waiting for server to start..."
sleep 3

# Test authentication
echo
echo "1. Testing authentication..."
echo "Logging in as admin..."
TOKEN=$(curl -s -X POST http://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq -r '.token')

if [ "$TOKEN" != "null" ] && [ ! -z "$TOKEN" ]; then
    echo "✅ Login successful!"
    echo "Token: ${TOKEN:0:20}..."
else
    echo "❌ Login failed"
fi

# Test protected endpoint
echo
echo "2. Testing protected endpoint..."
curl -s -X GET http://localhost:8443/api/v1/models \
  -H "Authorization: Bearer $TOKEN" | jq

# Test audit log
echo
echo "3. Checking audit log..."
echo "SELECT * FROM audit_log LIMIT 5;" | sqlite3 test_vault.db -header -column

# Cleanup
echo
echo "Cleaning up..."
kill $SERVER_PID 2>/dev/null
rm -f uranium_test.toml test_vault.db test_vault.db-shm test_vault.db-wal
rm -rf test_vault/

echo "✅ Demo completed!"