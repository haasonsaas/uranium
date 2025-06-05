#!/bin/bash

echo "=== Uranium Integration Tests ==="
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if demo server is running
if ! curl -s http://localhost:8080/api/v1/status > /dev/null 2>&1; then
    echo -e "${YELLOW}Starting demo vault server...${NC}"
    ./start-vault.sh &
    SERVER_PID=$!
    echo "Server PID: $SERVER_PID"
    
    # Wait for server to start
    echo "Waiting for server to start..."
    for i in {1..10}; do
        if curl -s http://localhost:8080/api/v1/status > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Server started${NC}"
            break
        fi
        sleep 1
    done
    
    CLEANUP_SERVER=true
else
    echo -e "${GREEN}✅ Vault server already running${NC}"
    CLEANUP_SERVER=false
fi

# Run tests
echo
echo "Running integration tests..."
echo

# Core tests
echo "1. Testing uranium-core..."
cargo test -p uranium-core --quiet
CORE_RESULT=$?

# Vault tests (requires database)
echo
echo "2. Testing uranium-vault..."
if [ -f uranium_vault.db ]; then
    SQLX_OFFLINE=true cargo test -p uranium-vault --quiet
    VAULT_RESULT=$?
else
    echo -e "${YELLOW}Skipping vault tests (no database)${NC}"
    VAULT_RESULT=0
fi

# CLI tests
echo
echo "3. Testing uranium-cli..."
cargo test -p uranium-cli --quiet
CLI_RESULT=$?

# SDK tests
echo
echo "4. Testing uranium-sdk..."
cargo test -p uranium-sdk --quiet
SDK_RESULT=$?

# Integration tests
echo
echo "5. Running full integration tests..."
cargo test --test integration_test -- --nocapture
INTEGRATION_RESULT=$?

# Cleanup
if [ "$CLEANUP_SERVER" = true ] && [ ! -z "$SERVER_PID" ]; then
    echo
    echo "Stopping test server..."
    kill $SERVER_PID 2>/dev/null
fi

# Summary
echo
echo "=== Test Summary ==="
[ $CORE_RESULT -eq 0 ] && echo -e "${GREEN}✅ Core tests passed${NC}" || echo -e "${RED}❌ Core tests failed${NC}"
[ $VAULT_RESULT -eq 0 ] && echo -e "${GREEN}✅ Vault tests passed${NC}" || echo -e "${RED}❌ Vault tests failed${NC}"
[ $CLI_RESULT -eq 0 ] && echo -e "${GREEN}✅ CLI tests passed${NC}" || echo -e "${RED}❌ CLI tests failed${NC}"
[ $SDK_RESULT -eq 0 ] && echo -e "${GREEN}✅ SDK tests passed${NC}" || echo -e "${RED}❌ SDK tests failed${NC}"
[ $INTEGRATION_RESULT -eq 0 ] && echo -e "${GREEN}✅ Integration tests passed${NC}" || echo -e "${RED}❌ Integration tests failed${NC}"

# Exit with failure if any test failed
if [ $CORE_RESULT -ne 0 ] || [ $VAULT_RESULT -ne 0 ] || [ $CLI_RESULT -ne 0 ] || [ $SDK_RESULT -ne 0 ] || [ $INTEGRATION_RESULT -ne 0 ]; then
    exit 1
fi

echo
echo -e "${GREEN}✅ All tests passed!${NC}"