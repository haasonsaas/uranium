#!/bin/bash

echo "🧪 Running Uranium Tests"
echo "======================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests for a crate
run_crate_tests() {
    local crate=$1
    echo -e "\n${YELLOW}Testing $crate...${NC}"
    
    if cargo test -p $crate --all-features; then
        echo -e "${GREEN}✓ $crate tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $crate tests failed${NC}"
        return 1
    fi
}

# Track failures
FAILED=0

# Run tests for each crate
for crate in uranium-core uranium-vault uranium-cli; do
    if ! run_crate_tests $crate; then
        FAILED=$((FAILED + 1))
    fi
done

# Run integration tests
echo -e "\n${YELLOW}Running integration tests...${NC}"
if cargo test --all --all-features -- --test-threads=1; then
    echo -e "${GREEN}✓ Integration tests passed${NC}"
else
    echo -e "${RED}✗ Integration tests failed${NC}"
    FAILED=$((FAILED + 1))
fi

# Run benchmarks (just compile, don't run)
echo -e "\n${YELLOW}Checking benchmarks compile...${NC}"
if cargo bench --no-run -p uranium-core; then
    echo -e "${GREEN}✓ Benchmarks compile${NC}"
else
    echo -e "${RED}✗ Benchmarks failed to compile${NC}"
    FAILED=$((FAILED + 1))
fi

# Check formatting
echo -e "\n${YELLOW}Checking code formatting...${NC}"
if cargo fmt --all -- --check; then
    echo -e "${GREEN}✓ Code formatting is correct${NC}"
else
    echo -e "${RED}✗ Code needs formatting (run: cargo fmt)${NC}"
    FAILED=$((FAILED + 1))
fi

# Run clippy
echo -e "\n${YELLOW}Running clippy...${NC}"
if cargo clippy --all --all-features -- -D warnings; then
    echo -e "${GREEN}✓ Clippy checks passed${NC}"
else
    echo -e "${RED}✗ Clippy found issues${NC}"
    FAILED=$((FAILED + 1))
fi

# Summary
echo -e "\n${YELLOW}Test Summary${NC}"
echo "============"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! 🎉${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test suites failed 😞${NC}"
    exit 1
fi