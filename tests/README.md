# Integration Tests

This directory contains integration tests for the Uranium project.

To run these tests locally:

```bash
# Start the demo vault server first
./start-vault.sh

# In another terminal, run the tests
cargo test --test integration_test
```

Note: The integration tests require the demo vault server to be running as they test the full system including API endpoints.