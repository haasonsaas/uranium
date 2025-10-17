# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Uranium, please report it by emailing the maintainers directly. Please do not open a public issue.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Known Issues

### RUSTSEC-2023-0071: RSA Marvin Attack (Medium Severity)

**Status:** Acknowledged, monitoring for fix

**Details:**
- **Crate:** `rsa` v0.9.8
- **Severity:** 5.9 (Medium)
- **Impact:** Potential key recovery through timing sidechannels
- **Advisory:** https://rustsec.org/advisories/RUSTSEC-2023-0071

**Why This Is Accepted:**

This vulnerability exists in the `rsa` crate v0.9.8, which is pulled in as a transitive dependency through `sqlx-mysql` → `sqlx-macros`. However:

1. **We don't use MySQL**: Uranium only uses SQLite for database operations
2. **Not in runtime path**: The `rsa` crate is only pulled in by sqlx's macro expansion system and is not used in any runtime code paths
3. **No fix available**: There is currently no patched version of the `rsa` crate available
4. **Low actual risk**: Since we don't use MySQL authentication or any RSA-based cryptography features, the attack surface is not present in our application

**Mitigation:**

We are monitoring this issue and will update dependencies once a fix is available. The vulnerability is documented in `.cargo/audit.toml` and is explicitly allowed in our security audit configuration.

**Timeline:**
- Identified: 2025-10-17
- Next review: When sqlx or rsa releases updates

## Security Best Practices

When using Uranium:

1. **Secrets Management:** Never commit encryption keys, API tokens, or sensitive configuration to version control
2. **Secure Enclave (macOS):** Use the Secure Enclave features when available for hardware-backed key storage
3. **Access Controls:** Implement proper authentication and authorization in vault deployments
4. **Network Security:** Always use TLS/HTTPS for vault API communications
5. **Regular Updates:** Keep Uranium and its dependencies up to date
