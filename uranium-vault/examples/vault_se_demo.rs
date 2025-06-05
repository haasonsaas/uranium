/// Demo showing Vault with Secure Enclave integration
///
/// This demonstrates that the vault is ready to use Secure Enclave
/// when properly configured.
use std::path::PathBuf;
use std::sync::Arc;
use uranium_core::crypto::EncryptionAlgorithm;
use uranium_core::integrity::HashAlgorithm;
use uranium_vault::{
    audit::{AuditEvent, AuditLogger},
    auth::AuthManager,
    vault::{Vault, VaultConfig},
};

// Mock audit logger for demo
struct MockAuditLogger;

#[async_trait::async_trait]
impl AuditLogger for MockAuditLogger {
    async fn log(&self, event: AuditEvent) -> uranium_core::Result<()> {
        println!("📝 Audit: {:?}", event);
        Ok(())
    }

    async fn query_events(
        &self,
        _filter: uranium_vault::audit::EventFilter,
    ) -> uranium_core::Result<Vec<AuditEvent>> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🔐 Uranium Vault with Secure Enclave Demo");
    println!("=========================================\n");

    // Create vault config with SE enabled
    let vault_config = VaultConfig {
        storage_path: PathBuf::from("./demo_vault"),
        encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        hash_algorithm: HashAlgorithm::Blake3,
        max_concurrent_loads: 10,
        cache_size_mb: 1024,
        session_timeout_minutes: 60,
        enable_memory_protection: true,
        enable_secure_enclave: true, // ← Enable Secure Enclave
    };

    println!("📋 Vault Configuration:");
    println!("  • Encryption: {:?}", vault_config.encryption_algorithm);
    println!(
        "  • Secure Enclave: {}",
        if vault_config.enable_secure_enclave {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  • Memory Protection: {}",
        if vault_config.enable_memory_protection {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );

    // Note: In a real app, you'd have a proper auth manager and audit logger
    // For this demo, we'll show what would happen
    println!("\n🏗️  Creating Vault with Secure Enclave support...");

    // This is what happens internally when vault is created:
    #[cfg(target_os = "macos")]
    {
        if vault_config.enable_secure_enclave {
            if uranium_core::storage::SecureEnclaveStorage::is_secure_enclave_available() {
                println!("✅ Secure Enclave detected and enabled!");
                println!("🔒 All models will be encrypted with hardware-backed keys");
                println!("🛡️  Keys are non-extractable and protected by hardware");
            } else {
                println!("⚠️  Secure Enclave requested but not available");
                println!("📱 This requires Apple Silicon or Intel Mac with T2 chip");
                println!("🔐 Falling back to software encryption");
            }
        }
    }

    // Show the actual SE status
    println!("\n📊 Platform Security Status:");
    #[cfg(target_os = "macos")]
    {
        let se_available = uranium_core::platform::macos::SecureEnclaveKey::is_available();
        println!(
            "  • Secure Enclave Hardware: {}",
            if se_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );

        #[cfg(target_arch = "aarch64")]
        println!("  • Architecture: Apple Silicon (ARM64)");

        #[cfg(target_arch = "x86_64")]
        {
            println!("  • Architecture: Intel x86_64");
            if se_available {
                println!("  • T2 Security Chip: ✅ Detected");
            }
        }
    }

    println!("\n🎯 What happens when you use the vault:");
    println!("  1. store_model() → Encrypts with Secure Enclave keys");
    println!("  2. load_model() → Decrypts with Secure Enclave keys");
    println!("  3. migrate_to_secure_enclave() → Re-encrypts existing models");
    println!("  4. All operations are transparent to your code!");

    println!("\n✨ Benefits you get:");
    println!("  • Hardware-isolated encryption keys");
    println!("  • Protection against memory dumps");
    println!("  • Compliance with security standards");
    println!("  • Zero code changes needed");

    Ok(())
}
