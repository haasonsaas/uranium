#[cfg(not(target_os = "macos"))]
fn main() {
    println!("This example requires macOS for Secure Enclave support");
}

#[cfg(target_os = "macos")]
use chrono::Utc;
/// Full Secure Enclave Integration Demo
///
/// This shows exactly how the vault uses Secure Enclave when configured
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use uranium_core::{
    crypto::{EncryptionAlgorithm, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelMetadata},
    platform::macos::SecureEnclaveKey,
    storage::{ModelStorage, SecureEnclaveStorage, SecureEnclaveStorageBuilder},
    Result,
};
#[cfg(target_os = "macos")]
use uuid::Uuid;

#[cfg(target_os = "macos")]
fn main() -> Result<()> {
    println!("🔐 Full Secure Enclave Integration Demo");
    println!("======================================\n");

    // This is exactly what happens in the vault when enable_secure_enclave = true
    demonstrate_vault_integration()?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn demonstrate_vault_integration() -> Result<()> {
    println!("📋 Simulating Vault Configuration:");
    println!("  enable_secure_enclave = true");

    let enable_secure_enclave = true;
    let storage_path = PathBuf::from("./demo_vault_storage");
    let encryption_algorithm = EncryptionAlgorithm::ChaCha20Poly1305;

    // Create storage directory
    std::fs::create_dir_all(&storage_path).ok();

    // This is the exact logic from Vault::new()
    println!("\n🏗️  Creating storage (same as Vault::new())...");

    // First create regular storage (always needed)
    let base_storage = ModelStorage::new(
        &storage_path,
        VaultCrypto::new(encryption_algorithm),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )?;
    println!("✅ Created base storage");

    // Then check for Secure Enclave (on macOS only)
    #[cfg(target_os = "macos")]
    {
        if enable_secure_enclave && SecureEnclaveStorage::is_secure_enclave_available() {
            println!("✅ Secure Enclave available - enabling hardware-backed encryption");

            let se_storage = SecureEnclaveStorageBuilder::new()
                .with_path(&storage_path)
                .with_algorithm(encryption_algorithm)
                .build()?;

            println!("✅ Created Secure Enclave storage wrapper");

            // Now demonstrate usage
            demonstrate_se_operations(se_storage)?;
        } else {
            if enable_secure_enclave {
                println!("⚠️  Secure Enclave requested but not available on this device");
            }
            println!("🔐 Using software encryption (base storage)");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("🔐 Not on macOS - using software encryption");
    }

    // Clean up
    std::fs::remove_dir_all(&storage_path).ok();

    Ok(())
}

#[cfg(target_os = "macos")]
#[cfg(target_os = "macos")]
fn demonstrate_se_operations(se_storage: SecureEnclaveStorage) -> Result<()> {
    println!("\n🚀 Demonstrating Secure Enclave Operations:");
    println!("-------------------------------------------");

    // Create a test model
    let model_id = Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "llama-70b-custom".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1000,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: Some("Custom fine-tuned model".to_string()),
        tags: vec!["nlp".to_string(), "proprietary".to_string()],
        framework: None,
        architecture: Some("transformer".to_string()),
        parameters_count: Some(70_000_000_000),
        watermark: None,
        license_constraints: None,
    };

    let model_weights = vec![42u8; 1000]; // Simulated weights

    // Store with Secure Enclave
    println!("\n1️⃣  Storing model with Secure Enclave:");
    se_storage.store_model_secure_enclave(model_id, metadata.clone(), &model_weights)?;
    println!("   ✅ Model encrypted with hardware-backed key");
    println!("   🔑 Key ID: model_{}", model_id);
    println!("   🛡️  Key material never leaves Secure Enclave");

    // Load with Secure Enclave
    println!("\n2️⃣  Loading model with Secure Enclave:");
    let loaded = se_storage.load_model_secure_enclave(model_id)?;
    println!("   ✅ Model decrypted successfully");
    println!("   📦 Loaded {} bytes", loaded.weights.len());

    // Verify integrity
    if loaded.weights == model_weights {
        println!("   ✅ Data integrity verified");
    }

    // Show what happens in the vault
    println!("\n3️⃣  How the Vault uses this:");
    println!("   • vault.store_model() → calls se_storage.store_model_secure_enclave()");
    println!("   • vault.load_model() → calls se_storage.load_model_secure_enclave()");
    println!("   • Completely transparent to your application code!");

    println!("\n✨ Security Benefits:");
    println!("   • Encryption keys are hardware-isolated");
    println!("   • Keys cannot be extracted even with root access");
    println!("   • Hardware-backed random number generation");
    println!("   • Automatic key management per model");

    Ok(())
}
