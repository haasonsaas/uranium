use uranium_core::platform::get_platform_security;
#[cfg(target_os = "macos")]
use uranium_core::{
    crypto::EncryptionAlgorithm,
    models::{LicenseConstraints, ModelFormat, ModelFramework, ModelMetadata},
    Result,
};

#[cfg(target_os = "macos")]
use uranium_core::{
    platform::{SecureEnclaveKey, SecureEnclaveManager},
    storage::secure_enclave_storage::SecureEnclaveStorageBuilder,
};

fn main() -> uranium_core::Result<()> {
    println!("🔐 Uranium Secure Enclave Demo");
    println!("================================\n");

    // Check platform security features
    let platform = get_platform_security();
    println!("Platform Security Features:");
    println!(
        "  • Hardware security: {}",
        if platform.has_hardware_security() {
            "✅ Available"
        } else {
            "❌ Not available"
        }
    );

    #[cfg(target_os = "macos")]
    {
        println!(
            "  • Secure Enclave: {}",
            if SecureEnclaveKey::is_available() {
                "✅ Available"
            } else {
                "❌ Not available"
            }
        );

        if SecureEnclaveKey::is_available() {
            run_secure_enclave_demo()?;
        } else {
            println!("\n⚠️  Secure Enclave not available on this device");
            println!("   (Requires Apple Silicon Mac or Intel Mac with T2 chip)");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("\n⚠️  Secure Enclave is only available on macOS");
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn test_secure_enclave_keys() -> uranium_core::Result<()> {
    println!("\n1️⃣  Testing Secure Enclave Key Generation");

    let key_id = "demo_se_key";

    // Generate a key in Secure Enclave
    let se_key = SecureEnclaveKey::generate(key_id)?;
    println!("   ✅ Generated key in Secure Enclave");

    // Test encryption/decryption
    let plaintext = b"Ultra-secret LLM architecture details!";
    let ciphertext = se_key.encrypt(plaintext)?;
    println!("   ✅ Encrypted {} bytes with SE key", plaintext.len());

    let decrypted = se_key.decrypt(&ciphertext)?;
    assert_eq!(plaintext, &decrypted[..]);
    println!("   ✅ Decrypted successfully - data integrity verified");

    // Clean up
    SecureEnclaveKey::delete(key_id)?;
    println!("   ✅ Cleaned up SE key");

    Ok(())
}

#[cfg(target_os = "macos")]
fn test_secure_enclave_storage() -> uranium_core::Result<()> {
    println!("\n2️⃣  Testing Secure Enclave Model Storage");

    // Create temporary storage directory
    let temp_dir = tempfile::tempdir()
        .map_err(|e| uranium_core::UraniumError::Storage(std::io::Error::other(e)))?;

    // Build SE storage
    let storage = SecureEnclaveStorageBuilder::new()
        .with_path(temp_dir.path())
        .with_algorithm(EncryptionAlgorithm::ChaCha20Poly1305)
        .build()?;
    println!("   ✅ Created Secure Enclave storage");

    // Create test model
    let model_id = uuid::Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "gpt-4-turbo-custom".to_string(),
        version: "2.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1_000_000, // 1MB test model
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: Some("Custom fine-tuned GPT-4 Turbo model".to_string()),
        tags: vec!["nlp".to_string(), "proprietary".to_string()],
        framework: Some(ModelFramework::PyTorch),
        architecture: Some("transformer".to_string()),
        parameters_count: Some(1_700_000_000), // 1.7B parameters
        watermark: Some("uranium-secured".as_bytes().to_vec()),
        license_constraints: Some(LicenseConstraints {
            max_instances: Some(1),
            expiration_date: None,
            allowed_hosts: Some(vec!["internal-server".to_string()]),
            usage_quota: None,
            restricted_operations: vec!["commercial_use".to_string()],
        }),
    };

    // Simulate model weights (normally would be actual tensor data)
    let model_weights = vec![0x42u8; 1_000_000]; // 1MB of "weights"

    // Store with Secure Enclave
    storage.store_model_secure_enclave(model_id, metadata.clone(), &model_weights)?;
    println!("   ✅ Stored 1MB model with SE encryption");

    // Load back
    let loaded = storage.load_model_secure_enclave(model_id)?;
    println!("   ✅ Loaded model with SE decryption");

    // Verify
    assert_eq!(loaded.metadata.name, "gpt-4-turbo-custom");
    assert_eq!(loaded.weights.len(), 1_000_000);
    println!("   ✅ Model integrity verified");

    Ok(())
}

#[cfg(target_os = "macos")]
fn test_key_migration() -> uranium_core::Result<()> {
    println!("\n3️⃣  Testing Key Migration to Secure Enclave");

    // Simulate existing software-encrypted model
    let mut se_manager = SecureEnclaveManager::new();

    // Generate software key (simulating existing encryption)
    let software_key = se_manager.get_or_generate_key("legacy_software_key")?;
    println!(
        "   ✅ Generated legacy software key: {} bytes",
        software_key.len()
    );

    // Migrate to Secure Enclave
    let se_key = se_manager.get_or_generate_key("migrated_se_key")?;
    println!("   ✅ Generated new SE-backed key: {} bytes", se_key.len());

    // In production, you would:
    // 1. Decrypt models with software_key
    // 2. Re-encrypt with se_key
    // 3. Update key references in database

    println!("   ✅ Migration path demonstrated");

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_secure_enclave_demo() -> uranium_core::Result<()> {
    unreachable!("This function should only be called on macOS");
}
