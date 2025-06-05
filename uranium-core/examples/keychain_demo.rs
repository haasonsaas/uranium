use chrono::Utc;
use std::sync::Arc;
use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelMetadata},
    platform::get_platform_security,
    storage::{secure::SecureModelStorage, ModelStorage},
    Result, UraniumError,
};
use uuid::Uuid;

fn main() -> Result<()> {
    // Initialize simple logging
    println!("🔐 Uranium Keychain Integration Demo");
    println!("=====================================\n");

    // Get platform security features
    let platform = Arc::new(get_platform_security());

    println!("Platform Security Status:");
    println!(
        "  • Hardware security: {}",
        if platform.has_hardware_security() {
            "✅ Available"
        } else {
            "❌ Not available"
        }
    );
    println!();

    // Test Keychain integration
    test_keychain_integration(&platform)?;

    // Test secure model storage with Keychain
    test_secure_model_with_keychain(&platform)?;

    println!("\n✅ All Keychain integration tests passed!");

    Ok(())
}

fn test_keychain_integration(
    platform: &Arc<Box<dyn uranium_core::platform::PlatformSecurity>>,
) -> Result<()> {
    println!("📋 Testing Keychain Operations");
    println!("------------------------------");

    let test_key_id = "demo_master_key";
    let test_key_data = b"super_secret_master_key_32_bytes";

    // Store key in Keychain
    println!("1. Storing master key in Keychain...");
    platform.store_hardware_key(test_key_id, test_key_data)?;
    println!("   ✅ Key stored successfully");

    // Retrieve key from Keychain
    println!("2. Retrieving key from Keychain...");
    let retrieved_key = platform.get_hardware_key(test_key_id)?;
    println!("   ✅ Key retrieved successfully");

    // Verify key matches
    if retrieved_key == test_key_data {
        println!("   ✅ Retrieved key matches original");
    } else {
        println!("   ❌ Key mismatch!");
        return Err(uranium_core::UraniumError::Internal(
            "Key mismatch".to_string(),
        ));
    }

    // Test key persistence (simulating app restart)
    println!("3. Testing key persistence...");
    drop(platform.clone());
    let new_platform = Arc::new(get_platform_security());
    let persistent_key = new_platform.get_hardware_key(test_key_id)?;

    if persistent_key == test_key_data {
        println!("   ✅ Key persists across sessions");
    } else {
        println!("   ❌ Key not persistent!");
        return Err(uranium_core::UraniumError::Internal(
            "Key not persistent".to_string(),
        ));
    }

    Ok(())
}

fn test_secure_model_with_keychain(
    platform: &Arc<Box<dyn uranium_core::platform::PlatformSecurity>>,
) -> Result<()> {
    println!("\n🔒 Testing Secure Model Storage with Keychain");
    println!("-------------------------------------------");

    // Create test directory
    let test_dir =
        tempfile::tempdir().map_err(|e| UraniumError::Storage(std::io::Error::other(e)))?;
    let storage_path = test_dir.path();

    // Initialize crypto components
    let vault_crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
    let integrity = IntegrityVerifier::new(HashAlgorithm::Blake3);

    // Initialize storage
    let storage = ModelStorage::new(storage_path, vault_crypto, integrity)?;
    let secure_storage = SecureModelStorage::new(storage);

    // Generate a master key and store it in Keychain
    println!("1. Generating and storing vault master key...");
    let master_key = EncryptionKey::generate();

    // Store master key in Keychain
    let vault_key_id = "uranium_vault_master";
    platform.store_hardware_key(vault_key_id, master_key.as_bytes())?;
    println!("   ✅ Master key stored in Keychain");

    // Create test model data
    let model_id = Uuid::new_v4();
    let test_weights = vec![0.1f32, 0.2, 0.3, 0.4, 0.5];
    let test_data =
        bincode::serialize(&test_weights).map_err(|e| UraniumError::Internal(e.to_string()))?;

    // Create metadata
    let metadata = ModelMetadata {
        id: model_id,
        name: "llama-7b".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: test_data.len() as u64,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: Some("Test model for Keychain demo".to_string()),
        tags: vec!["demo".to_string(), "test".to_string()],
        framework: None,
        architecture: Some("transformer".to_string()),
        parameters_count: Some(7_000_000_000),
        watermark: None,
        license_constraints: None,
    };

    // Store model (key is retrieved from Keychain internally)
    println!("2. Storing encrypted model...");
    let stored_key = platform.get_hardware_key(vault_key_id)?;
    let encryption_key = EncryptionKey::from_bytes(&stored_key)?;
    secure_storage.store_model_secure(model_id, metadata, &test_data, &encryption_key)?;
    println!("   ✅ Model encrypted and stored");

    // Simulate app restart - retrieve key from Keychain
    println!("3. Simulating app restart...");
    drop(encryption_key);

    // Retrieve key from Keychain and load model
    println!("4. Loading model with key from Keychain...");
    let keychain_key = platform.get_hardware_key(vault_key_id)?;
    let encryption_key = EncryptionKey::from_bytes(&keychain_key)?;
    let secure_model = secure_storage.load_model_secure(model_id, &encryption_key)?;

    // Verify model data
    let decrypted_weights: Vec<f32> = bincode::deserialize(secure_model.weights())
        .map_err(|e| UraniumError::Internal(e.to_string()))?;
    if decrypted_weights == test_weights {
        println!("   ✅ Model loaded and decrypted successfully");
        println!("   ✅ Data integrity verified");
    } else {
        println!("   ❌ Model data corrupted!");
        return Err(uranium_core::UraniumError::Internal(
            "Data corruption".to_string(),
        ));
    }

    // Demonstrate key rotation
    println!("\n5. Testing key rotation...");
    let new_master_key = EncryptionKey::generate();

    // Update key in Keychain
    platform.store_hardware_key(vault_key_id, new_master_key.as_bytes())?;
    println!("   ✅ New master key stored in Keychain");

    // Re-encrypt model with new key would happen here
    println!("   ℹ️  In production, all models would be re-encrypted");

    Ok(())
}
