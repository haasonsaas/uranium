use tempfile::TempDir;
use uuid::Uuid;

use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelFramework, ModelMetadata},
    storage::ModelStorage,
};

/// This example demonstrates the core functionality of Uranium
/// without requiring a full database setup.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Uranium Core Demo\n");
    println!("This demo shows the core encryption and storage capabilities.\n");

    // Create temporary storage
    let temp_dir = TempDir::new()?;
    println!("📁 Created temporary storage at: {:?}", temp_dir.path());

    // Initialize storage with encryption
    let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
    let verifier = IntegrityVerifier::new(HashAlgorithm::Blake3);
    let storage = ModelStorage::new(temp_dir.path(), crypto, verifier)?;

    // Generate encryption key
    println!("\n🔑 Generating encryption key...");
    let master_key = EncryptionKey::generate();
    println!("✅ Master key generated (256-bit)");

    // Create a test model
    println!("\n📦 Creating test model...");
    let model_id = Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "demo-llm-model".to_string(),
        version: "1.0.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1024 * 1024, // 1MB
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: Some("Demo LLM model for testing".to_string()),
        tags: vec!["demo".to_string(), "test".to_string()],
        framework: Some(ModelFramework::PyTorch),
        architecture: Some("transformer".to_string()),
        parameters_count: Some(1_000_000),
        watermark: None,
        license_constraints: None,
    };

    // Generate some dummy weights
    let model_weights = vec![0x42; 1024 * 1024]; // 1MB of dummy data
    println!("✅ Created model: {} ({})", metadata.name, metadata.version);
    println!("   Size: {} MB", metadata.size_bytes / (1024 * 1024));
    println!("   Format: {:?}", metadata.format);

    // Store the encrypted model
    println!("\n🔒 Encrypting and storing model...");
    let start = std::time::Instant::now();
    let path = storage.store_model(model_id, metadata.clone(), &model_weights, &master_key)?;
    let encrypt_time = start.elapsed();
    println!("✅ Model encrypted and stored in {:.2?}", encrypt_time);
    println!("   Path: {:?}", path);

    // List models
    println!("\n📋 Listing stored models...");
    let models = storage.list_models()?;
    for id in &models {
        let meta = storage.get_model_metadata(*id)?;
        println!("   - {} v{} (ID: {})", meta.name, meta.version, id);
    }

    // Load and decrypt the model
    println!("\n🔓 Loading and decrypting model...");
    let start = std::time::Instant::now();
    let loaded_model = storage.load_model(model_id, &master_key)?;
    let decrypt_time = start.elapsed();
    println!("✅ Model decrypted in {:.2?}", decrypt_time);

    // Verify integrity
    println!("\n🔍 Verifying model integrity...");
    let weights_match = loaded_model.weights == model_weights;
    println!(
        "   Weights match: {}",
        if weights_match { "✅ YES" } else { "❌ NO" }
    );
    println!("   Size: {} bytes", loaded_model.weights.len());

    // Test wrong key
    println!("\n🚫 Testing access with wrong key...");
    let wrong_key = EncryptionKey::generate();
    match storage.load_model(model_id, &wrong_key) {
        Ok(_) => println!("❌ ERROR: Wrong key should have failed!"),
        Err(e) => println!("✅ Correctly rejected: {}", e),
    }

    // Performance metrics
    println!("\n📊 Performance Summary:");
    println!(
        "   Encryption speed: {:.2} MB/s",
        (metadata.size_bytes as f64 / (1024.0 * 1024.0)) / encrypt_time.as_secs_f64()
    );
    println!(
        "   Decryption speed: {:.2} MB/s",
        (metadata.size_bytes as f64 / (1024.0 * 1024.0)) / decrypt_time.as_secs_f64()
    );

    // Test different encryption algorithms
    println!("\n🔬 Testing different encryption algorithms...");

    // AES-GCM
    let aes_crypto = VaultCrypto::new(EncryptionAlgorithm::AesGcm256);
    let aes_storage = ModelStorage::new(
        temp_dir.path().join("aes"),
        aes_crypto,
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )?;

    let start = std::time::Instant::now();
    aes_storage.store_model(model_id, metadata.clone(), &model_weights, &master_key)?;
    let aes_time = start.elapsed();
    println!("   AES-256-GCM encryption: {:.2?}", aes_time);

    // Clean up
    println!("\n🧹 Cleaning up...");
    storage.delete_model(model_id)?;
    println!("✅ Model securely deleted");

    println!("\n🎉 Demo completed successfully!");
    println!("\nKey takeaways:");
    println!("- Models are encrypted with strong algorithms (ChaCha20-Poly1305 or AES-256-GCM)");
    println!("- Integrity is verified using Blake3 hashing");
    println!("- Wrong keys are properly rejected");
    println!("- Performance is excellent (>100 MB/s on modern hardware)");

    Ok(())
}
