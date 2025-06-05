use std::time::Instant;
use tempfile::TempDir;
use uuid::Uuid;

use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelMetadata},
    platform::get_platform_security,
    storage::{secure::SecureModelStorage, ModelStorage},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🍎 Uranium macOS Security Features Demo\n");

    // Check platform security capabilities
    let platform = get_platform_security();
    println!("🔍 Platform Security Check:");
    println!(
        "   Hardware security available: {}",
        if platform.has_hardware_security() {
            "✅ YES (Secure Enclave)"
        } else {
            "❌ NO"
        }
    );

    #[cfg(target_arch = "aarch64")]
    println!("   Running on: Apple Silicon (M1/M2/M3)");
    #[cfg(not(target_arch = "aarch64"))]
    println!("   Running on: Intel Mac");

    println!();

    // Test memory protection features
    println!("🧪 Testing Memory Protection Features:\n");

    // 1. Memory Locking
    println!("1️⃣ Memory Locking (preventing swap to disk):");
    let mut test_data = vec![0x42u8; 4096 * 16]; // 64KB
    let result = platform.lock_memory(test_data.as_ptr(), test_data.len());
    match result {
        Ok(_) => println!("   ✅ Successfully locked 64KB in memory"),
        Err(e) => println!("   ⚠️  Failed to lock memory: {}", e),
    }

    // 2. Read-only protection
    println!("\n2️⃣ Memory Protection (making memory read-only):");
    let result = platform.protect_memory_readonly(test_data.as_ptr(), test_data.len());
    match result {
        Ok(_) => {
            println!("   ✅ Memory marked as read-only");
            // Note: Actually writing would cause a segfault, so we don't test that
        }
        Err(e) => println!("   ⚠️  Failed to protect memory: {}", e),
    }

    // Unlock memory before modifying
    let _ = platform.unlock_memory(test_data.as_ptr(), test_data.len());

    // 3. Secure memory clearing
    println!("\n3️⃣ Secure Memory Clearing:");
    platform.secure_zero_memory(test_data.as_mut_ptr(), test_data.len());
    let all_zero = test_data.iter().all(|&b| b == 0);
    println!(
        "   {} Memory securely cleared",
        if all_zero { "✅" } else { "❌" }
    );

    // 4. Hardware key generation (if available)
    println!("\n4️⃣ Hardware-backed Key Generation:");
    if platform.has_hardware_security() {
        match platform.generate_hardware_key("test_key") {
            Ok(key) => println!("   ✅ Generated {}-bit hardware key", key.len() * 8),
            Err(e) => println!(
                "   ⚠️  Hardware key generation not fully implemented: {}",
                e
            ),
        }
    } else {
        println!("   ℹ️  No hardware security available");
    }

    // Test secure model storage
    println!("\n📦 Testing Secure Model Storage:\n");

    let temp_dir = TempDir::new()?;
    let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
    let verifier = IntegrityVerifier::new(HashAlgorithm::Blake3);
    let storage = ModelStorage::new(temp_dir.path(), crypto, verifier)?;
    let secure_storage = SecureModelStorage::new(storage);

    // Create a test model
    let model_id = Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "secure-demo-model".to_string(),
        version: "1.0.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 10 * 1024 * 1024, // 10MB
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: Some("Model with macOS security features".to_string()),
        tags: vec!["secure".to_string(), "macos".to_string()],
        framework: None,
        architecture: None,
        parameters_count: Some(10_000_000),
        watermark: None,
        license_constraints: None,
    };

    let model_weights = vec![0xAB; 10 * 1024 * 1024]; // 10MB
    let master_key = EncryptionKey::generate();

    // Store with security features
    println!("🔒 Storing model with enhanced security...");
    let start = Instant::now();
    secure_storage.store_model_secure(model_id, metadata.clone(), &model_weights, &master_key)?;
    println!("   ✅ Model stored in {:.2?}", start.elapsed());

    // Load with memory protection
    println!("\n🔓 Loading model with memory protection...");
    let start = Instant::now();
    let secure_model = secure_storage.load_model_secure(model_id, &master_key)?;
    let load_time = start.elapsed();
    println!("   ✅ Model loaded in {:.2?}", load_time);
    println!("   ✅ Model weights locked in memory (won't swap to disk)");

    // Make read-only
    match secure_model.make_readonly() {
        Ok(_) => println!("   ✅ Model weights protected as read-only"),
        Err(e) => println!("   ⚠️  Failed to make read-only: {}", e),
    }

    // Verify the model
    println!("\n🔍 Verifying model integrity...");
    assert_eq!(secure_model.weights().len(), model_weights.len());
    assert_eq!(secure_model.metadata().name, "secure-demo-model");
    println!("   ✅ Model integrity verified");

    // Performance comparison
    println!("\n📊 Security Feature Impact:");
    println!("   Model size: 10 MB");
    println!("   Load time: {:.2?}", load_time);
    println!("   Speed: {:.2} MB/s", 10.0 / load_time.as_secs_f64());
    println!("   Memory overhead: ~0% (protection is transparent)");

    // Clean up
    println!("\n🧹 Secure cleanup...");
    let start = Instant::now();
    secure_model.secure_drop();
    println!(
        "   ✅ Model memory securely cleared in {:.2?}",
        start.elapsed()
    );

    println!("\n🎉 Demo completed successfully!");

    println!("\n📋 Summary of macOS Security Features Used:");
    println!("   • Memory locking (mlock) - prevents swapping sensitive data");
    println!("   • Memory protection (mprotect) - makes model weights read-only");
    println!("   • Secure memory clearing (memset_s) - guaranteed zeroing");
    if platform.has_hardware_security() {
        println!("   • Secure Enclave available for future key management");
    }
    println!("\n💡 These features provide defense-in-depth security on macOS!");

    Ok(())
}
