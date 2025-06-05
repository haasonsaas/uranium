use uranium_core::{
    platform::macos::{SecureEnclaveKey, SecureEnclaveManager},
    Result,
};

fn main() -> Result<()> {
    println!("🔐 Uranium Secure Enclave Simple Demo");
    println!("=====================================\n");

    // Check if Secure Enclave is available
    let se_available = SecureEnclaveKey::is_available();
    println!(
        "Secure Enclave Available: {}",
        if se_available { "✅ YES" } else { "❌ NO" }
    );

    if !se_available {
        println!("\nSecure Enclave is not available on this device.");
        println!("This demo requires:");
        println!("  • Apple Silicon Mac (M1/M2/M3), or");
        println!("  • Intel Mac with T2 security chip");
        return Ok(());
    }

    // Test hardware detection
    #[cfg(target_arch = "aarch64")]
    println!("Running on: Apple Silicon (ARM64)");

    #[cfg(not(target_arch = "aarch64"))]
    println!("Running on: Intel Mac with T2 chip");

    // Test Secure Enclave Manager
    println!("\n📱 Testing Secure Enclave Manager");
    println!("---------------------------------");

    let mut manager = SecureEnclaveManager::new();

    // Generate a key
    let key_id = "demo_key";
    let symmetric_key = manager.get_or_generate_key(key_id)?;
    println!(
        "✅ Generated symmetric key via SE: {} bytes",
        symmetric_key.len()
    );

    // Test encryption/decryption
    let plaintext = b"Secret model weights!";
    let ciphertext = manager.encrypt_with_se(key_id, plaintext)?;
    println!("✅ Encrypted {} bytes", plaintext.len());

    let decrypted = manager.decrypt_with_se(key_id, &ciphertext)?;
    println!("✅ Decrypted {} bytes", decrypted.len());

    if plaintext == &decrypted[..] {
        println!("✅ Encryption/decryption verified!");
    } else {
        println!("❌ Decryption failed!");
    }

    // Test hardware random generation
    println!("\n🎲 Testing Hardware Random Generation");
    println!("------------------------------------");

    let key1 = SecureEnclaveKey::generate("random_test_1")?;
    let key2 = SecureEnclaveKey::generate("random_test_2")?;

    // Get public key data (simulated)
    let pub1 = key1.public_key_data()?;
    let pub2 = key2.public_key_data()?;

    if pub1 != pub2 {
        println!("✅ Hardware random generation working (keys are unique)");
    } else {
        println!("❌ Keys are not unique!");
    }

    // Clean up
    SecureEnclaveKey::delete("demo_key")?;
    SecureEnclaveKey::delete("random_test_1")?;
    SecureEnclaveKey::delete("random_test_2")?;
    println!("\n✅ Demo completed successfully!");

    Ok(())
}
