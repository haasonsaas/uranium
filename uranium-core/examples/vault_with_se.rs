/// Example showing how to use Secure Enclave with the Uranium vault
///
/// This demonstrates:
/// - Configuring the vault to use Secure Enclave
/// - Storing models with hardware-backed encryption
/// - Migrating existing models to SE encryption
/// - Checking SE status

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("This example requires macOS for Secure Enclave support");
}

#[cfg(target_os = "macos")]
use uranium_core::{platform::macos::SecureEnclaveKey, Result};

#[cfg(target_os = "macos")]
fn main() -> Result<()> {
    println!("🏛️  Uranium Vault with Secure Enclave");
    println!("====================================\n");

    // Check platform capabilities
    check_platform_security();

    // Show vault configuration
    show_vault_config();

    // Demonstrate SE usage
    if SecureEnclaveKey::is_available() {
        demonstrate_se_vault()?;
    } else {
        println!("\n⚠️  Secure Enclave not available - using software encryption");
    }

    Ok(())
}

fn check_platform_security() {
    println!("🔒 Platform Security Status");
    println!("---------------------------");

    // Check Secure Enclave
    let se_available = SecureEnclaveKey::is_available();
    println!(
        "Secure Enclave: {}",
        if se_available {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );

    // Check architecture
    #[cfg(target_arch = "aarch64")]
    println!("Architecture: Apple Silicon (ARM64)");

    #[cfg(target_arch = "x86_64")]
    println!("Architecture: Intel x86_64");

    // Check OS version
    println!("Platform: macOS");
}

fn show_vault_config() {
    println!("\n⚙️  Recommended Vault Configuration");
    println!("----------------------------------");

    println!("```toml");
    println!("[security]");
    println!("encryption_algorithm = \"ChaCha20Poly1305\"");
    println!("hash_algorithm = \"Blake3\"");
    println!("enable_memory_protection = true");
    println!("enable_secure_enclave = true  # Enable SE when available");
    println!();
    println!("[storage]");
    println!("base_path = \"./vault/models\"");
    println!("chunk_size_mb = 64");
    println!("```");
}

fn demonstrate_se_vault() -> Result<()> {
    println!("\n🚀 Vault Operations with Secure Enclave");
    println!("--------------------------------------");

    // In a real application, you would:
    // 1. Create vault with SE enabled
    println!("1. Create vault with SE enabled:");
    println!("   ```rust");
    println!("   let config = VaultConfig {{");
    println!("       enable_secure_enclave: true,");
    println!("       ..Default::default()");
    println!("   }};");
    println!("   let vault = Vault::new(config, auth_manager, audit_logger)?;");
    println!("   ```");

    // 2. Store models - automatically uses SE
    println!("\n2. Store model (automatically uses SE):");
    println!("   ```rust");
    println!("   let model_id = vault.store_model(");
    println!("       &session,");
    println!("       metadata,");
    println!("       model_weights");
    println!("   ).await?;");
    println!("   // ✅ Model encrypted with Secure Enclave");
    println!("   ```");

    // 3. Load models - automatically uses SE
    println!("\n3. Load model (automatically uses SE):");
    println!("   ```rust");
    println!("   let model = vault.load_model(&session, model_id).await?;");
    println!("   // ✅ Model decrypted with Secure Enclave");
    println!("   ```");

    // 4. Migrate existing models
    println!("\n4. Migrate existing model to SE:");
    println!("   ```rust");
    println!("   vault.migrate_to_secure_enclave(&session, model_id).await?;");
    println!("   // ✅ Model re-encrypted with hardware backing");
    println!("   ```");

    // 5. Check SE status
    println!("\n5. Check if vault is using SE:");
    println!("   ```rust");
    println!("   if vault.is_secure_enclave_enabled() {{");
    println!("       println!(\"✅ Hardware-backed encryption active\");");
    println!("   }}");
    println!("   ```");

    // Show benefits
    println!("\n💎 Benefits of Secure Enclave Integration:");
    println!("   • Keys never leave hardware security module");
    println!("   • Hardware-backed random number generation");
    println!("   • Protection against key extraction attacks");
    println!("   • Automatic fallback to software when SE unavailable");
    println!("   • Transparent API - no code changes needed");

    Ok(())
}
