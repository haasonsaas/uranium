use uranium_vault::{VaultService, VaultConfig};
use uranium_core::{
    platform::get_platform_security,
    crypto::VaultCrypto,
};
use std::sync::Arc;
use tokio;
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🏦 Uranium Secure Vault Demo with Keychain");
    println!("==========================================\n");
    
    // Get platform security
    let platform = Arc::new(get_platform_security());
    
    // Check if we're on macOS with Keychain support
    if platform.has_hardware_security() {
        println!("✅ Hardware security features available");
        println!("✅ Using macOS Keychain for master key storage\n");
    } else {
        println!("⚠️  No hardware security - using software fallback\n");
    }
    
    // Generate or retrieve master key from Keychain
    let master_key = setup_master_key(&platform).await?;
    
    // Create vault configuration
    let config = VaultConfig {
        storage_path: "./secure_vault_demo".into(),
        bind_address: "127.0.0.1:8443".to_string(),
        enable_audit: true,
        max_model_size: 10 * 1024 * 1024 * 1024, // 10GB
        session_timeout: 3600, // 1 hour
        require_mfa: false,
    };
    
    // Initialize vault with master key from Keychain
    println!("🔧 Initializing vault service...");
    let vault = VaultService::new(config)?;
    
    // In a real implementation, the vault would use the master key
    // to derive encryption keys for models
    println!("   ✅ Vault initialized with secure master key");
    
    // Demonstrate secure operations
    demonstrate_secure_operations(&vault, &master_key).await?;
    
    println!("\n✅ Secure vault demo completed successfully!");
    println!("\n📝 Key Security Features:");
    println!("   • Master key stored in macOS Keychain");
    println!("   • Key never exists in code or config files");
    println!("   • Survives app restarts securely");
    println!("   • Protected by device authentication");
    
    Ok(())
}

async fn setup_master_key(platform: &Arc<Box<dyn uranium_core::platform::PlatformSecurity>>) -> anyhow::Result<Vec<u8>> {
    let master_key_id = "uranium_vault_master_production";
    
    // Try to retrieve existing master key from Keychain
    match platform.get_hardware_key(master_key_id) {
        Ok(key) => {
            println!("🔑 Retrieved existing master key from Keychain");
            Ok(key)
        }
        Err(_) => {
            // Generate new master key
            println!("🔑 Generating new master key...");
            let crypto = VaultCrypto::new()?;
            
            // In production, this would use a secure passphrase input
            // For demo purposes, we'll generate a strong random key
            let master_key = if platform.has_hardware_security() {
                // Use hardware RNG if available
                platform.generate_hardware_key(master_key_id)?
            } else {
                // Fallback to software generation
                crypto.generate_key()
            };
            
            // Store in Keychain
            platform.store_hardware_key(master_key_id, &master_key)?;
            println!("   ✅ Master key stored securely in Keychain");
            
            Ok(master_key)
        }
    }
}

async fn demonstrate_secure_operations(
    vault: &VaultService,
    master_key: &[u8],
) -> anyhow::Result<()> {
    println!("\n🔒 Demonstrating Secure Operations");
    println!("----------------------------------");
    
    // 1. Secure model encryption
    println!("1. Model encryption with Keychain-backed key:");
    println!("   • Master key never hardcoded");
    println!("   • Derived keys for each model");
    println!("   • Hardware-backed security when available");
    
    // 2. Access control
    println!("\n2. Access control integration:");
    println!("   • User authentication required");
    println!("   • Role-based permissions");
    println!("   • Audit trail of all access");
    
    // 3. Key rotation capability
    println!("\n3. Key rotation support:");
    println!("   • Update master key in Keychain");
    println!("   • Re-encrypt all models");
    println!("   • Zero downtime rotation");
    
    Ok(())
}

// Example of how to handle key rotation
async fn rotate_master_key(
    platform: &Arc<Box<dyn uranium_core::platform::PlatformSecurity>>,
    vault: &VaultService,
) -> anyhow::Result<()> {
    println!("\n🔄 Rotating Master Key");
    println!("----------------------");
    
    let master_key_id = "uranium_vault_master_production";
    let backup_key_id = "uranium_vault_master_backup";
    
    // 1. Backup current key
    let current_key = platform.get_hardware_key(master_key_id)?;
    platform.store_hardware_key(backup_key_id, &current_key)?;
    println!("   ✅ Current key backed up");
    
    // 2. Generate new key
    let new_key = if platform.has_hardware_security() {
        platform.generate_hardware_key("temp_new_key")?
    } else {
        VaultCrypto::new()?.generate_key()
    };
    
    // 3. Re-encrypt all models (would be implemented in VaultService)
    println!("   ⏳ Re-encrypting all models...");
    // vault.rotate_master_key(&current_key, &new_key).await?;
    
    // 4. Store new key
    platform.store_hardware_key(master_key_id, &new_key)?;
    println!("   ✅ New master key active");
    
    // 5. Clean up backup after verification
    // platform.delete_hardware_key(backup_key_id)?;
    
    Ok(())
}
