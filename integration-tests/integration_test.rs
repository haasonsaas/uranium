use anyhow::Result;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use uranium_sdk::{ModelFormat, VaultClient};
use uuid::Uuid;

/// Integration tests for the full Uranium system
/// 
/// These tests require the demo vault server to be running.
/// Start it with: ./start-vault.sh

#[tokio::test]
async fn test_full_workflow() -> Result<()> {
    // Check if server is running
    let client = VaultClient::new("http://localhost:8080")?;
    
    // Check status (no auth required)
    let status = client.status().await?;
    assert_eq!(status.vault_status, "unlocked");
    
    // Store a model (no auth for demo server)
    let test_data = b"Integration test model data";
    let model_id = client.store_model(
        "integration-test-model",
        test_data.to_vec(),
        ModelFormat::SafeTensors,
    ).await?;
    
    println!("Model stored with ID: {}", model_id);
    
    // List models
    let models = client.list_models().await?;
    assert!(models.iter().any(|m| m.id == model_id));
    
    // Get model info
    let model_info = client.get_model(model_id).await?;
    assert_eq!(model_info.name, "integration-test-model");
    assert_eq!(model_info.size, test_data.len());
    
    Ok(())
}

#[tokio::test]
async fn test_cli_integration() -> Result<()> {
    // Build CLI
    Command::new("cargo")
        .args(&["build", "-p", "uranium-cli", "--quiet"])
        .status()?;
    
    let uranium = "./target/debug/uranium";
    
    // Test status command
    let output = Command::new(uranium)
        .args(&["status", "--server", "http://localhost:8080"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Uranium Status"));
    
    // Test model list
    let output = Command::new(uranium)
        .args(&["model", "list", "--server", "http://localhost:8080"])
        .output()?;
    
    assert!(output.status.success());
    
    Ok(())
}

#[tokio::test]
async fn test_encryption_roundtrip() -> Result<()> {
    use uranium_core::{
        crypto::{EncryptionKey, VaultCrypto},
        integrity::IntegrityVerifier,
        models::{DecryptedModel, ModelFormat as CoreFormat, ModelMetadata},
    };
    
    // Create encryption components
    let crypto = VaultCrypto::new(uranium_core::crypto::EncryptionAlgorithm::ChaCha20Poly1305);
    let verifier = IntegrityVerifier::new(uranium_core::integrity::HashAlgorithm::Blake3);
    let key = EncryptionKey::generate();
    
    // Create test model
    let metadata = ModelMetadata {
        id: Uuid::new_v4(),
        name: "test-model".to_string(),
        version: "1.0".to_string(),
        format: CoreFormat::SafeTensors,
        size_bytes: 1024,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: Some("Test model".to_string()),
        tags: vec!["test".to_string()],
    };
    
    let weights = vec![1u8; 1024];
    let model = DecryptedModel {
        metadata: metadata.clone(),
        weights: weights.clone(),
    };
    
    // Encrypt
    let encrypted = crypto.encrypt_model(&model, &key)?;
    
    // Verify hash
    let expected_hash = verifier.compute_hash(&model);
    assert_eq!(encrypted.integrity_hash, expected_hash);
    
    // Decrypt
    let decrypted = crypto.decrypt_model(&encrypted, &key)?;
    assert!(verifier.verify_model(&decrypted, &encrypted.integrity_hash)?);
    
    // Verify roundtrip
    assert_eq!(decrypted.metadata.id, metadata.id);
    assert_eq!(decrypted.weights, weights);
    
    Ok(())
}

#[tokio::test]
async fn test_secure_enclave_detection() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use uranium_core::storage::SecureEnclaveStorage;
        
        let available = SecureEnclaveStorage::is_secure_enclave_available();
        println!("Secure Enclave available: {}", available);
        
        // Just check it doesn't crash
        assert!(available || !available);
    }
    
    Ok(())
}

#[tokio::test]
async fn test_streaming_encryption() -> Result<()> {
    use uranium_core::crypto::{
        streaming::{StreamingCrypto, StreamingEncryptor, StreamingDecryptor},
        EncryptionAlgorithm, EncryptionKey,
    };
    use std::io::Cursor;
    
    // Create streaming crypto
    let crypto = StreamingCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
    let key = EncryptionKey::generate();
    
    // Test data (1MB)
    let data = vec![42u8; 1024 * 1024];
    let mut encrypted = Vec::new();
    
    // Encrypt
    let mut encryptor = crypto.create_encryptor(&key)?;
    let mut reader = Cursor::new(&data);
    encryptor.encrypt_stream(&mut reader, &mut encrypted)?;
    let hash = encryptor.finalize()?;
    
    // Decrypt
    let mut decrypted = Vec::new();
    let mut decryptor = crypto.create_decryptor(&key)?;
    let mut reader = Cursor::new(&encrypted);
    decryptor.decrypt_stream(&mut reader, &mut decrypted)?;
    let verified_hash = decryptor.finalize()?;
    
    // Verify
    assert_eq!(hash, verified_hash);
    assert_eq!(data, decrypted);
    
    Ok(())
}

// Helper to ensure server is running
async fn ensure_server_running() -> Result<()> {
    let client = VaultClient::new("http://localhost:8080")?;
    
    for _ in 0..5 {
        if client.status().await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }
    
    anyhow::bail!("Vault server is not running. Start it with: ./start-vault.sh")
}

#[tokio::test]
async fn test_server_required() -> Result<()> {
    ensure_server_running().await
}