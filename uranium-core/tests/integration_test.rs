use chrono::Utc;
use tempfile::TempDir;
use uuid::Uuid;

use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelMetadata},
    storage::ModelStorage,
};

#[test]
fn test_end_to_end_model_storage() {
    // Setup
    let temp_dir = TempDir::new().unwrap();
    let storage = ModelStorage::new(
        temp_dir.path(),
        VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )
    .unwrap();

    let key = EncryptionKey::generate();

    // Create test model
    let model_id = Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "test_model".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1024,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: Some("Test model for integration testing".to_string()),
        tags: vec!["test".to_string(), "integration".to_string()],
        framework: Some(uranium_core::models::ModelFramework::PyTorch),
        architecture: Some("transformer".to_string()),
        parameters_count: Some(1_000_000),
        watermark: None,
        license_constraints: None,
    };

    let weights = vec![42u8; 1024]; // 1KB of test data

    // Store the model
    let path = storage
        .store_model(model_id, metadata.clone(), &weights, &key)
        .unwrap();

    assert!(path.exists());

    // Load the model back
    let decrypted = storage.load_model(model_id, &key).unwrap();

    // Verify metadata
    assert_eq!(decrypted.metadata.id, model_id);
    assert_eq!(decrypted.metadata.name, "test_model");
    assert_eq!(decrypted.metadata.version, "1.0");
    assert_eq!(decrypted.metadata.tags, vec!["test", "integration"]);

    // Verify weights
    assert_eq!(decrypted.weights, weights);

    // Test listing models
    let models = storage.list_models().unwrap();
    assert!(models.contains(&model_id));

    // Test metadata retrieval without decryption
    let metadata_only = storage.get_model_metadata(model_id).unwrap();
    assert_eq!(metadata_only.name, "test_model");
}

#[test]
fn test_model_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let storage = ModelStorage::new(
        temp_dir.path(),
        VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )
    .unwrap();

    let key = EncryptionKey::generate();
    let non_existent_id = Uuid::new_v4();

    let result = storage.load_model(non_existent_id, &key);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        uranium_core::UraniumError::ModelNotFound { .. }
    ));
}

#[test]
fn test_integrity_verification() {
    let temp_dir = TempDir::new().unwrap();
    let storage = ModelStorage::new(
        temp_dir.path(),
        VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )
    .unwrap();

    let key = EncryptionKey::generate();
    let model_id = Uuid::new_v4();

    let metadata = ModelMetadata {
        id: model_id,
        name: "integrity_test".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::ONNX,
        size_bytes: 512,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: None,
        tags: vec![],
        framework: None,
        architecture: None,
        parameters_count: None,
        watermark: None,
        license_constraints: None,
    };

    let weights = vec![0xAB; 512];

    // Store model
    storage
        .store_model(model_id, metadata, &weights, &key)
        .unwrap();

    // Load and verify integrity passes
    let loaded = storage.load_model(model_id, &key).unwrap();
    assert_eq!(loaded.weights, weights);

    // Note: We can't easily test integrity failure without modifying internal storage
    // In a real implementation, we'd have a test that corrupts the stored file
}

#[test]
fn test_secure_delete() {
    let temp_dir = TempDir::new().unwrap();
    let storage = ModelStorage::new(
        temp_dir.path(),
        VaultCrypto::new(EncryptionAlgorithm::AesGcm256),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )
    .unwrap();

    let key = EncryptionKey::generate();
    let model_id = Uuid::new_v4();

    let metadata = ModelMetadata {
        id: model_id,
        name: "delete_test".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::PyTorch,
        size_bytes: 256,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        description: None,
        tags: vec![],
        framework: None,
        architecture: None,
        parameters_count: None,
        watermark: None,
        license_constraints: None,
    };

    let weights = vec![0xFF; 256];

    // Store model
    let path = storage
        .store_model(model_id, metadata, &weights, &key)
        .unwrap();

    assert!(path.exists());

    // Delete model
    storage.delete_model(model_id).unwrap();

    // Verify file is gone
    assert!(!path.exists());

    // Verify model can't be loaded
    let result = storage.load_model(model_id, &key);
    assert!(result.is_err());
}

#[test]
fn test_different_encryption_algorithms() {
    let temp_dir = TempDir::new().unwrap();

    // Test with ChaCha20
    let storage_chacha = ModelStorage::new(
        temp_dir.path().join("chacha"),
        VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )
    .unwrap();

    // Test with AES-GCM
    let storage_aes = ModelStorage::new(
        temp_dir.path().join("aes"),
        VaultCrypto::new(EncryptionAlgorithm::AesGcm256),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )
    .unwrap();

    let key = EncryptionKey::generate();
    let weights = vec![0x42; 1024];

    for (storage, name) in [(storage_chacha, "chacha_model"), (storage_aes, "aes_model")] {
        let model_id = Uuid::new_v4();
        let metadata = ModelMetadata {
            id: model_id,
            name: name.to_string(),
            version: "1.0".to_string(),
            format: ModelFormat::SafeTensors,
            size_bytes: weights.len() as u64,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            description: None,
            tags: vec![],
            framework: None,
            architecture: None,
            parameters_count: None,
            watermark: None,
            license_constraints: None,
        };

        // Store and load
        storage
            .store_model(model_id, metadata, &weights, &key)
            .unwrap();

        let loaded = storage.load_model(model_id, &key).unwrap();
        assert_eq!(loaded.weights, weights);
    }
}
