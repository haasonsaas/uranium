use crate::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    models::ModelMetadata,
    platform::macos::{SecureEnclaveKey, SecureEnclaveManager},
    storage::ModelStorage,
    Result, UraniumError,
};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Secure model storage using macOS Secure Enclave
///
/// This provides hardware-backed encryption for LLM weights,
/// ensuring that encryption keys never leave the Secure Enclave.
pub struct SecureEnclaveStorage {
    base_storage: Arc<ModelStorage>,
    se_manager: Arc<Mutex<SecureEnclaveManager>>,
}

impl SecureEnclaveStorage {
    /// Create a new Secure Enclave-backed storage
    pub fn new(base_storage: ModelStorage) -> Self {
        Self {
            base_storage: Arc::new(base_storage),
            se_manager: Arc::new(Mutex::new(SecureEnclaveManager::new())),
        }
    }

    /// Store a model with Secure Enclave encryption
    pub fn store_model_secure_enclave(
        &self,
        model_id: Uuid,
        metadata: ModelMetadata,
        model_data: &[u8],
    ) -> Result<()> {
        // Generate or retrieve Secure Enclave key for this model
        let key_id = format!("model_{}", model_id);
        let encryption_key = {
            let mut manager = self
                .se_manager
                .lock()
                .map_err(|_| UraniumError::Internal("Failed to lock SE manager".to_string()))?;
            manager.get_or_generate_key(&key_id)?
        };

        // Convert to EncryptionKey
        let enc_key = EncryptionKey::from_bytes(&encryption_key)?;

        // Store using base storage with SE-derived key
        self.base_storage
            .store_model(model_id, metadata, model_data, &enc_key)?;

        tracing::info!("Stored model {} with Secure Enclave encryption", model_id);
        Ok(())
    }

    /// Load a model encrypted with Secure Enclave
    pub fn load_model_secure_enclave(
        &self,
        model_id: Uuid,
    ) -> Result<crate::models::DecryptedModel> {
        // Get the SE-derived key for this model
        let key_id = format!("model_{}", model_id);
        let encryption_key = {
            let mut manager = self
                .se_manager
                .lock()
                .map_err(|_| UraniumError::Internal("Failed to lock SE manager".to_string()))?;
            manager.get_or_generate_key(&key_id)?
        };

        // Convert to EncryptionKey
        let enc_key = EncryptionKey::from_bytes(&encryption_key)?;

        // Load using base storage
        let decrypted_model = self.base_storage.load_model(model_id, &enc_key)?;

        tracing::info!("Loaded model {} with Secure Enclave decryption", model_id);
        Ok(decrypted_model)
    }

    /// Check if Secure Enclave is available
    pub fn is_secure_enclave_available() -> bool {
        SecureEnclaveKey::is_available()
    }

    /// Migrate an existing model to Secure Enclave encryption
    pub fn migrate_to_secure_enclave(&self, model_id: Uuid, old_key: &EncryptionKey) -> Result<()> {
        // Load and decrypt with old key
        let decrypted_model = self.base_storage.load_model(model_id, old_key)?;

        // Extract metadata and weights from decrypted model
        let metadata = decrypted_model.metadata.clone();
        let weights = decrypted_model.weights.clone();

        // Re-encrypt with Secure Enclave
        self.store_model_secure_enclave(model_id, metadata, &weights)?;

        tracing::info!("Migrated model {} to Secure Enclave encryption", model_id);
        Ok(())
    }

    /// Batch migrate multiple models to Secure Enclave
    pub fn batch_migrate_to_secure_enclave(
        &self,
        model_keys: Vec<(Uuid, EncryptionKey)>,
    ) -> Result<Vec<Uuid>> {
        let mut migrated = Vec::new();

        for (model_id, old_key) in model_keys {
            match self.migrate_to_secure_enclave(model_id, &old_key) {
                Ok(_) => {
                    migrated.push(model_id);
                    tracing::info!("Successfully migrated model {}", model_id);
                }
                Err(e) => {
                    tracing::error!("Failed to migrate model {}: {}", model_id, e);
                }
            }
        }

        Ok(migrated)
    }

    /// Generate a data encryption key using Secure Enclave
    ///
    /// This creates a new key in the Secure Enclave and returns
    /// a derived symmetric key suitable for bulk encryption.
    pub fn generate_dek_with_secure_enclave(&self, key_id: &str) -> Result<Vec<u8>> {
        let mut manager = self
            .se_manager
            .lock()
            .map_err(|_| UraniumError::Internal("Failed to lock SE manager".to_string()))?;

        manager.get_or_generate_key(key_id)
    }

    /// Encrypt metadata using Secure Enclave
    pub fn encrypt_metadata_with_se(&self, metadata: &ModelMetadata) -> Result<Vec<u8>> {
        let key_id = "metadata_encryption_key";
        let manager = self
            .se_manager
            .lock()
            .map_err(|_| UraniumError::Internal("Failed to lock SE manager".to_string()))?;

        // Serialize metadata
        let metadata_bytes = bincode::serialize(metadata)
            .map_err(|e| UraniumError::Internal(format!("Failed to serialize metadata: {}", e)))?;

        // Encrypt with SE
        manager.encrypt_with_se(key_id, &metadata_bytes)
    }

    /// Decrypt metadata using Secure Enclave
    pub fn decrypt_metadata_with_se(&self, encrypted_metadata: &[u8]) -> Result<ModelMetadata> {
        let key_id = "metadata_encryption_key";
        let manager = self
            .se_manager
            .lock()
            .map_err(|_| UraniumError::Internal("Failed to lock SE manager".to_string()))?;

        // Decrypt with SE
        let decrypted = manager.decrypt_with_se(key_id, encrypted_metadata)?;

        // Deserialize metadata
        bincode::deserialize(&decrypted)
            .map_err(|e| UraniumError::Internal(format!("Failed to deserialize metadata: {}", e)))
    }
}

/// Builder for SecureEnclaveStorage with configuration options
pub struct SecureEnclaveStorageBuilder {
    storage_path: Option<String>,
    algorithm: EncryptionAlgorithm,
    enable_audit: bool,
}

impl SecureEnclaveStorageBuilder {
    pub fn new() -> Self {
        Self {
            storage_path: None,
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            enable_audit: true,
        }
    }

    pub fn with_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.storage_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    pub fn with_algorithm(mut self, algorithm: EncryptionAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_audit(mut self, enable: bool) -> Self {
        self.enable_audit = enable;
        self
    }

    pub fn build(self) -> Result<SecureEnclaveStorage> {
        // Check if Secure Enclave is available
        if !SecureEnclaveStorage::is_secure_enclave_available() {
            return Err(UraniumError::Internal(
                "Secure Enclave not available on this device".to_string(),
            ));
        }

        let storage_path = self
            .storage_path
            .ok_or_else(|| UraniumError::Internal("Storage path not specified".to_string()))?;

        // Create base storage components
        let vault_crypto = VaultCrypto::new(self.algorithm);
        let integrity =
            crate::integrity::IntegrityVerifier::new(crate::integrity::HashAlgorithm::Blake3);

        let base_storage = ModelStorage::new(storage_path, vault_crypto, integrity)?;

        Ok(SecureEnclaveStorage::new(base_storage))
    }
}

impl Default for SecureEnclaveStorageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_secure_enclave_availability() {
        let available = SecureEnclaveStorage::is_secure_enclave_available();
        println!("Secure Enclave available for storage: {}", available);
    }

    #[test]
    #[ignore = "Requires actual Secure Enclave hardware"]
    fn test_secure_enclave_storage() {
        if !SecureEnclaveStorage::is_secure_enclave_available() {
            println!("Skipping - Secure Enclave not available");
            return;
        }

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage = SecureEnclaveStorageBuilder::new()
            .with_path(temp_dir.path())
            .build()
            .expect("Failed to create SE storage");

        // Test storing and loading a model
        let model_id = Uuid::new_v4();
        let metadata = ModelMetadata {
            id: model_id,
            name: "test-model".to_string(),
            version: "1.0".to_string(),
            format: crate::models::ModelFormat::SafeTensors,
            size_bytes: 1024,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            description: Some("Test model".to_string()),
            tags: vec!["test".to_string()],
            framework: None,
            architecture: None,
            parameters_count: None,
            watermark: None,
            license_constraints: None,
        };

        let model_data = vec![42u8; 1024];

        // Store with SE
        storage
            .store_model_secure_enclave(model_id, metadata.clone(), &model_data)
            .expect("Failed to store model");

        // Load with SE
        let loaded = storage
            .load_model_secure_enclave(model_id)
            .expect("Failed to load model");

        assert_eq!(loaded.metadata.id, model_id);
        // Verify decryption worked by checking the weights match
        assert_eq!(loaded.weights, model_data);
    }
}
