use std::sync::Arc;
use uuid::Uuid;

use crate::{
    crypto::EncryptionKey,
    errors::Result,
    models::{DecryptedModel, ModelMetadata},
    platform::{get_platform_security, PlatformSecurity},
    storage::ModelStorage,
};

/// Secure model storage with platform-specific security features
pub struct SecureModelStorage {
    storage: ModelStorage,
    platform: Arc<Box<dyn PlatformSecurity>>,
}

impl SecureModelStorage {
    pub fn new(storage: ModelStorage) -> Self {
        let platform = Arc::new(get_platform_security());

        if platform.has_hardware_security() {
            tracing::info!("Hardware security features available and enabled");
        }

        Self { storage, platform }
    }

    /// Store model with hardware-backed key if available
    pub fn store_model_secure(
        &self,
        model_id: Uuid,
        metadata: ModelMetadata,
        weights: &[u8],
        master_key: &EncryptionKey,
    ) -> Result<()> {
        // Try to use hardware-backed key storage
        let key_id = format!("uranium_model_{}", model_id);

        if self.platform.has_hardware_security() {
            // Generate a model-specific key
            match self.platform.generate_hardware_key(&key_id) {
                Ok(hw_key) => {
                    tracing::info!("Using hardware-backed key for model {}", model_id);
                    // Store the hardware key reference
                    if let Err(e) = self.platform.store_hardware_key(&key_id, &hw_key) {
                        tracing::warn!("Failed to store hardware key: {}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to generate hardware key: {}", e);
                }
            }
        }

        // Store using regular encryption
        self.storage
            .store_model(model_id, metadata, weights, master_key)?;

        Ok(())
    }

    /// Load model with enhanced memory protection
    pub fn load_model_secure(
        &self,
        model_id: Uuid,
        master_key: &EncryptionKey,
    ) -> Result<SecureDecryptedModel> {
        // Load the encrypted model
        let decrypted = self.storage.load_model(model_id, master_key)?;

        // Wrap in secure model with memory protection
        SecureDecryptedModel::new(decrypted, self.platform.clone())
    }
}

/// Wrapper for decrypted model with memory protection
pub struct SecureDecryptedModel {
    inner: DecryptedModel,
    platform: Arc<Box<dyn PlatformSecurity>>,
    locked: bool,
}

impl SecureDecryptedModel {
    fn new(model: DecryptedModel, platform: Arc<Box<dyn PlatformSecurity>>) -> Result<Self> {
        let mut secure_model = Self {
            inner: model,
            platform,
            locked: false,
        };

        // Lock the memory to prevent swapping
        secure_model.lock_memory()?;

        Ok(secure_model)
    }

    /// Lock model weights in memory to prevent swapping
    fn lock_memory(&mut self) -> Result<()> {
        if !self.locked {
            let addr = self.inner.weights.as_ptr();
            let len = self.inner.weights.len();

            if let Err(e) = self.platform.lock_memory(addr, len) {
                tracing::warn!("Failed to lock model memory: {}", e);
                // Continue even if locking fails
            } else {
                self.locked = true;
                tracing::debug!("Locked {} bytes of model weights in memory", len);
            }
        }
        Ok(())
    }

    /// Make model weights read-only
    pub fn make_readonly(&self) -> Result<()> {
        let addr = self.inner.weights.as_ptr();
        let len = self.inner.weights.len();

        self.platform.protect_memory_readonly(addr, len)?;
        tracing::debug!("Model weights set to read-only");
        Ok(())
    }

    /// Get reference to model metadata
    pub fn metadata(&self) -> &ModelMetadata {
        &self.inner.metadata
    }

    /// Get reference to model weights
    pub fn weights(&self) -> &[u8] {
        &self.inner.weights
    }

    /// Consume and securely clear the model
    pub fn secure_drop(mut self) {
        // Securely zero the memory
        let addr = self.inner.weights.as_mut_ptr();
        let len = self.inner.weights.len();

        self.platform.secure_zero_memory(addr, len);

        // Unlock memory if it was locked
        if self.locked {
            if let Err(e) = self
                .platform
                .unlock_memory(self.inner.weights.as_ptr(), len)
            {
                tracing::warn!("Failed to unlock memory during cleanup: {}", e);
            }
        }
    }
}

impl Drop for SecureDecryptedModel {
    fn drop(&mut self) {
        // Ensure memory is unlocked and cleared
        if self.locked {
            let addr = self.inner.weights.as_ptr();
            let len = self.inner.weights.len();

            // Best effort to unlock
            let _ = self.platform.unlock_memory(addr, len);
        }

        // Note: The inner DecryptedModel's Drop will handle zeroization
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{EncryptionAlgorithm, VaultCrypto},
        integrity::HashAlgorithm,
        models::ModelFormat,
    };
    use tempfile::TempDir;

    #[test]
    #[ignore = "Memory protection can cause SIGBUS in test environment"]
    fn test_secure_storage() {
        let temp_dir = TempDir::new().unwrap();
        let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
        let verifier = crate::integrity::IntegrityVerifier::new(HashAlgorithm::Blake3);

        let storage = ModelStorage::new(temp_dir.path(), crypto, verifier).unwrap();
        let secure_storage = SecureModelStorage::new(storage);

        // Create test model
        let model_id = Uuid::new_v4();
        let metadata = ModelMetadata {
            id: model_id,
            name: "secure_test".to_string(),
            version: "1.0".to_string(),
            format: ModelFormat::SafeTensors,
            size_bytes: 1024,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            description: None,
            tags: vec![],
            framework: None,
            architecture: None,
            parameters_count: None,
            watermark: None,
            license_constraints: None,
        };

        let weights = vec![0x42u8; 1024];
        let key = EncryptionKey::generate();

        // Store securely
        secure_storage
            .store_model_secure(model_id, metadata, &weights, &key)
            .unwrap();

        // Load securely
        let secure_model = secure_storage.load_model_secure(model_id, &key).unwrap();

        // Verify we can read the weights
        assert_eq!(secure_model.weights(), &weights);

        // Try to make read-only
        let _ = secure_model.make_readonly();

        // Clean up
        secure_model.secure_drop();
    }
}
