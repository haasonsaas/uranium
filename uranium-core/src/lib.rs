pub mod crypto;
pub mod errors;
pub mod integrity;
pub mod models;
pub mod platform;
pub mod storage;

pub use crypto::{EncryptionKey, VaultCrypto};
pub use errors::{Result, UraniumError};
pub use integrity::{IntegrityVerifier, ModelHash};
pub use models::{ModelFormat, ModelMetadata};
pub use storage::{EncryptedModel, ModelStorage};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_encryption_flow() {
        // Create a complete encryption/decryption flow
        let key = EncryptionKey::generate();
        let crypto = VaultCrypto::new(crypto::EncryptionAlgorithm::ChaCha20Poly1305);

        let plaintext = b"This is a test model weights data";

        // Encrypt
        let encrypted = crypto.encrypt(&key, plaintext).unwrap();

        // Ensure encrypted data is different from plaintext
        assert_ne!(encrypted.ciphertext, plaintext);

        // Decrypt
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();

        // Verify we get the same data back
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let crypto = VaultCrypto::new(crypto::EncryptionAlgorithm::ChaCha20Poly1305);

        let plaintext = b"Secret model data";

        // Encrypt with key1
        let encrypted = crypto.encrypt(&key1, plaintext).unwrap();

        // Try to decrypt with key2 - should fail
        let result = crypto.decrypt(&key2, &encrypted);
        assert!(result.is_err());
    }
}
