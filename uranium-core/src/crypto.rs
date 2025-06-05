use aead::{Aead, AeadCore, KeyInit, OsRng};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{Result, UraniumError};

const KEY_SIZE: usize = 32; // 256 bits
const SALT_SIZE: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

// Streaming encryption constants
// const STREAMING_CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks for streaming
const NONCE_SIZE: usize = 12; // Nonce size for ChaCha20Poly1305 and AES-GCM

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: [u8; KEY_SIZE],
}

impl EncryptionKey {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(UraniumError::Encryption(format!(
                "Invalid key size: expected {}, got {}",
                KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    pub fn derive_from_password(password: &str, salt: &[u8]) -> Result<Self> {
        if salt.len() != SALT_SIZE {
            return Err(UraniumError::KeyDerivation(format!(
                "Invalid salt size: expected {}, got {}",
                SALT_SIZE,
                salt.len()
            )));
        }

        let mut key = [0u8; KEY_SIZE];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt,
            password.as_bytes(),
            &mut key,
        );

        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub salt: Option<Vec<u8>>,
    pub algorithm: EncryptionAlgorithm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EncryptionAlgorithm {
    ChaCha20Poly1305,
    AesGcm256,
}

pub struct VaultCrypto {
    algorithm: EncryptionAlgorithm,
}

impl VaultCrypto {
    pub fn new(algorithm: EncryptionAlgorithm) -> Self {
        Self { algorithm }
    }

    pub fn encrypt(&self, key: &EncryptionKey, plaintext: &[u8]) -> Result<EncryptedData> {
        match self.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => self.encrypt_chacha20poly1305(key, plaintext),
            EncryptionAlgorithm::AesGcm256 => self.encrypt_aes_gcm(key, plaintext),
        }
    }

    pub fn decrypt(&self, key: &EncryptionKey, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        if encrypted.algorithm != self.algorithm {
            return Err(UraniumError::Decryption(format!(
                "Algorithm mismatch: expected {:?}, got {:?}",
                self.algorithm, encrypted.algorithm
            )));
        }

        match self.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => self.decrypt_chacha20poly1305(key, encrypted),
            EncryptionAlgorithm::AesGcm256 => self.decrypt_aes_gcm(key, encrypted),
        }
    }

    fn encrypt_chacha20poly1305(
        &self,
        key: &EncryptionKey,
        plaintext: &[u8],
    ) -> Result<EncryptedData> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| UraniumError::Encryption(e.to_string()))?;

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| UraniumError::Encryption(e.to_string()))?;

        Ok(EncryptedData {
            nonce: nonce.to_vec(),
            ciphertext,
            salt: None,
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        })
    }

    fn decrypt_chacha20poly1305(
        &self,
        key: &EncryptionKey,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| UraniumError::Decryption(e.to_string()))?;

        let nonce = chacha20poly1305::Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|e| UraniumError::Decryption(e.to_string()))
    }

    fn encrypt_aes_gcm(&self, key: &EncryptionKey, plaintext: &[u8]) -> Result<EncryptedData> {
        use aes_gcm::Aes256Gcm;

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| UraniumError::Encryption(e.to_string()))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| UraniumError::Encryption(e.to_string()))?;

        Ok(EncryptedData {
            nonce: nonce.to_vec(),
            ciphertext,
            salt: None,
            algorithm: EncryptionAlgorithm::AesGcm256,
        })
    }

    fn decrypt_aes_gcm(&self, key: &EncryptionKey, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| UraniumError::Decryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|e| UraniumError::Decryption(e.to_string()))
    }

    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        salt
    }
}

/// Header for streaming encrypted data
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamingEncryptionHeader {
    pub algorithm: EncryptionAlgorithm,
    pub salt: Option<Vec<u8>>,
    pub chunk_size: usize,
    pub total_size: Option<u64>,
}

/// Represents an encrypted chunk in streaming mode
#[derive(Debug)]
pub struct EncryptedChunk {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub chunk_index: u64,
}

/// Trait for streaming encryption operations
pub trait StreamingCrypto {
    fn create_encryptor<W: Write + Send + 'static>(
        &self,
        key: &EncryptionKey,
        writer: W,
        header: StreamingEncryptionHeader,
    ) -> Result<Box<dyn StreamingEncryptor<W>>>;

    fn create_decryptor<R: Read + Send + 'static>(
        &self,
        key: &EncryptionKey,
        reader: R,
    ) -> Result<Box<dyn StreamingDecryptor<R>>>;
}

/// Trait for streaming encryption
pub trait StreamingEncryptor<W: Write>: Send {
    fn write_chunk(&mut self, data: &[u8]) -> Result<usize>;
    fn finalize(self: Box<Self>) -> Result<W>;
}

/// Trait for streaming decryption
pub trait StreamingDecryptor<R: Read>: Send {
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn verify_integrity(&self) -> Result<()>;
}

/// ChaCha20Poly1305 streaming encryptor
struct ChaCha20Poly1305StreamingEncryptor<W: Write + Send> {
    writer: W,
    cipher: ChaCha20Poly1305,
    chunk_index: u64,
    chunk_size: usize,
    buffer: Vec<u8>,
    hasher: blake3::Hasher,
}

impl<W: Write + Send> ChaCha20Poly1305StreamingEncryptor<W> {
    fn new(key: &EncryptionKey, writer: W, header: StreamingEncryptionHeader) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| UraniumError::Encryption(e.to_string()))?;

        // Write header to output
        let mut encryptor = Self {
            writer,
            cipher,
            chunk_index: 0,
            chunk_size: header.chunk_size,
            buffer: Vec::with_capacity(header.chunk_size),
            hasher: blake3::Hasher::new(),
        };

        // Serialize and write the header
        let header_bytes =
            bincode::serialize(&header).map_err(|e| UraniumError::Serialization(e.to_string()))?;
        let header_len = header_bytes.len() as u32;

        encryptor.writer.write_all(&header_len.to_le_bytes())?;
        encryptor.writer.write_all(&header_bytes)?;

        Ok(encryptor)
    }

    fn encrypt_and_write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        // Generate a unique nonce for this chunk
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&self.chunk_index.to_le_bytes());
        OsRng.fill_bytes(&mut nonce_bytes[8..]);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        // Encrypt the chunk
        let ciphertext = self
            .cipher
            .encrypt(nonce, chunk)
            .map_err(|e| UraniumError::Encryption(e.to_string()))?;

        // Write chunk metadata
        let chunk_len = ciphertext.len() as u32;
        self.writer.write_all(&chunk_len.to_le_bytes())?;
        self.writer.write_all(&nonce_bytes)?;
        self.writer.write_all(&ciphertext)?;

        // Update hash
        self.hasher.update(chunk);
        self.chunk_index += 1;

        Ok(())
    }
}

impl<W: Write + Send> StreamingEncryptor<W> for ChaCha20Poly1305StreamingEncryptor<W> {
    fn write_chunk(&mut self, data: &[u8]) -> Result<usize> {
        let mut written = 0;

        // Add data to buffer
        self.buffer.extend_from_slice(data);
        written += data.len();

        // Process complete chunks
        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            self.encrypt_and_write_chunk(&chunk)?;
        }

        Ok(written)
    }

    fn finalize(mut self: Box<Self>) -> Result<W> {
        // Encrypt any remaining data
        if !self.buffer.is_empty() {
            let final_chunk: Vec<u8> = self.buffer.drain(..).collect();
            self.encrypt_and_write_chunk(&final_chunk)?;
        }

        // Write end-of-chunks marker (chunk length = 0)
        self.writer.write_all(&0u32.to_le_bytes())?;

        // Write integrity hash
        let hash = self.hasher.finalize();
        self.writer.write_all(hash.as_bytes())?;

        self.writer.flush()?;
        Ok(self.writer)
    }
}

/// ChaCha20Poly1305 streaming decryptor
struct ChaCha20Poly1305StreamingDecryptor<R: Read + Send> {
    reader: R,
    cipher: ChaCha20Poly1305,
    _header: StreamingEncryptionHeader,
    chunk_index: u64,
    buffer: Vec<u8>,
    hasher: blake3::Hasher,
    expected_hash: Option<Vec<u8>>,
}

impl<R: Read + Send> ChaCha20Poly1305StreamingDecryptor<R> {
    fn new(key: &EncryptionKey, mut reader: R) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| UraniumError::Decryption(e.to_string()))?;

        // Read header
        let mut header_len_bytes = [0u8; 4];
        reader.read_exact(&mut header_len_bytes)?;
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;

        let header: StreamingEncryptionHeader = bincode::deserialize(&header_bytes)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;

        Ok(Self {
            reader,
            cipher,
            _header: header,
            chunk_index: 0,
            buffer: Vec::new(),
            hasher: blake3::Hasher::new(),
            expected_hash: None,
        })
    }

    fn decrypt_next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        // Try to read chunk length
        let mut chunk_len_bytes = [0u8; 4];
        let mut bytes_read = 0;

        // Read chunk length with proper EOF handling
        loop {
            match self.reader.read(&mut chunk_len_bytes[bytes_read..]) {
                Ok(0) => {
                    // EOF reached
                    if bytes_read == 0 {
                        // Clean EOF, try to read hash
                        self.read_final_hash();
                        return Ok(None);
                    } else {
                        // Partial read, error
                        return Err(UraniumError::Decryption(
                            "Incomplete chunk header".to_string(),
                        ));
                    }
                }
                Ok(n) => {
                    bytes_read += n;
                    if bytes_read == 4 {
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;

        // Check for end-of-chunks marker
        if chunk_len == 0 {
            self.read_final_hash();
            return Ok(None);
        }

        // Read nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.reader.read_exact(&mut nonce_bytes)?;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        // Read ciphertext
        let mut ciphertext = vec![0u8; chunk_len];
        self.reader.read_exact(&mut ciphertext)?;

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| UraniumError::Decryption(e.to_string()))?;

        // Update hash
        self.hasher.update(&plaintext);
        self.chunk_index += 1;

        Ok(Some(plaintext))
    }

    fn read_final_hash(&mut self) {
        let mut hash_bytes = Vec::new();
        let _ = self.reader.read_to_end(&mut hash_bytes);

        if hash_bytes.len() == 32 {
            self.expected_hash = Some(hash_bytes);
        } else {
            // No hash or incomplete hash, use computed hash
            let hash = self.hasher.clone().finalize();
            self.expected_hash = Some(hash.as_bytes().to_vec());
        }
    }
}

impl<R: Read + Send> StreamingDecryptor<R> for ChaCha20Poly1305StreamingDecryptor<R> {
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.buffer.is_empty() {
            // Try to decrypt next chunk
            match self.decrypt_next_chunk()? {
                Some(chunk) => self.buffer = chunk,
                None => return Ok(0), // EOF
            }
        }

        // Copy data from buffer to output
        let to_copy = std::cmp::min(buf.len(), self.buffer.len());
        buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
        self.buffer.drain(..to_copy);

        Ok(to_copy)
    }

    fn verify_integrity(&self) -> Result<()> {
        if let Some(ref expected_hash) = self.expected_hash {
            let computed_hash = self.hasher.clone().finalize();
            if computed_hash.as_bytes() != expected_hash.as_slice() {
                return Err(UraniumError::IntegrityCheckFailed {
                    id: "streaming_decryption".to_string(),
                });
            }
        }
        Ok(())
    }
}

impl StreamingCrypto for VaultCrypto {
    fn create_encryptor<W: Write + Send + 'static>(
        &self,
        key: &EncryptionKey,
        writer: W,
        header: StreamingEncryptionHeader,
    ) -> Result<Box<dyn StreamingEncryptor<W>>> {
        match self.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => Ok(Box::new(
                ChaCha20Poly1305StreamingEncryptor::new(key, writer, header)?,
            )),
            EncryptionAlgorithm::AesGcm256 => {
                // TODO: Implement AES-GCM streaming
                Err(UraniumError::Encryption(
                    "AES-GCM streaming not yet implemented".to_string(),
                ))
            }
        }
    }

    fn create_decryptor<R: Read + Send + 'static>(
        &self,
        key: &EncryptionKey,
        reader: R,
    ) -> Result<Box<dyn StreamingDecryptor<R>>> {
        match self.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => Ok(Box::new(
                ChaCha20Poly1305StreamingDecryptor::new(key, reader)?,
            )),
            EncryptionAlgorithm::AesGcm256 => {
                // TODO: Implement AES-GCM streaming
                Err(UraniumError::Decryption(
                    "AES-GCM streaming not yet implemented".to_string(),
                ))
            }
        }
    }
}

pub struct PasswordManager {
    argon2: Argon2<'static>,
}

impl Default for PasswordManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordManager {
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<String> {
        use argon2::password_hash::PasswordHasher;

        let salt = SaltString::generate(&mut OsRng);

        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| UraniumError::Encryption(e.to_string()))
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| UraniumError::Decryption(e.to_string()))?;

        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(UraniumError::Decryption(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = EncryptionKey::generate();
        let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
        let plaintext = b"Hello, Uranium!";

        let encrypted = crypto.encrypt(&key, plaintext).unwrap();
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_password_derivation() {
        let password = "secure_password123";
        let salt = VaultCrypto::generate_salt();

        let key1 = EncryptionKey::derive_from_password(password, &salt).unwrap();
        let key2 = EncryptionKey::derive_from_password(password, &salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_password_hashing() {
        let password_manager = PasswordManager::new();
        let password = "test_password123!";

        let hash = password_manager.hash_password(password).unwrap();
        assert!(password_manager.verify_password(password, &hash).unwrap());
        assert!(!password_manager
            .verify_password("wrong_password", &hash)
            .unwrap());
    }

    #[test]
    fn test_streaming_encryption_small_data() {
        use std::io::Cursor;

        let key = EncryptionKey::generate();
        let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
        let plaintext = b"Hello, streaming encryption!";

        // Encrypt
        let header = StreamingEncryptionHeader {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            salt: None,
            chunk_size: 64 * 1024, // 64KB chunks
            total_size: Some(plaintext.len() as u64),
        };

        let encrypted_data = {
            let data = Vec::new();
            let writer = Cursor::new(data);
            let mut encryptor = crypto.create_encryptor(&key, writer, header).unwrap();

            encryptor.write_chunk(plaintext).unwrap();
            let cursor = encryptor.finalize().unwrap();
            cursor.into_inner()
        };

        // Decrypt
        let reader = Cursor::new(encrypted_data);
        let mut decryptor = crypto.create_decryptor(&key, reader).unwrap();

        let mut decrypted = Vec::new();
        let mut buffer = [0u8; 1024];

        loop {
            let n = decryptor.read_chunk(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            decrypted.extend_from_slice(&buffer[..n]);
        }

        assert_eq!(plaintext, decrypted.as_slice());
        assert!(decryptor.verify_integrity().is_ok());
    }

    #[test]
    fn test_streaming_encryption_large_data() {
        use std::io::Cursor;

        let key = EncryptionKey::generate();
        let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);

        // Create large test data (5MB)
        let plaintext: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

        // Encrypt
        let header = StreamingEncryptionHeader {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            salt: None,
            chunk_size: 64 * 1024, // 64KB chunks
            total_size: Some(plaintext.len() as u64),
        };

        let encrypted_data = {
            let data = Vec::new();
            let writer = Cursor::new(data);
            let mut encryptor = crypto.create_encryptor(&key, writer, header).unwrap();

            // Write in smaller chunks to simulate streaming
            for chunk in plaintext.chunks(8192) {
                encryptor.write_chunk(chunk).unwrap();
            }
            let cursor = encryptor.finalize().unwrap();
            cursor.into_inner()
        };

        // Decrypt
        let reader = Cursor::new(encrypted_data);
        let mut decryptor = crypto.create_decryptor(&key, reader).unwrap();

        let mut decrypted = Vec::new();
        let mut buffer = [0u8; 8192];

        loop {
            let n = decryptor.read_chunk(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            decrypted.extend_from_slice(&buffer[..n]);
        }

        assert_eq!(plaintext, decrypted);
        assert!(decryptor.verify_integrity().is_ok());
    }

    #[test]
    fn test_streaming_integrity_check() {
        use std::io::Cursor;

        let key = EncryptionKey::generate();
        let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
        let plaintext = b"Integrity test data";

        // Encrypt
        let header = StreamingEncryptionHeader {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            salt: None,
            chunk_size: 64 * 1024, // 64KB chunks
            total_size: Some(plaintext.len() as u64),
        };

        let mut encrypted_data = {
            let data = Vec::new();
            let writer = Cursor::new(data);
            let mut encryptor = crypto.create_encryptor(&key, writer, header).unwrap();

            encryptor.write_chunk(plaintext).unwrap();
            let cursor = encryptor.finalize().unwrap();
            cursor.into_inner()
        };

        // Corrupt the encrypted data
        let data_len = encrypted_data.len();
        encrypted_data[data_len / 2] ^= 0x01;

        // Try to decrypt - should fail
        let reader = Cursor::new(encrypted_data);
        let mut decryptor = crypto.create_decryptor(&key, reader).unwrap();

        let mut buffer = [0u8; 1024];

        // Decryption should fail due to AEAD authentication
        let result = decryptor.read_chunk(&mut buffer);
        assert!(result.is_err());
    }
}
