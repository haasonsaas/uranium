pub mod secure;
#[cfg(target_os = "macos")]
pub mod secure_enclave_storage;

#[cfg(target_os = "macos")]
pub use secure_enclave_storage::{SecureEnclaveStorage, SecureEnclaveStorageBuilder};

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::crypto::{
    EncryptedData, EncryptionKey, StreamingCrypto, StreamingEncryptionHeader, VaultCrypto,
};
use crate::errors::{Result, UraniumError};
use crate::integrity::{IntegrityVerifier, ModelHash};
use crate::models::{DecryptedModel, ModelMetadata};

const CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64MB chunks

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedModel {
    pub metadata: ModelMetadata,
    pub encrypted_data: EncryptedData,
    pub integrity_hash: ModelHash,
    pub format_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedModelHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub metadata_size: u64,
    pub model_size: u64,
    pub compression: Option<CompressionType>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Zstd,
    Lz4,
}

pub struct ModelStorage {
    base_path: PathBuf,
    crypto: VaultCrypto,
    verifier: IntegrityVerifier,
}

impl ModelStorage {
    pub fn new(
        base_path: impl AsRef<Path>,
        crypto: VaultCrypto,
        verifier: IntegrityVerifier,
    ) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&base_path)?;

        Ok(Self {
            base_path,
            crypto,
            verifier,
        })
    }

    pub fn store_model(
        &self,
        model_id: Uuid,
        metadata: ModelMetadata,
        weights: &[u8],
        key: &EncryptionKey,
    ) -> Result<PathBuf> {
        // Compute integrity hash before encryption
        let integrity_hash = ModelHash {
            algorithm: crate::integrity::HashAlgorithm::Blake3,
            hash: self.verifier.hash_data(weights),
            chunks: None,
        };

        // Encrypt the model weights
        let encrypted_data = self.crypto.encrypt(key, weights)?;

        // Create the encrypted model structure
        let encrypted_model = EncryptedModel {
            metadata,
            encrypted_data,
            integrity_hash,
            format_version: 1,
        };

        // Serialize and save to disk
        let file_path = self.model_path(model_id);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)?;

        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &encrypted_model)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;

        Ok(file_path)
    }

    pub fn load_model(&self, model_id: Uuid, key: &EncryptionKey) -> Result<DecryptedModel> {
        let file_path = self.model_path(model_id);

        if !file_path.exists() {
            return Err(UraniumError::ModelNotFound {
                id: model_id.to_string(),
            });
        }

        // Load encrypted model from disk
        let file = File::open(&file_path)?;
        let reader = BufReader::new(file);

        let encrypted_model: EncryptedModel = bincode::deserialize_from(reader)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;

        // Decrypt the weights
        let weights = self.crypto.decrypt(key, &encrypted_model.encrypted_data)?;

        // Verify integrity
        let computed_hash = self.verifier.hash_data(&weights);
        if computed_hash != encrypted_model.integrity_hash.hash {
            return Err(UraniumError::IntegrityCheckFailed {
                id: model_id.to_string(),
            });
        }

        Ok(DecryptedModel::new(encrypted_model.metadata, weights))
    }

    pub fn store_model_streaming<R: Read>(
        &self,
        model_id: Uuid,
        metadata: ModelMetadata,
        mut reader: R,
        key: &EncryptionKey,
    ) -> Result<PathBuf> {
        let file_path = self.model_path(model_id);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)?;

        // Create streaming header
        let header = StreamingEncryptionHeader {
            algorithm: self.crypto.algorithm(),
            salt: None,
            chunk_size: CHUNK_SIZE,
            total_size: Some(metadata.size_bytes),
            mac_algorithm: crate::crypto::MacAlgorithm::Blake3Keyed,
            mac_salt: Vec::new(),
        };

        // Write metadata first
        let mut writer = BufWriter::new(file);
        let metadata_bytes = bincode::serialize(&metadata)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;
        let metadata_len = metadata_bytes.len() as u32;

        writer.write_all(&metadata_len.to_le_bytes())?;
        writer.write_all(&metadata_bytes)?;

        // Create streaming encryptor
        let mut encryptor = self.crypto.create_encryptor(key, writer, header)?;

        // Stream and encrypt data
        let mut buffer = vec![0u8; 8192];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            encryptor.write_chunk(&buffer[..n])?;
        }

        // Finalize encryption
        encryptor.finalize()?;

        Ok(file_path)
    }

    pub fn load_model_streaming<W: Write>(
        &self,
        model_id: Uuid,
        key: &EncryptionKey,
        mut writer: W,
    ) -> Result<ModelMetadata> {
        let file_path = self.model_path(model_id);

        if !file_path.exists() {
            return Err(UraniumError::ModelNotFound {
                id: model_id.to_string(),
            });
        }

        let file = File::open(&file_path)?;
        let mut reader = BufReader::new(file);

        // Read metadata
        let mut metadata_len_bytes = [0u8; 4];
        reader.read_exact(&mut metadata_len_bytes)?;
        let metadata_len = u32::from_le_bytes(metadata_len_bytes) as usize;

        let mut metadata_bytes = vec![0u8; metadata_len];
        reader.read_exact(&mut metadata_bytes)?;

        let metadata: ModelMetadata = bincode::deserialize(&metadata_bytes)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;

        // Create streaming decryptor
        let mut decryptor = self.crypto.create_decryptor(key, reader)?;

        // Stream and decrypt data
        let mut buffer = vec![0u8; 8192];
        loop {
            let n = decryptor.read_chunk(&mut buffer)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buffer[..n])?;
        }

        // Verify integrity
        decryptor.verify_integrity()?;

        Ok(metadata)
    }

    pub fn stream_model<F>(
        &self,
        model_id: Uuid,
        key: &EncryptionKey,
        mut processor: F,
    ) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let file_path = self.model_path(model_id);

        if !file_path.exists() {
            return Err(UraniumError::ModelNotFound {
                id: model_id.to_string(),
            });
        }

        let file = File::open(&file_path)?;
        let mut reader = BufReader::new(file);

        // Read metadata
        let mut metadata_len_bytes = [0u8; 4];
        reader.read_exact(&mut metadata_len_bytes)?;
        let metadata_len = u32::from_le_bytes(metadata_len_bytes) as usize;

        let mut metadata_bytes = vec![0u8; metadata_len];
        reader.read_exact(&mut metadata_bytes)?;

        // Create streaming decryptor
        let mut decryptor = self.crypto.create_decryptor(key, reader)?;

        // Process decrypted data in chunks
        let mut buffer = vec![0u8; CHUNK_SIZE];
        loop {
            let n = decryptor.read_chunk(&mut buffer)?;
            if n == 0 {
                break;
            }
            processor(&buffer[..n])?;
        }

        // Verify integrity
        decryptor.verify_integrity()?;

        Ok(())
    }

    pub fn delete_model(&self, model_id: Uuid) -> Result<()> {
        let file_path = self.model_path(model_id);

        if file_path.exists() {
            // Securely overwrite the file before deletion
            self.secure_delete(&file_path)?;
        }

        Ok(())
    }

    pub fn list_models(&self) -> Result<Vec<Uuid>> {
        let mut models = Vec::new();

        for entry in std::fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("umodel") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(uuid) = Uuid::parse_str(stem) {
                        models.push(uuid);
                    }
                }
            }
        }

        Ok(models)
    }

    pub fn get_model_metadata(&self, model_id: Uuid) -> Result<ModelMetadata> {
        let file_path = self.model_path(model_id);

        if !file_path.exists() {
            return Err(UraniumError::ModelNotFound {
                id: model_id.to_string(),
            });
        }

        // Read just the metadata without decrypting the entire model
        let file = File::open(&file_path)?;
        let reader = BufReader::new(file);

        let encrypted_model: EncryptedModel = bincode::deserialize_from(reader)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;

        Ok(encrypted_model.metadata)
    }

    fn model_path(&self, model_id: Uuid) -> PathBuf {
        self.base_path.join(format!("{}.umodel", model_id))
    }

    fn secure_delete(&self, path: &Path) -> Result<()> {
        use rand::RngCore;

        let file = OpenOptions::new().write(true).open(path)?;

        let file_len = file.metadata()?.len();
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; 4096];

        // Overwrite with random data multiple times
        for _ in 0..3 {
            let mut writer = BufWriter::new(&file);
            let mut written = 0u64;

            while written < file_len {
                rng.fill_bytes(&mut buffer);
                let to_write = std::cmp::min(buffer.len(), (file_len - written) as usize);
                writer.write_all(&buffer[..to_write])?;
                written += to_write as u64;
            }

            writer.flush()?;
            writer.get_ref().sync_all()?;
        }

        // Finally delete the file
        std::fs::remove_file(path)?;

        Ok(())
    }
}

/// A wrapper that provides Read interface for streaming decryption
pub struct StreamingModelReader {
    metadata: ModelMetadata,
    decryptor: Box<dyn StreamingDecryptor<BufReader<File>> + Send>,
}

impl StreamingModelReader {
    pub fn metadata(&self) -> &ModelMetadata {
        &self.metadata
    }
}

impl Read for StreamingModelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decryptor
            .read_chunk(buf)
            .map_err(std::io::Error::other)
    }
}

/// A wrapper that provides Write interface for streaming encryption
pub struct StreamingModelWriter {
    model_id: Uuid,
    encryptor: Box<dyn StreamingEncryptor<BufWriter<File>> + Send>,
}

impl Write for StreamingModelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encryptor
            .write_chunk(buf)
            .map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl StreamingModelWriter {
    pub fn finalize(self) -> Result<PathBuf> {
        let writer = self.encryptor.finalize()?;
        writer
            .into_inner()
            .map_err(|e| UraniumError::Storage(e.into_error()))?
            .sync_all()?;

        Ok(PathBuf::from(format!("{}.umodel", self.model_id)))
    }
}

impl ModelStorage {
    /// Creates a streaming reader for a model
    pub fn create_streaming_reader(
        &self,
        model_id: Uuid,
        key: &EncryptionKey,
    ) -> Result<StreamingModelReader> {
        let file_path = self.model_path(model_id);

        if !file_path.exists() {
            return Err(UraniumError::ModelNotFound {
                id: model_id.to_string(),
            });
        }

        let file = File::open(&file_path)?;
        let mut reader = BufReader::new(file);

        // Read metadata
        let mut metadata_len_bytes = [0u8; 4];
        reader.read_exact(&mut metadata_len_bytes)?;
        let metadata_len = u32::from_le_bytes(metadata_len_bytes) as usize;

        let mut metadata_bytes = vec![0u8; metadata_len];
        reader.read_exact(&mut metadata_bytes)?;

        let metadata: ModelMetadata = bincode::deserialize(&metadata_bytes)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;

        // Create streaming decryptor
        let decryptor = self.crypto.create_decryptor(key, reader)?;

        Ok(StreamingModelReader {
            metadata,
            decryptor,
        })
    }

    /// Creates a streaming writer for a model
    pub fn create_streaming_writer(
        &self,
        model_id: Uuid,
        metadata: ModelMetadata,
        key: &EncryptionKey,
    ) -> Result<StreamingModelWriter> {
        let file_path = self.model_path(model_id);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)?;

        // Create streaming header
        let header = StreamingEncryptionHeader {
            algorithm: self.crypto.algorithm(),
            salt: None,
            chunk_size: CHUNK_SIZE,
            total_size: Some(metadata.size_bytes),
            mac_algorithm: crate::crypto::MacAlgorithm::Blake3Keyed,
            mac_salt: Vec::new(),
        };

        // Write metadata first
        let mut writer = BufWriter::new(file);
        let metadata_bytes = bincode::serialize(&metadata)
            .map_err(|e| UraniumError::Serialization(e.to_string()))?;
        let metadata_len = metadata_bytes.len() as u32;

        writer.write_all(&metadata_len.to_le_bytes())?;
        writer.write_all(&metadata_bytes)?;

        // Create streaming encryptor
        let encryptor = self.crypto.create_encryptor(key, writer, header)?;

        Ok(StreamingModelWriter {
            model_id,
            encryptor,
        })
    }
}

use crate::crypto::{StreamingDecryptor, StreamingEncryptor};

pub struct ChunkedModelStorage {
    storage: ModelStorage,
}

impl ChunkedModelStorage {
    pub fn new(storage: ModelStorage) -> Self {
        Self { storage }
    }

    pub fn store_model_chunked(
        &self,
        _model_id: Uuid,
        metadata: ModelMetadata,
        weights: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        let chunks: Vec<_> = weights.chunks(CHUNK_SIZE).collect();
        let _total_chunks = chunks.len() as u32;

        for (index, chunk) in chunks.into_iter().enumerate() {
            let chunk_id = Uuid::new_v4();
            let chunk_metadata = ModelMetadata {
                id: chunk_id,
                name: format!("{}_chunk_{}", metadata.name, index),
                ..metadata.clone()
            };

            let path = self
                .storage
                .store_model(chunk_id, chunk_metadata, chunk, key)?;
            paths.push(path);
        }

        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncryptionAlgorithm;
    use crate::integrity::HashAlgorithm;
    use chrono::Utc;
    use tempfile::TempDir;

    fn create_test_metadata() -> ModelMetadata {
        ModelMetadata {
            id: Uuid::new_v4(),
            name: "test_model".to_string(),
            version: "1.0".to_string(),
            format: crate::models::ModelFormat::SafeTensors,
            size_bytes: 1024,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            description: None,
            tags: vec![],
            framework: None,
            architecture: None,
            parameters_count: None,
            watermark: None,
            license_constraints: None,
        }
    }

    #[test]
    fn test_store_and_load_model() {
        let temp_dir = TempDir::new().unwrap();
        let storage = ModelStorage::new(
            temp_dir.path(),
            VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
            IntegrityVerifier::new(HashAlgorithm::Blake3),
        )
        .unwrap();

        let key = EncryptionKey::generate();
        let metadata = create_test_metadata();
        let model_id = metadata.id;
        let weights = vec![0u8; 1024];

        // Store model
        let path = storage
            .store_model(model_id, metadata.clone(), &weights, &key)
            .unwrap();
        assert!(path.exists());

        // Load model
        let decrypted = storage.load_model(model_id, &key).unwrap();
        assert_eq!(decrypted.weights, weights);
        assert_eq!(decrypted.metadata.id, model_id);
    }

    #[test]
    fn test_streaming_storage() {
        use std::io::Cursor;

        let temp_dir = TempDir::new().unwrap();
        let storage = ModelStorage::new(
            temp_dir.path(),
            VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
            IntegrityVerifier::new(HashAlgorithm::Blake3),
        )
        .unwrap();

        let key = EncryptionKey::generate();
        let mut metadata = create_test_metadata();
        let model_id = metadata.id;

        // Create large test data (10MB)
        let weights: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 256) as u8).collect();
        metadata.size_bytes = weights.len() as u64;

        // Store model using streaming
        let reader = Cursor::new(&weights);
        let path = storage
            .store_model_streaming(model_id, metadata.clone(), reader, &key)
            .unwrap();
        assert!(path.exists());

        // Load model using streaming
        let mut loaded_weights = Vec::new();
        let loaded_metadata = storage
            .load_model_streaming(model_id, &key, &mut loaded_weights)
            .unwrap();

        assert_eq!(loaded_metadata.id, model_id);
        assert_eq!(loaded_weights, weights);
    }

    #[test]
    fn test_stream_model_processor() {
        use std::io::Cursor;

        let temp_dir = TempDir::new().unwrap();
        let storage = ModelStorage::new(
            temp_dir.path(),
            VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
            IntegrityVerifier::new(HashAlgorithm::Blake3),
        )
        .unwrap();

        let key = EncryptionKey::generate();
        let mut metadata = create_test_metadata();
        let model_id = metadata.id;

        // Create test data
        let weights = vec![42u8; 1024 * 1024]; // 1MB of 42s
        metadata.size_bytes = weights.len() as u64;

        // Store model
        let reader = Cursor::new(&weights);
        storage
            .store_model_streaming(model_id, metadata.clone(), reader, &key)
            .unwrap();

        // Process model in chunks
        let mut total_bytes = 0;
        let mut all_42s = true;

        storage
            .stream_model(model_id, &key, |chunk| {
                total_bytes += chunk.len();
                if chunk.iter().any(|&b| b != 42) {
                    all_42s = false;
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(total_bytes, weights.len());
        assert!(all_42s);
    }
}
