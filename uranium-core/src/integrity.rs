use blake3::Hasher;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::errors::{Result, UraniumError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelHash {
    pub algorithm: HashAlgorithm,
    pub hash: Vec<u8>,
    pub chunks: Option<Vec<ChunkHash>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHash {
    pub index: u32,
    pub hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Sha512,
}

pub struct IntegrityVerifier {
    algorithm: HashAlgorithm,
}

impl IntegrityVerifier {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        match self.algorithm {
            HashAlgorithm::Blake3 => {
                let mut hasher = Hasher::new();
                hasher.update(data);
                hasher.finalize().as_bytes().to_vec()
            }
            HashAlgorithm::Sha256 => {
                use ring::digest;
                digest::digest(&digest::SHA256, data).as_ref().to_vec()
            }
            HashAlgorithm::Sha512 => {
                use ring::digest;
                digest::digest(&digest::SHA512, data).as_ref().to_vec()
            }
        }
    }

    pub fn hash_file<R: Read>(&self, mut reader: R) -> Result<Vec<u8>> {
        match self.algorithm {
            HashAlgorithm::Blake3 => {
                let mut hasher = Hasher::new();
                let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer

                loop {
                    let bytes_read = reader.read(&mut buffer).map_err(UraniumError::Storage)?;

                    if bytes_read == 0 {
                        break;
                    }

                    hasher.update(&buffer[..bytes_read]);
                }

                Ok(hasher.finalize().as_bytes().to_vec())
            }
            HashAlgorithm::Sha256 | HashAlgorithm::Sha512 => {
                use ring::digest::{Context, SHA256, SHA512};

                let algorithm = match self.algorithm {
                    HashAlgorithm::Sha256 => &SHA256,
                    HashAlgorithm::Sha512 => &SHA512,
                    _ => unreachable!(),
                };

                let mut context = Context::new(algorithm);
                let mut buffer = vec![0u8; 1024 * 1024];

                loop {
                    let bytes_read = reader.read(&mut buffer).map_err(UraniumError::Storage)?;

                    if bytes_read == 0 {
                        break;
                    }

                    context.update(&buffer[..bytes_read]);
                }

                Ok(context.finish().as_ref().to_vec())
            }
        }
    }

    pub fn hash_chunks(&self, data: &[u8], chunk_size: usize) -> ModelHash {
        let mut chunks = Vec::new();
        let mut overall_hasher = match self.algorithm {
            HashAlgorithm::Blake3 => Some(Hasher::new()),
            _ => None,
        };

        for (index, chunk) in data.chunks(chunk_size).enumerate() {
            let chunk_hash = self.hash_data(chunk);
            chunks.push(ChunkHash {
                index: index as u32,
                hash: chunk_hash,
            });

            if let Some(ref mut hasher) = overall_hasher {
                hasher.update(chunk);
            }
        }

        let overall_hash = match overall_hasher {
            Some(hasher) => hasher.finalize().as_bytes().to_vec(),
            None => self.hash_data(data),
        };

        ModelHash {
            algorithm: self.algorithm,
            hash: overall_hash,
            chunks: Some(chunks),
        }
    }

    pub fn verify(&self, data: &[u8], expected_hash: &ModelHash) -> Result<()> {
        if expected_hash.algorithm != self.algorithm {
            return Err(UraniumError::IntegrityCheckFailed {
                id: "algorithm_mismatch".to_string(),
            });
        }

        let computed_hash = self.hash_data(data);

        if computed_hash != expected_hash.hash {
            return Err(UraniumError::IntegrityCheckFailed {
                id: "hash_mismatch".to_string(),
            });
        }

        // Verify chunks if present
        if let Some(ref expected_chunks) = expected_hash.chunks {
            let chunk_size = data.len() / expected_chunks.len();

            for (index, (chunk, expected_chunk)) in data
                .chunks(chunk_size)
                .zip(expected_chunks.iter())
                .enumerate()
            {
                let chunk_hash = self.hash_data(chunk);
                if chunk_hash != expected_chunk.hash {
                    return Err(UraniumError::IntegrityCheckFailed {
                        id: format!("chunk_{}_mismatch", index),
                    });
                }
            }
        }

        Ok(())
    }

    pub fn create_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&signing_key, data).as_ref().to_vec()
    }

    pub fn verify_hmac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);

        hmac::verify(&signing_key, data, tag).map_err(|_| UraniumError::IntegrityCheckFailed {
            id: "hmac_verification_failed".to_string(),
        })
    }
}

pub struct StreamingHasher {
    hasher: Blake3Hasher,
}

enum Blake3Hasher {
    Blake3(Hasher),
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingHasher {
    pub fn new() -> Self {
        Self {
            hasher: Blake3Hasher::Blake3(Hasher::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match &mut self.hasher {
            Blake3Hasher::Blake3(hasher) => {
                hasher.update(data);
            }
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self.hasher {
            Blake3Hasher::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verification() {
        let data = b"Test model data";
        let verifier = IntegrityVerifier::new(HashAlgorithm::Blake3);

        let hash = verifier.hash_data(data);
        let model_hash = ModelHash {
            algorithm: HashAlgorithm::Blake3,
            hash,
            chunks: None,
        };

        assert!(verifier.verify(data, &model_hash).is_ok());

        // Test with wrong data
        let wrong_data = b"Wrong model data";
        assert!(verifier.verify(wrong_data, &model_hash).is_err());
    }

    #[test]
    fn test_chunked_hashing() {
        let data = vec![0u8; 1024 * 10]; // 10KB
        let verifier = IntegrityVerifier::new(HashAlgorithm::Blake3);

        let model_hash = verifier.hash_chunks(&data, 1024);

        assert!(model_hash.chunks.is_some());
        assert_eq!(model_hash.chunks.as_ref().unwrap().len(), 10);
        assert!(verifier.verify(&data, &model_hash).is_ok());
    }
}
