use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub format: ModelFormat,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub framework: Option<ModelFramework>,
    pub architecture: Option<String>,
    pub parameters_count: Option<u64>,
    pub watermark: Option<Vec<u8>>,
    pub license_constraints: Option<LicenseConstraints>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ModelFormat {
    SafeTensors,
    ONNX,
    PyTorch,
    TensorFlow,
    Custom(u32),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ModelFramework {
    PyTorch,
    TensorFlow,
    JAX,
    ONNX,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConstraints {
    pub max_instances: Option<u32>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub allowed_hosts: Option<Vec<String>>,
    pub usage_quota: Option<UsageQuota>,
    pub restricted_operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageQuota {
    pub max_inferences: Option<u64>,
    pub max_batch_size: Option<u32>,
    pub time_window_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAccess {
    pub model_id: Uuid,
    pub user_id: String,
    pub session_id: Uuid,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Permission {
    Read,
    Execute,
    Export,
    Admin,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptedModel {
    pub metadata: ModelMetadata,
    #[serde(skip_serializing)]
    pub weights: Vec<u8>,
}

impl Drop for DecryptedModel {
    fn drop(&mut self) {
        self.weights.zeroize();
    }
}

impl DecryptedModel {
    pub fn new(metadata: ModelMetadata, weights: Vec<u8>) -> Self {
        Self { metadata, weights }
    }

    pub fn verify_integrity(&self, expected_hash: &[u8]) -> crate::Result<()> {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&self.weights);
        let computed_hash = hasher.finalize();

        if computed_hash.as_bytes() != expected_hash {
            return Err(crate::errors::UraniumError::IntegrityCheckFailed {
                id: self.metadata.id.to_string(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelChunk {
    pub model_id: Uuid,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub hash: Vec<u8>,
}

impl ModelFormat {
    pub fn is_safe(&self) -> bool {
        matches!(self, ModelFormat::SafeTensors | ModelFormat::ONNX)
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            ModelFormat::SafeTensors => ".safetensors",
            ModelFormat::ONNX => ".onnx",
            ModelFormat::PyTorch => ".pt",
            ModelFormat::TensorFlow => ".pb",
            ModelFormat::Custom(_) => ".bin",
        }
    }
}
