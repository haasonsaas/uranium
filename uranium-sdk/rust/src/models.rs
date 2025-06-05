use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Model storage format
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ModelFormat {
    SafeTensors,
    ONNX,
    PyTorch,
    TensorFlow,
    Unknown,
}

/// Model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: Uuid,
    pub name: String,
    pub size: usize,
    pub encrypted_with_se: bool,
    pub created_at: DateTime<Utc>,
}

/// Vault status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub vault_status: String,
    pub secure_enclave_available: bool,
    pub secure_enclave_enabled: bool,
    pub models_count: usize,
}

/// Model metadata (full details)
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
}

/// Error response from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}
