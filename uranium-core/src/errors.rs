use thiserror::Error;

#[derive(Error, Debug)]
pub enum UraniumError {
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Authorization denied for resource: {resource}")]
    AuthorizationDenied { resource: String },

    #[error("Model not found: {id}")]
    ModelNotFound { id: String },

    #[error("Integrity check failed for model: {id}")]
    IntegrityCheckFailed { id: String },

    #[error("Invalid model format: {format}")]
    InvalidModelFormat { format: String },

    #[error("Storage error: {0}")]
    Storage(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Vault locked")]
    VaultLocked,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Concurrent access denied")]
    ConcurrentAccessDenied,

    #[error("Memory protection error: {0}")]
    MemoryProtection(String),

    #[error("License validation failed: {0}")]
    LicenseValidation(String),

    #[error("Audit log error: {0}")]
    AuditLog(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, UraniumError>;
