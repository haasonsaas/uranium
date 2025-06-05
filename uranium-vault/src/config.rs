use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use uranium_core::crypto::EncryptionAlgorithm;
use uranium_core::integrity::HashAlgorithm;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfiguration {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub auth: AuthConfig,
    pub audit: AuditConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub unix_socket_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub encryption_algorithm: EncryptionAlgorithm,
    pub hash_algorithm: HashAlgorithm,
    pub enable_memory_protection: bool,
    pub enable_secure_enclave: bool,
    pub master_key_source: KeySource,
    pub require_mfa: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeySource {
    Environment,
    File(PathBuf),
    HardwareSecurityModule { provider: String, key_id: String },
    Prompt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub base_path: PathBuf,
    pub database_url: String,
    pub enable_compression: bool,
    pub compression_type: Option<String>,
    pub chunk_size_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_duration_hours: i64,
    pub session_timeout_minutes: u64,
    pub max_sessions_per_user: usize,
    pub password_requirements: PasswordRequirements,
    pub ldap_config: Option<LdapConfig>,
    pub oauth_config: Option<OAuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRequirements {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub server_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_base_dn: String,
    pub user_filter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub backend: AuditBackend,
    pub retention_days: u32,
    pub enable_security_monitoring: bool,
    pub alert_webhook: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditBackend {
    File { path: PathBuf },
    Database,
    Syslog { address: String },
    CloudWatch { region: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub cache_size_mb: usize,
    pub max_concurrent_loads: usize,
    pub prefetch_models: Vec<String>,
    pub enable_metrics: bool,
    pub metrics_port: Option<u16>,
}

impl Default for VaultConfiguration {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8443,
                tls_cert_path: None,
                tls_key_path: None,
                unix_socket_path: Some(PathBuf::from("/tmp/uranium.sock")),
            },
            security: SecurityConfig {
                encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
                hash_algorithm: HashAlgorithm::Blake3,
                enable_memory_protection: true,
                enable_secure_enclave: false,
                master_key_source: KeySource::Environment,
                require_mfa: false,
            },
            storage: StorageConfig {
                base_path: PathBuf::from("./vault/models"),
                database_url: "sqlite://vault.db".to_string(),
                enable_compression: false,
                compression_type: None,
                chunk_size_mb: 64,
            },
            auth: AuthConfig {
                jwt_secret: "change-me-in-production".to_string(),
                token_duration_hours: 24,
                session_timeout_minutes: 60,
                max_sessions_per_user: 5,
                password_requirements: PasswordRequirements {
                    min_length: 12,
                    require_uppercase: true,
                    require_lowercase: true,
                    require_numbers: true,
                    require_special_chars: true,
                },
                ldap_config: None,
                oauth_config: None,
            },
            audit: AuditConfig {
                backend: AuditBackend::Database,
                retention_days: 90,
                enable_security_monitoring: true,
                alert_webhook: None,
            },
            performance: PerformanceConfig {
                cache_size_mb: 1024,
                max_concurrent_loads: 10,
                prefetch_models: Vec::new(),
                enable_metrics: true,
                metrics_port: Some(9090),
            },
        }
    }
}

impl VaultConfiguration {
    pub fn load() -> Result<Self, ConfigError> {
        let config = Config::builder()
            // Start with default values
            .add_source(Config::try_from(&Self::default())?)
            // Add config file if it exists
            .add_source(File::with_name("uranium.toml").required(false))
            .add_source(File::with_name("/etc/uranium/config.toml").required(false))
            // Override with environment variables
            .add_source(Environment::with_prefix("URANIUM").separator("__"))
            .build()?;

        config.try_deserialize()
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate configuration
        if self.server.port == 0 {
            return Err("Server port must be non-zero".to_string());
        }

        if self.auth.jwt_secret == "change-me-in-production" {
            return Err("JWT secret must be changed from default".to_string());
        }

        if self.performance.cache_size_mb == 0 {
            return Err("Cache size must be greater than 0".to_string());
        }

        if self.storage.chunk_size_mb == 0 {
            return Err("Chunk size must be greater than 0".to_string());
        }

        Ok(())
    }
}
