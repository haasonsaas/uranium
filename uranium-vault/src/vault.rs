use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{DecryptedModel, ModelMetadata},
    storage::ModelStorage,
    Result, UraniumError,
};

#[cfg(target_os = "macos")]
use uranium_core::storage::{SecureEnclaveStorage, SecureEnclaveStorageBuilder};

use crate::audit::{AuditEvent, AuditLogger};
use crate::auth::{AuthManager, Permission, User};
use crate::cache::{CacheStats, ModelCache};
use crate::session::{Session, SessionManager};

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub storage_path: PathBuf,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub hash_algorithm: HashAlgorithm,
    pub max_concurrent_loads: usize,
    pub cache_size_mb: usize,
    pub session_timeout_minutes: u64,
    pub enable_memory_protection: bool,
    pub enable_secure_enclave: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from("./vault"),
            encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            hash_algorithm: HashAlgorithm::Blake3,
            max_concurrent_loads: 10,
            cache_size_mb: 1024,
            session_timeout_minutes: 60,
            enable_memory_protection: true,
            enable_secure_enclave: false,
        }
    }
}

pub struct Vault {
    config: VaultConfig,
    storage: Arc<ModelStorage>,
    #[cfg(target_os = "macos")]
    secure_enclave_storage: Option<Arc<SecureEnclaveStorage>>,
    auth_manager: Arc<AuthManager>,
    session_manager: Arc<SessionManager>,
    audit_logger: Arc<dyn AuditLogger>,
    cache: Arc<ModelCache>,
    load_semaphore: Arc<Semaphore>,
    master_key: Arc<RwLock<Option<EncryptionKey>>>,
}

impl Vault {
    pub fn new(
        config: VaultConfig,
        auth_manager: Arc<AuthManager>,
        audit_logger: Arc<dyn AuditLogger>,
    ) -> Result<Self> {
        let storage = Arc::new(ModelStorage::new(
            &config.storage_path,
            VaultCrypto::new(config.encryption_algorithm),
            IntegrityVerifier::new(config.hash_algorithm),
        )?);

        #[cfg(target_os = "macos")]
        let secure_enclave_storage = if config.enable_secure_enclave
            && SecureEnclaveStorage::is_secure_enclave_available()
        {
            tracing::info!("Secure Enclave available - enabling hardware-backed encryption");
            let se_storage = SecureEnclaveStorageBuilder::new()
                .with_path(&config.storage_path)
                .with_algorithm(config.encryption_algorithm)
                .build()?;
            Some(Arc::new(se_storage))
        } else {
            if config.enable_secure_enclave {
                tracing::warn!("Secure Enclave requested but not available on this device");
            }
            None
        };

        let _crypto = Arc::new(VaultCrypto::new(config.encryption_algorithm));
        let _verifier = Arc::new(IntegrityVerifier::new(config.hash_algorithm));
        let session_manager = Arc::new(SessionManager::new(
            config.session_timeout_minutes,
            auth_manager.get_provider(),
        ));
        let cache = Arc::new(ModelCache::new(config.cache_size_mb));
        let load_semaphore = Arc::new(Semaphore::new(config.max_concurrent_loads));

        Ok(Self {
            config,
            storage,
            #[cfg(target_os = "macos")]
            secure_enclave_storage,
            auth_manager,
            session_manager,
            audit_logger,
            cache,
            load_semaphore,
            master_key: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn unlock(&self, master_key: EncryptionKey) -> Result<()> {
        let mut key_guard = self.master_key.write().await;
        *key_guard = Some(master_key);

        self.audit_logger
            .log(AuditEvent::VaultUnlocked {
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(())
    }

    pub async fn lock(&self) -> Result<()> {
        let mut key_guard = self.master_key.write().await;
        *key_guard = None;

        // Clear cache on lock
        self.cache.clear().await;

        self.audit_logger
            .log(AuditEvent::VaultLocked {
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(())
    }

    pub async fn is_locked(&self) -> bool {
        self.master_key.read().await.is_none()
    }

    pub fn auth_manager(&self) -> Arc<AuthManager> {
        self.auth_manager.clone()
    }

    pub async fn load_model(
        &self,
        session: &Session,
        model_id: Uuid,
    ) -> Result<Arc<DecryptedModel>> {
        // Check if vault is locked
        if self.is_locked().await {
            return Err(UraniumError::VaultLocked);
        }

        // Verify session
        let user = self.session_manager.get_user(session).await?;

        // Check permissions
        AuthManager::check_model_access(&user, model_id, Permission::ModelRead)?;

        // Check cache first
        if let Some(model) = self.cache.get(model_id).await {
            self.audit_logger
                .log(AuditEvent::ModelAccessed {
                    user_id: user.id,
                    model_id,
                    action: "load_cached".to_string(),
                    timestamp: chrono::Utc::now(),
                })
                .await?;

            return Ok(model);
        }

        // Acquire load permit
        let _permit = self
            .load_semaphore
            .acquire()
            .await
            .map_err(|_| UraniumError::ConcurrentAccessDenied)?;

        // Get master key
        let master_key = self
            .master_key
            .read()
            .await
            .as_ref()
            .ok_or(UraniumError::VaultLocked)?
            .clone();

        // Load from storage
        let model = {
            #[cfg(target_os = "macos")]
            {
                if let Some(se_storage) = &self.secure_enclave_storage {
                    se_storage.load_model_secure_enclave(model_id)?
                } else {
                    self.storage.load_model(model_id, &master_key)?
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                self.storage.load_model(model_id, &master_key)?
            }
        };

        // Apply memory protection if enabled
        if self.config.enable_memory_protection {
            self.protect_memory(&model)?;
        }

        let model = Arc::new(model);

        // Cache the model
        self.cache.insert(model_id, model.clone()).await;

        // Log access
        self.audit_logger
            .log(AuditEvent::ModelAccessed {
                user_id: user.id,
                model_id,
                action: "load".to_string(),
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(model)
    }

    pub async fn store_model(
        &self,
        session: &Session,
        metadata: ModelMetadata,
        weights: Vec<u8>,
    ) -> Result<Uuid> {
        // Check if vault is locked
        if self.is_locked().await {
            return Err(UraniumError::VaultLocked);
        }

        // Verify session
        let user = self.session_manager.get_user(session).await?;

        // Check permissions
        AuthManager::check_permission(&user, Permission::ModelWrite)?;

        let model_id = metadata.id;

        // Get master key
        let master_key = self
            .master_key
            .read()
            .await
            .as_ref()
            .ok_or(UraniumError::VaultLocked)?
            .clone();

        // Store the model
        #[cfg(target_os = "macos")]
        {
            if let Some(se_storage) = &self.secure_enclave_storage {
                se_storage.store_model_secure_enclave(model_id, metadata, &weights)?;
            } else {
                self.storage
                    .store_model(model_id, metadata, &weights, &master_key)?;
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.storage
                .store_model(model_id, metadata, &weights, &master_key)?;
        }

        // Log the action
        self.audit_logger
            .log(AuditEvent::ModelStored {
                user_id: user.id,
                model_id,
                size_bytes: weights.len() as u64,
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(model_id)
    }

    pub async fn delete_model(&self, session: &Session, model_id: Uuid) -> Result<()> {
        // Verify session
        let user = self.session_manager.get_user(session).await?;

        // Check permissions
        AuthManager::check_model_access(&user, model_id, Permission::ModelDelete)?;

        // Remove from cache
        self.cache.remove(model_id).await;

        // Delete from storage
        self.storage.delete_model(model_id)?;

        // Log the action
        self.audit_logger
            .log(AuditEvent::ModelDeleted {
                user_id: user.id,
                model_id,
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(())
    }

    pub async fn list_models(&self, session: &Session) -> Result<Vec<ModelMetadata>> {
        // Verify session
        let user = self.session_manager.get_user(session).await?;

        // Check permissions
        AuthManager::check_permission(&user, Permission::ModelRead)?;

        let model_ids = self.storage.list_models()?;
        let mut metadata_list = Vec::new();

        for model_id in model_ids {
            match self.storage.get_model_metadata(model_id) {
                Ok(metadata) => metadata_list.push(metadata),
                Err(_) => continue,
            }
        }

        Ok(metadata_list)
    }

    pub fn model_count(&self) -> usize {
        self.storage
            .list_models()
            .map(|models| models.len())
            .unwrap_or(0)
    }

    pub fn get_cache_stats(&self) -> CacheStats {
        self.cache.get_stats()
    }

    pub async fn create_session(&self, token: &str) -> Result<Session> {
        let user = self.auth_manager.verify_token(token).await?;
        let session = self.session_manager.create_session(user).await?;

        self.audit_logger
            .log(AuditEvent::SessionCreated {
                session_id: session.id,
                user_id: session.user_id,
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(session)
    }

    pub async fn destroy_session(&self, session: &Session) -> Result<()> {
        self.session_manager.destroy_session(session).await?;

        self.audit_logger
            .log(AuditEvent::SessionDestroyed {
                session_id: session.id,
                user_id: session.user_id,
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(())
    }

    fn protect_memory(&self, model: &DecryptedModel) -> Result<()> {
        // Lock memory pages to prevent swapping
        #[cfg(unix)]
        {
            use nix::sys::mman::mlock;

            // Try to lock all current and future memory
            use std::ptr::NonNull;
            if let Some(non_null_ptr) =
                NonNull::new(model.weights.as_ptr() as *mut std::ffi::c_void)
            {
                if let Err(_) = unsafe { mlock(non_null_ptr, model.weights.len()) } {
                    tracing::warn!("Failed to lock model memory pages");
                }
            }
        }

        Ok(())
    }

    /// Check if Secure Enclave is available and enabled
    pub fn is_secure_enclave_enabled(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.secure_enclave_storage.is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Migrate a model to Secure Enclave encryption (macOS only)
    #[cfg(target_os = "macos")]
    pub async fn migrate_to_secure_enclave(&self, session: &Session, model_id: Uuid) -> Result<()> {
        // Verify session and permissions
        let user = self.session_manager.get_user(session).await?;
        AuthManager::check_permission(&user, Permission::ModelWrite)?;

        // Check if SE is available
        let se_storage = self.secure_enclave_storage.as_ref().ok_or_else(|| {
            UraniumError::Internal("Secure Enclave not available on this device".to_string())
        })?;

        // Get master key
        let master_key = self
            .master_key
            .read()
            .await
            .as_ref()
            .ok_or(UraniumError::VaultLocked)?
            .clone();

        // Migrate the model
        se_storage.migrate_to_secure_enclave(model_id, &master_key)?;

        // Log the migration
        self.audit_logger
            .log(AuditEvent::ModelMigrated {
                user_id: user.id,
                model_id,
                migration_type: "secure_enclave".to_string(),
                timestamp: chrono::Utc::now(),
            })
            .await?;

        Ok(())
    }
}

#[async_trait]
pub trait VaultExtension: Send + Sync {
    async fn on_model_load(&self, model_id: Uuid, user: &User) -> Result<()>;
    async fn on_model_store(&self, model_id: Uuid, user: &User) -> Result<()>;
}

pub struct LicenseEnforcer {
    // Implementation for license checks
}

#[async_trait]
impl VaultExtension for LicenseEnforcer {
    async fn on_model_load(&self, _model_id: Uuid, _user: &User) -> Result<()> {
        // Check license constraints
        Ok(())
    }

    async fn on_model_store(&self, _model_id: Uuid, _user: &User) -> Result<()> {
        // Validate license for storage
        Ok(())
    }
}
