use std::sync::Arc;
use tempfile::TempDir;
use tokio;
use uuid::Uuid;

use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey},
    integrity::HashAlgorithm,
    models::{ModelFormat, ModelMetadata},
};
use uranium_vault::{
    audit::{AuditEvent, AuditFilter, AuditLogger, AuditStats},
    auth::{AuthManager, AuthProvider, Credentials, DatabaseAuthProvider, Permission, User},
    config::VaultConfiguration,
    session::Session,
    vault::{Vault, VaultConfig},
};

// Mock audit logger for testing
struct MockAuditLogger {
    events: tokio::sync::Mutex<Vec<AuditEvent>>,
}

impl MockAuditLogger {
    fn new() -> Self {
        Self {
            events: tokio::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl AuditLogger for MockAuditLogger {
    async fn log(&self, event: AuditEvent) -> uranium_core::Result<()> {
        let mut events = self.events.lock().await;
        events.push(event);
        Ok(())
    }

    async fn query(&self, _filter: AuditFilter) -> uranium_core::Result<Vec<AuditEvent>> {
        let events = self.events.lock().await;
        Ok(events.clone())
    }

    async fn get_stats(&self) -> uranium_core::Result<AuditStats> {
        let events = self.events.lock().await;
        Ok(AuditStats {
            total_events: events.len() as u64,
            events_by_type: std::collections::HashMap::new(),
            active_sessions: 0,
            models_accessed_today: 0,
            failed_auth_attempts: 0,
            security_alerts: 0,
        })
    }
}

// Mock auth provider for testing
struct MockAuthProvider;

#[async_trait::async_trait]
impl AuthProvider for MockAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> uranium_core::Result<User> {
        if credentials.username == "test_user" && credentials.password == "test_pass" {
            Ok(User {
                id: Uuid::new_v4(),
                username: credentials.username.clone(),
                email: Some("test@example.com".to_string()),
                roles: vec!["developer".to_string()],
                permissions: vec![
                    Permission::ModelRead,
                    Permission::ModelWrite,
                    Permission::ModelExecute,
                ]
                .into_iter()
                .collect(),
                created_at: chrono::Utc::now(),
                last_login: None,
                is_active: true,
            })
        } else {
            Err(uranium_core::UraniumError::AuthenticationFailed)
        }
    }

    async fn get_user(&self, _user_id: Uuid) -> uranium_core::Result<User> {
        Ok(User {
            id: Uuid::new_v4(),
            username: "test_user".to_string(),
            email: Some("test@example.com".to_string()),
            roles: vec!["developer".to_string()],
            permissions: vec![
                Permission::ModelRead,
                Permission::ModelWrite,
                Permission::ModelExecute,
            ]
            .into_iter()
            .collect(),
            created_at: chrono::Utc::now(),
            last_login: Some(chrono::Utc::now()),
            is_active: true,
        })
    }

    async fn update_last_login(&self, _user_id: Uuid) -> uranium_core::Result<()> {
        Ok(())
    }
}

async fn setup_test_vault() -> (Vault, TempDir, Arc<MockAuditLogger>) {
    let temp_dir = TempDir::new().unwrap();

    let config = VaultConfig {
        storage_path: temp_dir.path().to_path_buf(),
        encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        hash_algorithm: HashAlgorithm::Blake3,
        max_concurrent_loads: 10,
        cache_size_mb: 10,
        session_timeout_minutes: 60,
        enable_memory_protection: false, // Disable for tests
    };

    let auth_manager = Arc::new(AuthManager::new(
        Box::new(MockAuthProvider),
        "test_jwt_secret".to_string(),
        24,
    ));

    let audit_logger = Arc::new(MockAuditLogger::new());

    let vault = Vault::new(config, auth_manager, audit_logger.clone()).unwrap();

    (vault, temp_dir, audit_logger)
}

#[tokio::test]
async fn test_vault_lock_unlock() {
    let (vault, _temp_dir, audit_logger) = setup_test_vault().await;

    // Vault should start locked
    assert!(vault.is_locked());

    // Generate a master key
    let master_key = EncryptionKey::generate();

    // Unlock the vault
    vault.unlock(master_key.clone()).await.unwrap();
    assert!(!vault.is_locked());

    // Check audit log
    let events = audit_logger
        .query(AuditFilter {
            start_time: None,
            end_time: None,
            user_id: None,
            model_id: None,
            event_types: None,
            limit: None,
        })
        .await
        .unwrap();

    assert!(matches!(
        events.last().unwrap(),
        AuditEvent::VaultUnlocked { .. }
    ));

    // Lock the vault
    vault.lock().await.unwrap();
    assert!(vault.is_locked());
}

#[tokio::test]
async fn test_model_storage_and_retrieval() {
    let (vault, _temp_dir, audit_logger) = setup_test_vault().await;

    // Unlock vault
    let master_key = EncryptionKey::generate();
    vault.unlock(master_key).await.unwrap();

    // Create session
    let token = vault
        .auth_manager
        .authenticate(&Credentials {
            username: "test_user".to_string(),
            password: "test_pass".to_string(),
        })
        .await
        .unwrap();

    let session = vault.create_session(&token.token).await.unwrap();

    // Create test model
    let model_id = Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "test_model".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1024,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: None,
        tags: vec!["test".to_string()],
        framework: None,
        architecture: None,
        parameters_count: None,
        watermark: None,
        license_constraints: None,
    };

    let weights = vec![0x42; 1024];

    // Store model
    let stored_id = vault
        .store_model(&session, metadata.clone(), weights.clone())
        .await
        .unwrap();

    assert_eq!(stored_id, model_id);

    // Load model
    let loaded_model = vault.load_model(&session, model_id).await.unwrap();

    assert_eq!(loaded_model.metadata.name, "test_model");
    assert_eq!(loaded_model.weights, weights);

    // Check audit log
    let events = audit_logger
        .query(AuditFilter {
            start_time: None,
            end_time: None,
            user_id: None,
            model_id: Some(model_id),
            event_types: None,
            limit: None,
        })
        .await
        .unwrap();

    assert!(events
        .iter()
        .any(|e| matches!(e, AuditEvent::ModelStored { .. })));
    assert!(events
        .iter()
        .any(|e| matches!(e, AuditEvent::ModelAccessed { .. })));
}

#[tokio::test]
async fn test_access_control() {
    let (vault, _temp_dir, _audit_logger) = setup_test_vault().await;

    // Try to load model without unlocking vault
    let session = Session::new(
        &User {
            id: Uuid::new_v4(),
            username: "test".to_string(),
            email: None,
            roles: vec![],
            permissions: std::collections::HashSet::new(),
            created_at: chrono::Utc::now(),
            last_login: None,
            is_active: true,
        },
        60,
    );

    let result = vault.load_model(&session, Uuid::new_v4()).await;

    assert!(matches!(
        result.unwrap_err(),
        uranium_core::UraniumError::VaultLocked
    ));
}

#[tokio::test]
async fn test_model_caching() {
    let (vault, _temp_dir, _audit_logger) = setup_test_vault().await;

    // Unlock vault
    let master_key = EncryptionKey::generate();
    vault.unlock(master_key).await.unwrap();

    // Create session
    let token = vault
        .auth_manager
        .authenticate(&Credentials {
            username: "test_user".to_string(),
            password: "test_pass".to_string(),
        })
        .await
        .unwrap();

    let session = vault.create_session(&token.token).await.unwrap();

    // Store a model
    let model_id = Uuid::new_v4();
    let metadata = ModelMetadata {
        id: model_id,
        name: "cached_model".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::ONNX,
        size_bytes: 512,
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

    let weights = vec![0xAB; 512];

    vault
        .store_model(&session, metadata, weights.clone())
        .await
        .unwrap();

    // Load model twice - second should be cached
    let model1 = vault.load_model(&session, model_id).await.unwrap();
    let model2 = vault.load_model(&session, model_id).await.unwrap();

    // Both should be the same
    assert_eq!(model1.metadata.id, model2.metadata.id);
    assert_eq!(model1.weights, model2.weights);
}
