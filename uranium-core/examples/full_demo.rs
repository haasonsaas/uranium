use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use uuid::Uuid;

use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, PasswordManager, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelFramework, ModelMetadata},
    storage::ModelStorage,
    Result, UraniumError,
};

// Define permissions for demo
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
enum Permission {
    ModelRead,
    ModelWrite,
    ModelExecute,
}

// Mock user type
#[derive(Debug, Clone)]
struct User {
    #[allow(dead_code)]
    id: Uuid,
    username: String,
    permissions: HashSet<Permission>,
}

// Mock session type
#[derive(Debug, Clone)]
struct Session {
    id: Uuid,
    user: User,
    #[allow(dead_code)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

// Simple in-memory vault implementation for demo
struct DemoVault {
    storage: Arc<ModelStorage>,
    master_key: Arc<RwLock<Option<EncryptionKey>>>,
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
    audit_log: Arc<RwLock<Vec<String>>>,
}

impl DemoVault {
    fn new(storage_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let crypto = VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305);
        let verifier = IntegrityVerifier::new(HashAlgorithm::Blake3);
        let storage = Arc::new(ModelStorage::new(storage_path, crypto, verifier)?);

        Ok(Self {
            storage,
            master_key: Arc::new(RwLock::new(None)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        })
    }

    async fn unlock(&self, key: EncryptionKey) -> Result<()> {
        let mut master_key = self.master_key.write().await;
        *master_key = Some(key);
        self.log("Vault unlocked").await;
        Ok(())
    }

    async fn lock(&self) -> Result<()> {
        let mut master_key = self.master_key.write().await;
        *master_key = None;
        self.log("Vault locked").await;
        Ok(())
    }

    async fn is_locked(&self) -> bool {
        self.master_key.read().await.is_none()
    }

    async fn create_session(&self, user: User) -> Result<Session> {
        let session = Session {
            id: Uuid::new_v4(),
            user: user.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        self.sessions
            .write()
            .await
            .insert(session.id, session.clone());
        self.log(&format!("Session created for user: {}", user.username))
            .await;

        Ok(session)
    }

    async fn store_model(
        &self,
        session: &Session,
        metadata: ModelMetadata,
        weights: Vec<u8>,
    ) -> Result<Uuid> {
        // Check permissions
        if !session.user.permissions.contains(&Permission::ModelWrite) {
            return Err(UraniumError::AuthorizationDenied {
                resource: "model:write".to_string(),
            });
        }

        // Check if vault is locked
        let key_guard = self.master_key.read().await;
        let key = key_guard.as_ref().ok_or(UraniumError::VaultLocked)?;

        // Store the model
        let model_id = metadata.id;
        self.storage
            .store_model(model_id, metadata.clone(), &weights, key)?;

        self.log(&format!(
            "Model stored: {} by user: {}",
            metadata.name, session.user.username
        ))
        .await;

        Ok(model_id)
    }

    async fn load_model(&self, session: &Session, model_id: Uuid) -> Result<Vec<u8>> {
        // Check permissions
        if !session.user.permissions.contains(&Permission::ModelRead) {
            return Err(UraniumError::AuthorizationDenied {
                resource: "model:read".to_string(),
            });
        }

        // Check if vault is locked
        let key_guard = self.master_key.read().await;
        let key = key_guard.as_ref().ok_or(UraniumError::VaultLocked)?;

        // Load the model
        let model = self.storage.load_model(model_id, key)?;

        self.log(&format!(
            "Model loaded: {} by user: {}",
            model.metadata.name, session.user.username
        ))
        .await;

        Ok(model.weights.clone())
    }

    async fn log(&self, message: &str) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let entry = format!("[{}] {}", timestamp, message);
        self.audit_log.write().await.push(entry.clone());
        println!("📝 {}", entry);
    }

    async fn get_audit_log(&self) -> Vec<String> {
        self.audit_log.read().await.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Uranium Full System Demo\n");
    println!("This demo simulates the complete Uranium workflow with authentication,\n");
    println!("authorization, and audit logging.\n");

    // Create temporary storage
    let temp_dir = TempDir::new()?;

    // Initialize the vault
    let vault = Arc::new(DemoVault::new(temp_dir.path())?);
    println!("✅ Vault initialized\n");

    // Create test users
    println!("👥 Creating users...");

    let alice = User {
        id: Uuid::new_v4(),
        username: "alice".to_string(),
        permissions: vec![
            Permission::ModelRead,
            Permission::ModelWrite,
            Permission::ModelExecute,
        ]
        .into_iter()
        .collect(),
    };
    println!("   👤 Alice (Developer) - Read, Write, Execute permissions");

    let bob = User {
        id: Uuid::new_v4(),
        username: "bob".to_string(),
        permissions: vec![Permission::ModelRead].into_iter().collect(),
    };
    println!("   👤 Bob (Viewer) - Read-only permissions");

    let charlie = User {
        id: Uuid::new_v4(),
        username: "charlie".to_string(),
        permissions: HashSet::new(),
    };
    println!("   👤 Charlie (No Access) - No permissions\n");

    // Test password hashing
    println!("🔑 Testing password security...");
    let password_manager = PasswordManager::new();
    let alice_password = "secure_password123!";
    let alice_hash = password_manager.hash_password(alice_password)?;
    println!("   Password hashed successfully");
    assert!(password_manager.verify_password(alice_password, &alice_hash)?);
    println!("   ✅ Password verification works\n");

    // Try operations before unlocking vault
    println!("🔒 Testing locked vault...");
    let alice_session = vault.create_session(alice.clone()).await?;

    let test_metadata = ModelMetadata {
        id: Uuid::new_v4(),
        name: "test-model".to_string(),
        version: "1.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1024,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: None,
        tags: vec![],
        framework: Some(ModelFramework::PyTorch),
        architecture: None,
        parameters_count: None,
        watermark: None,
        license_constraints: None,
    };

    match vault
        .store_model(&alice_session, test_metadata.clone(), vec![0u8; 1024])
        .await
    {
        Err(UraniumError::VaultLocked) => println!("   ✅ Correctly rejected: Vault is locked"),
        _ => println!("   ❌ ERROR: Should have failed with vault locked!"),
    }

    // Generate and set master key
    println!("\n🔓 Unlocking vault...");
    let master_key = EncryptionKey::generate();
    vault.unlock(master_key).await?;
    assert!(!vault.is_locked().await);
    println!("   ✅ Vault unlocked successfully\n");

    // Alice stores a model
    println!("📦 Alice storing a model...");
    let model_id = Uuid::new_v4();
    let model_metadata = ModelMetadata {
        id: model_id,
        name: "gpt-nano".to_string(),
        version: "1.0.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1024 * 1024,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: Some("Small GPT model for testing".to_string()),
        tags: vec!["nlp".to_string(), "transformer".to_string()],
        framework: Some(ModelFramework::PyTorch),
        architecture: Some("transformer".to_string()),
        parameters_count: Some(10_000_000),
        watermark: None,
        license_constraints: None,
    };

    let model_weights = vec![0x42; 1024 * 1024];
    let stored_id = vault
        .store_model(
            &alice_session,
            model_metadata.clone(),
            model_weights.clone(),
        )
        .await?;
    println!("   ✅ Model stored successfully (ID: {})\n", stored_id);

    // Bob tries to read the model
    println!("📖 Bob reading the model...");
    let bob_session = vault.create_session(bob.clone()).await?;
    let loaded_weights = vault.load_model(&bob_session, model_id).await?;
    assert_eq!(loaded_weights, model_weights);
    println!("   ✅ Bob successfully read the model\n");

    // Bob tries to write (should fail)
    println!("❌ Bob trying to write a model...");
    match vault
        .store_model(&bob_session, model_metadata.clone(), vec![0u8; 1024])
        .await
    {
        Err(UraniumError::AuthorizationDenied { .. }) => {
            println!("   ✅ Correctly rejected: Bob lacks write permission")
        }
        _ => println!("   ❌ ERROR: Should have failed with authorization error!"),
    }

    // Charlie tries to read (should fail)
    println!("\n❌ Charlie trying to read the model...");
    let charlie_session = vault.create_session(charlie.clone()).await?;
    match vault.load_model(&charlie_session, model_id).await {
        Err(UraniumError::AuthorizationDenied { .. }) => {
            println!("   ✅ Correctly rejected: Charlie has no permissions")
        }
        _ => println!("   ❌ ERROR: Should have failed with authorization error!"),
    }

    // Lock the vault
    println!("\n🔒 Locking the vault...");
    vault.lock().await?;
    assert!(vault.is_locked().await);

    // Try to access after locking
    match vault.load_model(&alice_session, model_id).await {
        Err(UraniumError::VaultLocked) => println!("   ✅ Correctly rejected: Vault is locked"),
        _ => println!("   ❌ ERROR: Should have failed with vault locked!"),
    }

    // Show audit log
    println!("\n📊 Audit Log:");
    println!("{}", "=".repeat(60));
    let logs = vault.get_audit_log().await;
    for (i, entry) in logs.iter().enumerate() {
        println!("{:2}. {}", i + 1, entry);
    }
    println!("{}", "=".repeat(60));

    println!("\n🎉 Demo completed successfully!");
    println!("\nKey security features demonstrated:");
    println!("✅ Strong password hashing with Argon2");
    println!("✅ Master key encryption for models");
    println!("✅ Role-based access control");
    println!("✅ Vault lock/unlock mechanism");
    println!("✅ Comprehensive audit logging");
    println!("✅ Proper error handling for unauthorized access");

    Ok(())
}
