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
    audit::DatabaseAuditLogger,
    auth::{AuthManager, Credentials, DatabaseAuthProvider},
    config::VaultConfiguration,
    vault::{Vault, VaultConfig},
};

/// This example demonstrates the complete workflow of:
/// 1. Setting up a vault
/// 2. Creating users
/// 3. Authenticating
/// 4. Storing and retrieving models
/// 5. Access control and auditing
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("uranium=debug")
        .init();
    
    println!("🔐 Uranium Vault Demo\n");
    
    // Setup temporary directory for demo
    let temp_dir = TempDir::new()?;
    println!("📁 Created temporary vault at: {:?}", temp_dir.path());
    
    // Initialize SQLite database
    let db_url = format!("sqlite://{}/vault.db", temp_dir.path().display());
    let pool = sqlx::sqlite::SqlitePool::connect(&db_url).await?;
    
    // Run migrations (in real app, these would be SQL migration files)
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            roles TEXT NOT NULL,
            is_active INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            last_login INTEGER
        )
        "#
    )
    .execute(&pool)
    .await?;
    
    // Setup components
    let auth_provider = DatabaseAuthProvider::new(pool.clone());
    let auth_manager = Arc::new(AuthManager::new(
        Box::new(auth_provider),
        "demo_jwt_secret_key".to_string(),
        24,
    ));
    
    let audit_logger = Arc::new(DatabaseAuditLogger::new(pool.clone()));
    audit_logger.init_schema().await?;
    
    let vault_config = VaultConfig {
        storage_path: temp_dir.path().join("models"),
        encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        hash_algorithm: HashAlgorithm::Blake3,
        max_concurrent_loads: 10,
        cache_size_mb: 100,
        session_timeout_minutes: 60,
        enable_memory_protection: false, // Disable for demo
    };
    
    let vault = Arc::new(Vault::new(
        vault_config,
        auth_manager.clone(),
        audit_logger.clone(),
    )?);
    
    println!("✅ Vault initialized\n");
    
    // Create a demo user
    println!("👤 Creating demo user...");
    let user = auth_provider
        .create_user(
            "alice".to_string(),
            "secure_password123!".to_string(),
            Some("alice@haasonsaas.com".to_string()),
            vec!["developer".to_string()],
        )
        .await?;
    println!("✅ Created user: {} ({})\n", user.username, user.id);
    
    // Authenticate
    println!("🔑 Authenticating...");
    let auth_token = auth_manager
        .authenticate(&Credentials {
            username: "alice".to_string(),
            password: "secure_password123!".to_string(),
        })
        .await?;
    println!("✅ Authentication successful\n");
    
    // Create session
    let session = vault.create_session(&auth_token.token).await?;
    println!("📋 Session created: {}\n", session.id);
    
    // Generate and set master key
    println!("🔓 Unlocking vault...");
    let master_key = EncryptionKey::generate();
    vault.unlock(master_key).await?;
    println!("✅ Vault unlocked\n");
    
    // Create and store a model
    println!("📦 Storing a model...");
    let model_id = Uuid::new_v4();
    let model_metadata = ModelMetadata {
        id: model_id,
        name: "demo-llm-model".to_string(),
        version: "1.0.0".to_string(),
        format: ModelFormat::SafeTensors,
        size_bytes: 1024 * 1024, // 1MB
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: Some("Demo LLM model for testing".to_string()),
        tags: vec!["demo".to_string(), "test".to_string()],
        framework: Some(uranium_core::models::ModelFramework::PyTorch),
        architecture: Some("transformer".to_string()),
        parameters_count: Some(1_000_000),
        watermark: None,
        license_constraints: None,
    };
    
    // Simulate model weights (in reality, this would be actual model data)
    let model_weights = vec![0x42; 1024 * 1024]; // 1MB of dummy data
    
    let stored_id = vault
        .store_model(&session, model_metadata.clone(), model_weights.clone())
        .await?;
    
    println!("✅ Model stored with ID: {}\n", stored_id);
    
    // List models
    println!("📋 Listing models...");
    let models = vault.list_models(&session).await?;
    for model in &models {
        println!("  - {} v{} ({} MB)", 
            model.name, 
            model.version,
            model.size_bytes / (1024 * 1024)
        );
    }
    println!();
    
    // Load the model back
    println!("📥 Loading model...");
    let loaded_model = vault.load_model(&session, model_id).await?;
    println!("✅ Model loaded: {} v{}", 
        loaded_model.metadata.name,
        loaded_model.metadata.version
    );
    println!("   Size: {} bytes", loaded_model.weights.len());
    println!("   Tags: {:?}", loaded_model.metadata.tags);
    println!();
    
    // Verify integrity
    println!("🔍 Verifying model integrity...");
    let weights_match = loaded_model.weights == model_weights;
    println!("✅ Integrity check: {}\n", if weights_match { "PASSED" } else { "FAILED" });
    
    // Check audit logs
    println!("📊 Audit log summary:");
    let stats = audit_logger.get_stats().await?;
    println!("   Total events: {}", stats.total_events);
    println!("   Models accessed today: {}", stats.models_accessed_today);
    println!("   Failed auth attempts: {}", stats.failed_auth_attempts);
    println!("   Security alerts: {}", stats.security_alerts);
    println!();
    
    // Clean up
    println!("🧹 Cleaning up...");
    vault.destroy_session(&session).await?;
    vault.lock().await?;
    println!("✅ Vault locked and session destroyed\n");
    
    println!("🎉 Demo completed successfully!");
    
    Ok(())
}
