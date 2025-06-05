use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::info;

use uranium_vault::{
    api::create_api_server,
    audit::{AuditLogger, DatabaseAuditLogger},
    auth::{AuthManager, DatabaseAuthProvider},
    config::VaultConfiguration,
    vault::{Vault, VaultConfig},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("uranium_vault=info".parse()?)
                .add_directive("uranium_core=info".parse()?),
        )
        .init();

    info!("🔐 Uranium Vault Server starting...");

    // Load configuration
    let config = VaultConfiguration::load()?;
    config.validate().map_err(|e| anyhow::anyhow!(e))?;

    info!("📋 Configuration loaded from uranium.toml");

    // Convert VaultConfiguration to VaultConfig
    let vault_config = VaultConfig {
        storage_path: config.storage.base_path.clone(),
        encryption_algorithm: config.security.encryption_algorithm,
        hash_algorithm: config.security.hash_algorithm,
        max_concurrent_loads: config.performance.max_concurrent_loads,
        cache_size_mb: config.performance.cache_size_mb,
        session_timeout_minutes: config.auth.session_timeout_minutes,
        enable_memory_protection: config.security.enable_memory_protection,
        enable_secure_enclave: config.security.enable_secure_enclave,
    };

    // Log Secure Enclave status
    #[cfg(target_os = "macos")]
    {
        if vault_config.enable_secure_enclave {
            if uranium_core::storage::SecureEnclaveStorage::is_secure_enclave_available() {
                info!("✅ Secure Enclave: ENABLED and AVAILABLE");
                info!("🔒 Using hardware-backed encryption for all models");
            } else {
                info!("⚠️  Secure Enclave: REQUESTED but NOT AVAILABLE");
                info!("🔐 Falling back to software encryption");
            }
        } else {
            info!("🔐 Secure Enclave: DISABLED (using software encryption)");
        }
    }

    // Create storage directory if it doesn't exist
    tokio::fs::create_dir_all(&config.storage.base_path).await?;

    // Initialize database for auth and audit
    let db_pool = sqlx::SqlitePool::connect(&config.storage.database_url).await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;

    // Check if admin user exists
    let admin_check = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE username = 'admin'")
        .fetch_one(&db_pool)
        .await?;

    if admin_check.count == 0 {
        info!("Creating default admin user...");
        // Create auth provider temporarily to create admin
        let temp_provider = DatabaseAuthProvider::new(db_pool.clone());
        match temp_provider
            .create_admin_user("admin".to_string(), "changeme".to_string())
            .await
        {
            Ok(_) => info!("✅ Default admin user created (username: admin, password: changeme)"),
            Err(e) => tracing::warn!("Failed to create admin user: {}", e),
        }
    }

    // Create components
    let auth_provider = Arc::new(DatabaseAuthProvider::new(db_pool.clone()));
    let jwt_secret = config.auth.jwt_secret.clone();
    let audit_logger: Arc<dyn AuditLogger> = Arc::new(DatabaseAuditLogger::new(db_pool.clone()));
    let auth_manager = Arc::new(
        AuthManager::new(auth_provider, jwt_secret, config.auth.token_duration_hours)
            .with_audit_logger(audit_logger.clone()),
    );

    // Create vault
    let vault = Arc::new(Vault::new(
        vault_config,
        auth_manager.clone(),
        audit_logger,
    )?);

    info!("🏛️  Vault initialized successfully");

    // Check if using Secure Enclave
    if vault.is_secure_enclave_enabled() {
        info!("🍎 Secure Enclave protection: ACTIVE");
    }

    // Create API server
    let app = create_api_server(vault, auth_manager);

    // Start server
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    let listener = TcpListener::bind(&addr).await?;

    info!("🚀 Uranium Vault Server listening on {}", addr);
    info!("📡 API endpoint: http://{}/api/v1", addr);

    if config.security.enable_secure_enclave {
        info!("🔐 Secure Enclave: Models will be encrypted with hardware-backed keys");
    }

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}
