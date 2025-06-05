/// Uranium Vault Demo Server with Secure Enclave
///
/// This is a simplified demo server that shows the Secure Enclave integration
/// working without the full SQLx database complexity.
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uranium_core::{
    crypto::{EncryptionAlgorithm, EncryptionKey, VaultCrypto},
    integrity::{HashAlgorithm, IntegrityVerifier},
    models::{ModelFormat, ModelMetadata},
    storage::{ModelStorage, SecureEnclaveStorage, SecureEnclaveStorageBuilder},
};
use uuid::Uuid;

// Simple in-memory model registry
type ModelRegistry = Arc<Mutex<HashMap<Uuid, ModelInfo>>>;

#[derive(Clone)]
struct AppState {
    storage: Arc<ModelStorage>,
    #[cfg(target_os = "macos")]
    se_storage: Option<Arc<SecureEnclaveStorage>>,
    registry: ModelRegistry,
    master_key: EncryptionKey,
    enable_secure_enclave: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModelInfo {
    id: Uuid,
    name: String,
    size: usize,
    encrypted_with_se: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreModelRequest {
    name: String,
    data: Vec<u8>,
    format: ModelFormat,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreModelResponse {
    id: Uuid,
    message: String,
    encrypted_with_se: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    vault_status: String,
    secure_enclave_available: bool,
    secure_enclave_enabled: bool,
    models_count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("uranium_vault_demo=info,uranium_core=info")
        .init();

    tracing::info!("🔐 Uranium Vault Demo Server starting...");

    // Configuration
    let enable_secure_enclave = true;
    let storage_path = PathBuf::from("./demo_vault_storage");

    // Create storage directory
    tokio::fs::create_dir_all(&storage_path).await?;

    // Create base storage
    let storage = Arc::new(ModelStorage::new(
        &storage_path,
        VaultCrypto::new(EncryptionAlgorithm::ChaCha20Poly1305),
        IntegrityVerifier::new(HashAlgorithm::Blake3),
    )?);

    // Create Secure Enclave storage if available
    #[cfg(target_os = "macos")]
    let se_storage = if enable_secure_enclave && SecureEnclaveStorage::is_secure_enclave_available()
    {
        tracing::info!("✅ Secure Enclave detected - enabling hardware-backed encryption");
        let se_storage = SecureEnclaveStorageBuilder::new()
            .with_path(&storage_path)
            .with_algorithm(EncryptionAlgorithm::ChaCha20Poly1305)
            .build()?;
        Some(Arc::new(se_storage))
    } else {
        if enable_secure_enclave {
            tracing::warn!("⚠️  Secure Enclave requested but not available");
        }
        tracing::info!("🔐 Using software encryption");
        None
    };

    #[cfg(not(target_os = "macos"))]
    let se_storage: Option<Arc<SecureEnclaveStorage>> = None;

    // Generate a demo master key
    let master_key = EncryptionKey::generate();

    // Create app state
    let state = AppState {
        storage,
        #[cfg(target_os = "macos")]
        se_storage,
        registry: Arc::new(Mutex::new(HashMap::new())),
        master_key,
        enable_secure_enclave,
    };

    // Build routes
    let app = Router::new()
        .route("/", get(root))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/models", post(store_model))
        .route("/api/v1/models/:id", get(load_model))
        .route("/api/v1/models", get(list_models))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(&addr).await?;

    tracing::info!("🚀 Server listening on http://{}", addr);

    #[cfg(target_os = "macos")]
    if SecureEnclaveStorage::is_secure_enclave_available() {
        tracing::info!(
            "🍎 Secure Enclave: ACTIVE - All models encrypted with hardware-backed keys"
        );
    }

    axum::serve(listener, app).await?;

    Ok(())
}

async fn root() -> impl IntoResponse {
    "🔐 Uranium Vault Demo Server with Secure Enclave\n\nEndpoints:\n- GET /api/v1/status\n- POST /api/v1/models\n- GET /api/v1/models/:id\n- GET /api/v1/models"
}

async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let models_count = state.registry.lock().unwrap().len();

    Json(StatusResponse {
        vault_status: "operational".to_string(),
        secure_enclave_available: {
            #[cfg(target_os = "macos")]
            {
                SecureEnclaveStorage::is_secure_enclave_available()
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        },
        secure_enclave_enabled: state.enable_secure_enclave,
        models_count,
    })
}

async fn store_model(
    State(state): State<AppState>,
    Json(request): Json<StoreModelRequest>,
) -> Result<Json<StoreModelResponse>, StatusCode> {
    let model_id = Uuid::new_v4();

    // Create metadata
    let metadata = ModelMetadata {
        id: model_id,
        name: request.name.clone(),
        version: "1.0".to_string(),
        format: request.format,
        size_bytes: request.data.len() as u64,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        description: Some("Demo model".to_string()),
        tags: vec!["demo".to_string()],
        framework: None,
        architecture: None,
        parameters_count: None,
        watermark: None,
        license_constraints: None,
    };

    // Store with appropriate encryption
    let encrypted_with_se = {
        #[cfg(target_os = "macos")]
        {
            if let Some(se_storage) = &state.se_storage {
                // Use Secure Enclave
                se_storage
                    .store_model_secure_enclave(model_id, metadata.clone(), &request.data)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                true
            } else {
                // Use software encryption
                state
                    .storage
                    .store_model(model_id, metadata.clone(), &request.data, &state.master_key)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                false
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            state
                .storage
                .store_model(model_id, metadata.clone(), &request.data, &state.master_key)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            false
        }
    };

    // Register model
    let model_info = ModelInfo {
        id: model_id,
        name: request.name,
        size: request.data.len(),
        encrypted_with_se,
        created_at: chrono::Utc::now(),
    };

    state.registry.lock().unwrap().insert(model_id, model_info);

    let message = if encrypted_with_se {
        "Model stored with Secure Enclave encryption".to_string()
    } else {
        "Model stored with software encryption".to_string()
    };

    Ok(Json(StoreModelResponse {
        id: model_id,
        message,
        encrypted_with_se,
    }))
}

async fn load_model(
    State(state): State<AppState>,
    Path(model_id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if model exists
    let model_info = state
        .registry
        .lock()
        .unwrap()
        .get(&model_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Load model
    let decrypted = {
        #[cfg(target_os = "macos")]
        {
            if model_info.encrypted_with_se {
                if let Some(se_storage) = &state.se_storage {
                    se_storage
                        .load_model_secure_enclave(model_id)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                } else {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            } else {
                state
                    .storage
                    .load_model(model_id, &state.master_key)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            state
                .storage
                .load_model(model_id, &state.master_key)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };

    Ok(Json(serde_json::json!({
        "id": model_id,
        "name": decrypted.metadata.name,
        "size": decrypted.weights.len(),
        "encrypted_with_se": model_info.encrypted_with_se,
        "message": "Model loaded successfully"
    })))
}

async fn list_models(State(state): State<AppState>) -> Json<Vec<ModelInfo>> {
    let models: Vec<ModelInfo> = state.registry.lock().unwrap().values().cloned().collect();

    Json(models)
}
