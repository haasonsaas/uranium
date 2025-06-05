use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::{
    auth::{AuthManager, Credentials},
    session::Session,
    vault::Vault,
};
use uranium_core::{models::ModelMetadata, UraniumError};

pub struct ApiState {
    vault: Arc<Vault>,
    auth_manager: Arc<AuthManager>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    error: String,
    code: String,
}

impl From<UraniumError> for ApiError {
    fn from(err: UraniumError) -> Self {
        let (error, code) = match &err {
            UraniumError::AuthenticationFailed => ("Authentication failed", "AUTH_FAILED"),
            UraniumError::AuthorizationDenied { .. } => ("Authorization denied", "AUTH_DENIED"),
            UraniumError::ModelNotFound { .. } => ("Model not found", "MODEL_NOT_FOUND"),
            UraniumError::VaultLocked => ("Vault is locked", "VAULT_LOCKED"),
            UraniumError::SessionExpired => ("Session expired", "SESSION_EXPIRED"),
            _ => ("Internal error", "INTERNAL_ERROR"),
        };

        ApiError {
            error: error.to_string(),
            code: code.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.code.as_str() {
            "AUTH_FAILED" | "AUTH_DENIED" => StatusCode::UNAUTHORIZED,
            "MODEL_NOT_FOUND" => StatusCode::NOT_FOUND,
            "VAULT_LOCKED" => StatusCode::SERVICE_UNAVAILABLE,
            "SESSION_EXPIRED" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(self)).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub fn create_api_server(vault: Arc<Vault>, auth_manager: Arc<AuthManager>) -> Router {
    let state = Arc::new(ApiState {
        vault,
        auth_manager,
    });

    Router::new()
        // Auth endpoints
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        // Vault endpoints
        .route("/api/v1/vault/unlock", post(unlock_vault))
        .route("/api/v1/vault/lock", post(lock_vault))
        .route("/api/v1/vault/status", get(vault_status))
        // Model endpoints
        .route("/api/v1/models", get(list_models))
        .route("/api/v1/models/:id", get(get_model))
        .route("/api/v1/models/:id", delete(delete_model))
        .route("/api/v1/models/:id/download", get(download_model))
        // Health check
        .route("/health", get(health_check))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    expires_at: String,
}

async fn login(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let credentials = Credentials {
        username: req.username,
        password: req.password,
    };

    let auth_token = state
        .auth_manager
        .authenticate(&credentials)
        .await
        .map_err(|e| ApiError::from(e))?;

    Ok(Json(LoginResponse {
        token: auth_token.token,
        expires_at: auth_token.expires_at.to_rfc3339(),
    }))
}

async fn logout(State(state): State<Arc<ApiState>>, session: Session) -> ApiResult<StatusCode> {
    state
        .vault
        .destroy_session(&session)
        .await
        .map_err(|e| ApiError::from(e))?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct UnlockRequest {
    master_key: String,
}

#[axum::debug_handler]
async fn unlock_vault(
    State(state): State<Arc<ApiState>>,
    headers: TypedHeader<Authorization<Bearer>>,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<StatusCode> {
    let TypedHeader(auth) = headers;
    // Verify admin token
    let _ = state
        .auth_manager
        .verify_token(auth.token())
        .await
        .map_err(|e| ApiError::from(e))?;

    // Decode master key (in production, this would be more sophisticated)
    let key_bytes = hex::decode(&req.master_key).map_err(|_| ApiError {
        error: "Invalid master key format".to_string(),
        code: "INVALID_KEY".to_string(),
    })?;

    let master_key = uranium_core::crypto::EncryptionKey::from_bytes(&key_bytes)
        .map_err(|e| ApiError::from(e))?;

    state
        .vault
        .unlock(master_key)
        .await
        .map_err(|e| ApiError::from(e))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn lock_vault(
    State(state): State<Arc<ApiState>>,
    headers: TypedHeader<Authorization<Bearer>>,
) -> ApiResult<StatusCode> {
    let TypedHeader(auth) = headers;
    // Verify admin token
    let _ = state
        .auth_manager
        .verify_token(auth.token())
        .await
        .map_err(|e| ApiError::from(e))?;

    state.vault.lock().await.map_err(|e| ApiError::from(e))?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct VaultStatus {
    locked: bool,
    models_count: usize,
    cache_stats: CacheStats,
}

#[derive(Debug, Serialize)]
struct CacheStats {
    entries: usize,
    size_mb: f64,
}

async fn vault_status(State(state): State<Arc<ApiState>>) -> ApiResult<Json<VaultStatus>> {
    let locked = state.vault.is_locked().await;

    Ok(Json(VaultStatus {
        locked,
        models_count: 0, // TODO: Implement
        cache_stats: CacheStats {
            entries: 0,
            size_mb: 0.0,
        },
    }))
}

async fn list_models(
    State(state): State<Arc<ApiState>>,
    session: Session,
) -> ApiResult<Json<Vec<ModelMetadata>>> {
    let models = state
        .vault
        .list_models(&session)
        .await
        .map_err(|e| ApiError::from(e))?;

    Ok(Json(models))
}

async fn get_model(
    State(state): State<Arc<ApiState>>,
    session: Session,
    Path(model_id): Path<Uuid>,
) -> ApiResult<Json<ModelMetadata>> {
    let model = state
        .vault
        .load_model(&session, model_id)
        .await
        .map_err(|e| ApiError::from(e))?;

    Ok(Json(model.metadata.clone()))
}

async fn delete_model(
    State(state): State<Arc<ApiState>>,
    session: Session,
    Path(model_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    state
        .vault
        .delete_model(&session, model_id)
        .await
        .map_err(|e| ApiError::from(e))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn download_model(
    State(state): State<Arc<ApiState>>,
    session: Session,
    Path(model_id): Path<Uuid>,
) -> ApiResult<Vec<u8>> {
    let model = state
        .vault
        .load_model(&session, model_id)
        .await
        .map_err(|e| ApiError::from(e))?;

    // In production, this would stream the model weights
    Ok(model.weights.clone())
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

// Middleware to extract session from auth token
#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<ApiState>> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<ApiState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| ApiError {
                    error: "Missing authorization header".to_string(),
                    code: "AUTH_REQUIRED".to_string(),
                })?;

        let session = state
            .vault
            .create_session(bearer.token())
            .await
            .map_err(|e| ApiError::from(e))?;

        Ok(session)
    }
}
