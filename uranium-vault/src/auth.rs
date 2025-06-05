use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{AuditEvent, AuditLogger};
use uranium_core::{Result, UraniumError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub permissions: HashSet<Permission>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ModelRead,
    ModelWrite,
    ModelDelete,
    ModelExecute,
    VaultAdmin,
    AuditRead,
    UserManage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // user id
    exp: usize,  // expiration
    iat: usize,  // issued at
    roles: Vec<String>,
    permissions: Vec<Permission>,
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, credentials: &Credentials) -> Result<User>;
    async fn get_user(&self, user_id: Uuid) -> Result<User>;
    async fn update_last_login(&self, user_id: Uuid) -> Result<()>;
}

pub struct AuthManager {
    provider: Arc<dyn AuthProvider>,
    jwt_secret: String,
    token_duration: Duration,
    audit_logger: Option<Arc<dyn AuditLogger>>,
}

impl AuthManager {
    pub fn new(
        provider: Arc<dyn AuthProvider>,
        jwt_secret: String,
        token_duration_hours: i64,
    ) -> Self {
        Self {
            provider,
            jwt_secret,
            token_duration: Duration::hours(token_duration_hours),
            audit_logger: None,
        }
    }

    pub fn with_audit_logger(mut self, audit_logger: Arc<dyn AuditLogger>) -> Self {
        self.audit_logger = Some(audit_logger);
        self
    }

    pub fn get_provider(&self) -> Arc<dyn AuthProvider> {
        self.provider.clone()
    }

    pub async fn authenticate(&self, credentials: &Credentials) -> Result<AuthToken> {
        let result = self.provider.authenticate(credentials).await;

        // Log authentication attempt
        if let Some(audit_logger) = &self.audit_logger {
            let event = match &result {
                Ok(user) => AuditEvent::AuthenticationAttempt {
                    username: user.username.clone(),
                    success: true,
                    timestamp: Utc::now(),
                    ip_address: None,
                },
                Err(_) => AuditEvent::AuthenticationAttempt {
                    username: credentials.username.clone(),
                    success: false,
                    timestamp: Utc::now(),
                    ip_address: None,
                },
            };
            let _ = audit_logger.log(event).await;
        }

        let user = result?;

        if !user.is_active {
            return Err(UraniumError::AuthenticationFailed);
        }

        self.provider.update_last_login(user.id).await?;

        let expires_at = Utc::now() + self.token_duration;
        let claims = Claims {
            sub: user.id.to_string(),
            exp: expires_at.timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
            roles: user.roles,
            permissions: user.permissions.into_iter().collect(),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| UraniumError::Internal(e.to_string()))?;

        Ok(AuthToken {
            token,
            expires_at,
            refresh_token: None, // TODO: Implement refresh tokens
        })
    }

    pub async fn verify_token(&self, token: &str) -> Result<User> {
        let validation = Validation::new(Algorithm::HS256);

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| UraniumError::AuthenticationFailed)?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| UraniumError::AuthenticationFailed)?;

        self.provider.get_user(user_id).await
    }

    pub fn check_permission(user: &User, permission: Permission) -> Result<()> {
        if user.permissions.contains(&permission)
            || user.permissions.contains(&Permission::VaultAdmin)
        {
            Ok(())
        } else {
            Err(UraniumError::AuthorizationDenied {
                resource: format!("{:?}", permission),
            })
        }
    }

    pub fn check_model_access(user: &User, _model_id: Uuid, permission: Permission) -> Result<()> {
        // TODO: Implement model-specific access control
        Self::check_permission(user, permission)
    }
}

pub struct DatabaseAuthProvider {
    pool: SqlitePool,
    password_hasher: uranium_core::crypto::PasswordManager,
}

impl DatabaseAuthProvider {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            password_hasher: uranium_core::crypto::PasswordManager::new(),
        }
    }

    pub async fn create_admin_user(&self, username: String, password: String) -> Result<User> {
        self.create_user(
            username,
            password,
            Some("jonathan@haasonsaas.com".to_string()),
            vec!["admin".to_string()],
        )
        .await
    }

    pub async fn create_user(
        &self,
        username: String,
        password: String,
        email: Option<String>,
        roles: Vec<String>,
    ) -> Result<User> {
        let user_id = Uuid::new_v4();
        let password_hash = self.password_hasher.hash_password(&password)?;

        let mut permissions = HashSet::new();

        // Map roles to permissions
        for role in &roles {
            match role.as_str() {
                "admin" => {
                    permissions.insert(Permission::VaultAdmin);
                }
                "developer" => {
                    permissions.insert(Permission::ModelRead);
                    permissions.insert(Permission::ModelExecute);
                }
                "auditor" => {
                    permissions.insert(Permission::AuditRead);
                }
                _ => {}
            }
        }

        // Store in database
        let user_id_str = user_id.to_string();
        let roles_json = serde_json::to_string(&roles).unwrap();
        let created_at_timestamp = Utc::now().timestamp();

        sqlx::query!(
            r#"
            INSERT INTO users (id, username, email, password_hash, roles, is_active, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            user_id_str,
            username,
            email,
            password_hash,
            roles_json,
            true,
            created_at_timestamp,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UraniumError::Internal(e.to_string()))?;

        Ok(User {
            id: user_id,
            username,
            email,
            roles,
            permissions,
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
        })
    }
}

#[async_trait]
impl AuthProvider for DatabaseAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> Result<User> {
        let row = sqlx::query!(
            r#"
            SELECT id, username, email, password_hash, roles, created_at, last_login, is_active
            FROM users
            WHERE username = ?1
            "#,
            credentials.username,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UraniumError::Internal(e.to_string()))?;

        let row = row.ok_or(UraniumError::AuthenticationFailed)?;

        // Verify password
        if !self
            .password_hasher
            .verify_password(&credentials.password, &row.password_hash)?
        {
            return Err(UraniumError::AuthenticationFailed);
        }

        let roles: Vec<String> =
            serde_json::from_str(&row.roles).map_err(|e| UraniumError::Internal(e.to_string()))?;

        let mut permissions = HashSet::new();
        for role in &roles {
            match role.as_str() {
                "admin" => {
                    permissions.insert(Permission::VaultAdmin);
                }
                "developer" => {
                    permissions.insert(Permission::ModelRead);
                    permissions.insert(Permission::ModelExecute);
                }
                "auditor" => {
                    permissions.insert(Permission::AuditRead);
                }
                _ => {}
            }
        }

        Ok(User {
            id: Uuid::parse_str(&row.id.unwrap()).unwrap(),
            username: row.username,
            email: Some(row.email),
            roles,
            permissions,
            created_at: DateTime::from_timestamp(row.created_at, 0).unwrap(),
            last_login: row
                .last_login
                .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            is_active: row.is_active,
        })
    }

    async fn get_user(&self, user_id: Uuid) -> Result<User> {
        let user_id_str = user_id.to_string();
        let row = sqlx::query!(
            r#"
            SELECT id, username, email, roles, created_at, last_login, is_active
            FROM users
            WHERE id = ?1
            "#,
            user_id_str,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UraniumError::Internal(e.to_string()))?;

        let row = row.ok_or(UraniumError::AuthenticationFailed)?;

        let roles: Vec<String> =
            serde_json::from_str(&row.roles).map_err(|e| UraniumError::Internal(e.to_string()))?;

        let mut permissions = HashSet::new();
        for role in &roles {
            match role.as_str() {
                "admin" => {
                    permissions.insert(Permission::VaultAdmin);
                }
                "developer" => {
                    permissions.insert(Permission::ModelRead);
                    permissions.insert(Permission::ModelExecute);
                }
                "auditor" => {
                    permissions.insert(Permission::AuditRead);
                }
                _ => {}
            }
        }

        Ok(User {
            id: user_id,
            username: row.username,
            email: Some(row.email),
            roles,
            permissions,
            created_at: DateTime::from_timestamp(row.created_at, 0).unwrap(),
            last_login: row
                .last_login
                .and_then(|ts| DateTime::from_timestamp(ts, 0)),
            is_active: row.is_active,
        })
    }

    async fn update_last_login(&self, user_id: Uuid) -> Result<()> {
        let now_timestamp = Utc::now().timestamp();
        let user_id_str = user_id.to_string();

        sqlx::query!(
            r#"
            UPDATE users
            SET last_login = ?1
            WHERE id = ?2
            "#,
            now_timestamp,
            user_id_str,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UraniumError::Internal(e.to_string()))?;

        Ok(())
    }
}
