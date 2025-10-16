use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use uranium_core::{Result, UraniumError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum AuditEvent {
    VaultUnlocked {
        timestamp: DateTime<Utc>,
    },
    VaultLocked {
        timestamp: DateTime<Utc>,
    },
    ModelAccessed {
        user_id: Uuid,
        model_id: Uuid,
        action: String,
        timestamp: DateTime<Utc>,
    },
    ModelStored {
        user_id: Uuid,
        model_id: Uuid,
        size_bytes: u64,
        timestamp: DateTime<Utc>,
    },
    ModelDeleted {
        user_id: Uuid,
        model_id: Uuid,
        timestamp: DateTime<Utc>,
    },
    ModelMigrated {
        user_id: Uuid,
        model_id: Uuid,
        migration_type: String,
        timestamp: DateTime<Utc>,
    },
    SessionCreated {
        session_id: Uuid,
        user_id: Uuid,
        timestamp: DateTime<Utc>,
    },
    SessionDestroyed {
        session_id: Uuid,
        user_id: Uuid,
        timestamp: DateTime<Utc>,
    },
    AuthenticationAttempt {
        username: String,
        success: bool,
        ip_address: Option<String>,
        timestamp: DateTime<Utc>,
    },
    PermissionDenied {
        user_id: Uuid,
        resource: String,
        action: String,
        timestamp: DateTime<Utc>,
    },
    SecurityAlert {
        alert_type: String,
        description: String,
        severity: AlertSeverity,
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log(&self, event: AuditEvent) -> Result<()>;
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>>;
    async fn get_stats(&self) -> Result<AuditStats>;
}

#[derive(Debug, Clone)]
pub struct AuditFilter {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub user_id: Option<Uuid>,
    pub model_id: Option<Uuid>,
    pub event_types: Option<Vec<String>>,
    pub min_severity: Option<AlertSeverity>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditStats {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub active_sessions: u64,
    pub models_accessed_today: u64,
    pub failed_auth_attempts: u64,
    pub security_alerts: u64,
}

pub struct FileAuditLogger {
    file_path: String,
    file: Mutex<tokio::fs::File>,
}

impl FileAuditLogger {
    pub async fn new(file_path: String) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .await
            .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        Ok(Self {
            file_path,
            file: Mutex::new(file),
        })
    }
}

#[async_trait]
impl AuditLogger for FileAuditLogger {
    async fn log(&self, event: AuditEvent) -> Result<()> {
        let log_entry =
            serde_json::to_string(&event).map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        let mut file = self.file.lock().await;
        file.write_all(log_entry.as_bytes())
            .await
            .map_err(|e| UraniumError::AuditLog(e.to_string()))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| UraniumError::AuditLog(e.to_string()))?;
        file.flush()
            .await
            .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        Ok(())
    }

    async fn query(&self, _filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        // Simple implementation - in production, use proper indexing
        Err(UraniumError::Internal(
            "Query not implemented for file logger".to_string(),
        ))
    }

    async fn get_stats(&self) -> Result<AuditStats> {
        // Simple implementation
        Ok(AuditStats {
            total_events: 0,
            events_by_type: HashMap::new(),
            active_sessions: 0,
            models_accessed_today: 0,
            failed_auth_attempts: 0,
            security_alerts: 0,
        })
    }
}

pub struct DatabaseAuditLogger {
    pool: SqlitePool,
}

impl DatabaseAuditLogger {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn init_schema(&self) -> Result<()> {
        // Schema creation is handled by SQLx migrations
        // Tables and indexes are created in migrations/001_initial.sql
        Ok(())
    }
}

#[async_trait]
impl AuditLogger for DatabaseAuditLogger {
    async fn log(&self, event: AuditEvent) -> Result<()> {
        let event_type = match &event {
            AuditEvent::VaultUnlocked { .. } => "vault_unlocked",
            AuditEvent::VaultLocked { .. } => "vault_locked",
            AuditEvent::ModelAccessed { .. } => "model_accessed",
            AuditEvent::ModelStored { .. } => "model_stored",
            AuditEvent::ModelDeleted { .. } => "model_deleted",
            AuditEvent::ModelMigrated { .. } => "model_migrated",
            AuditEvent::SessionCreated { .. } => "session_created",
            AuditEvent::SessionDestroyed { .. } => "session_destroyed",
            AuditEvent::AuthenticationAttempt { .. } => "auth_attempt",
            AuditEvent::PermissionDenied { .. } => "permission_denied",
            AuditEvent::SecurityAlert { .. } => "security_alert",
        };

        let (user_id, model_id, timestamp) = match &event {
            AuditEvent::ModelAccessed {
                user_id,
                model_id,
                timestamp,
                ..
            }
            | AuditEvent::ModelStored {
                user_id,
                model_id,
                timestamp,
                ..
            }
            | AuditEvent::ModelDeleted {
                user_id,
                model_id,
                timestamp,
                ..
            }
            | AuditEvent::ModelMigrated {
                user_id,
                model_id,
                timestamp,
                ..
            } => (
                Some(user_id.to_string()),
                Some(model_id.to_string()),
                *timestamp,
            ),
            AuditEvent::SessionCreated {
                user_id, timestamp, ..
            }
            | AuditEvent::SessionDestroyed {
                user_id, timestamp, ..
            } => (Some(user_id.to_string()), None, *timestamp),
            AuditEvent::PermissionDenied {
                user_id, timestamp, ..
            } => (Some(user_id.to_string()), None, *timestamp),
            AuditEvent::VaultUnlocked { timestamp }
            | AuditEvent::VaultLocked { timestamp }
            | AuditEvent::AuthenticationAttempt { timestamp, .. }
            | AuditEvent::SecurityAlert { timestamp, .. } => (None, None, *timestamp),
        };

        let event_data =
            serde_json::to_string(&event).map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        let timestamp_val = timestamp.timestamp();
        let indexed_at_val = Utc::now().timestamp();

        sqlx::query!(
            r#"
            INSERT INTO audit_log (event_type, event_data, user_id, model_id, timestamp, indexed_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            event_type,
            event_data,
            user_id,
            model_id,
            timestamp_val,
            indexed_at_val,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        Ok(())
    }

    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        let mut query = String::from("SELECT event_data FROM audit_log WHERE 1=1");
        let mut params: Vec<(String, i32)> = Vec::new();

        if let Some(start) = filter.start_time {
            query.push_str(" AND timestamp >= ?");
            params.push((start.timestamp().to_string(), 0));
        }

        if let Some(end) = filter.end_time {
            query.push_str(" AND timestamp <= ?");
            params.push((end.timestamp().to_string(), 0));
        }

        if let Some(user_id) = filter.user_id {
            query.push_str(" AND user_id = ?");
            params.push((user_id.to_string(), 1));
        }

        if let Some(model_id) = filter.model_id {
            query.push_str(" AND model_id = ?");
            params.push((model_id.to_string(), 2));
        }

        if let Some(event_types) = &filter.event_types {
            if !event_types.is_empty() {
                let placeholders = std::iter::repeat("?")
                    .take(event_types.len())
                    .collect::<Vec<_>>()
                    .join(",");
                query.push_str(&format!(" AND event_type IN ({})", placeholders));
                for event_type in event_types {
                    params.push((event_type.clone(), 3));
                }
            }
        }

        if let Some(severity) = filter.min_severity {
            query.push_str(" AND (event_type != 'security_alert' OR event_data LIKE ?)");
            let severity_str = format!("%\"severity\":\"{:?}\"%", severity);
            params.push((severity_str, 4));
        }

        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let mut sqlx_query = sqlx::query(&query);
        for (value, ty) in params {
            match ty {
                0 | 3 | 4 => {
                    sqlx_query = sqlx_query.bind(value);
                }
                1 | 2 => {
                    sqlx_query = sqlx_query.bind(value);
                }
                _ => unreachable!(),
            }
        }

        let rows = sqlx_query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        let events: Result<Vec<AuditEvent>> = rows
            .into_iter()
            .map(|row| {
                let event_data: &str = row.get("event_data");
                serde_json::from_str(event_data)
                    .map_err(|e| UraniumError::AuditLog(e.to_string()))
            })
            .collect();

        events
    }

    async fn get_stats(&self) -> Result<AuditStats> {
        let total = sqlx::query!("SELECT COUNT(*) as count FROM audit_log")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        let today_start = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();

        let today_timestamp = today_start.timestamp();
        let models_today = sqlx::query!(
            "SELECT COUNT(DISTINCT model_id) as count FROM audit_log WHERE event_type = 'model_accessed' AND timestamp >= ?",
            today_timestamp
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        let failed_auth = sqlx::query!(
            "SELECT COUNT(*) as count FROM audit_log WHERE event_type = 'auth_attempt' AND event_data LIKE '%\"success\":false%'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        let alerts = sqlx::query!(
            "SELECT COUNT(*) as count FROM audit_log WHERE event_type = 'security_alert'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| UraniumError::AuditLog(e.to_string()))?;

        Ok(AuditStats {
            total_events: total.count as u64,
            events_by_type: HashMap::new(), // TODO: Implement
            active_sessions: 0,             // TODO: Get from session manager
            models_accessed_today: models_today.count as u64,
            failed_auth_attempts: failed_auth.count as u64,
            security_alerts: alerts.count as u64,
        })
    }
}

pub struct SecurityMonitor {
    logger: Arc<dyn AuditLogger>,
    alert_threshold: HashMap<String, (u64, std::time::Duration)>,
}

impl SecurityMonitor {
    pub fn new(logger: Arc<dyn AuditLogger>) -> Self {
        let mut thresholds = HashMap::new();
        thresholds.insert(
            "failed_auth".to_string(),
            (5, std::time::Duration::from_secs(300)),
        );
        thresholds.insert(
            "model_access".to_string(),
            (100, std::time::Duration::from_secs(3600)),
        );

        Self {
            logger,
            alert_threshold: thresholds,
        }
    }

    pub async fn check_anomalies(&self) -> Result<()> {
        // Check for suspicious patterns
        let _ = self.logger.get_stats().await?;

        Ok(())
    }
}
