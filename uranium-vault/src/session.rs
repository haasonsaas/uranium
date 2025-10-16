use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{AuthProvider, User};
use uranium_core::{Result, UraniumError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl Session {
    pub fn new(user: &User, duration_minutes: u64) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id: user.id,
            created_at: now,
            expires_at: now + Duration::minutes(duration_minutes as i64),
            last_activity: now,
            metadata: HashMap::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn refresh(&mut self, duration_minutes: u64) {
        let now = Utc::now();
        self.last_activity = now;
        self.expires_at = now + Duration::minutes(duration_minutes as i64);
    }
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, Arc<Session>>>>,
    user_sessions: Arc<RwLock<HashMap<Uuid, Vec<Uuid>>>>,
    session_timeout_minutes: u64,
    auth_provider: Arc<dyn AuthProvider>,
}

impl SessionManager {
    pub fn new(session_timeout_minutes: u64, auth_provider: Arc<dyn AuthProvider>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_timeout_minutes,
            auth_provider,
        }
    }

    pub async fn create_session(&self, user: User) -> Result<Session> {
        let session = Session::new(&user, self.session_timeout_minutes);
        let session_arc = Arc::new(session.clone());

        // Store session
        {
            let mut sessions = self.sessions.write();
            sessions.insert(session.id, session_arc);
        }

        // Track user sessions
        {
            let mut user_sessions = self.user_sessions.write();
            user_sessions
                .entry(user.id)
                .or_insert_with(Vec::new)
                .push(session.id);
        }

        // Start cleanup task for expired sessions
        let sessions = self.sessions.clone();
        let user_sessions = self.user_sessions.clone();
        let session_id = session.id;
        let timeout_minutes = self.session_timeout_minutes;

        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(timeout_minutes * 60)).await;

            // Remove expired session
            let mut sessions = sessions.write();
            let user_id = if let Some(session) = sessions.get(&session_id) {
                if session.is_expired() {
                    let user_id = session.user_id;
                    sessions.remove(&session_id);
                    Some(user_id)
                } else {
                    None
                }
            } else {
                None
            };

            // Remove from user sessions if we removed a session
            if let Some(uid) = user_id {
                let mut user_sessions = user_sessions.write();
                if let Some(user_session_list) = user_sessions.get_mut(&uid) {
                    user_session_list.retain(|&id| id != session_id);
                }
            }
        });

        Ok(session)
    }

    pub async fn get_session(&self, session_id: Uuid) -> Result<Arc<Session>> {
        let sessions = self.sessions.read();

        let session = sessions
            .get(&session_id)
            .ok_or(UraniumError::SessionExpired)?
            .clone();

        if session.is_expired() {
            drop(sessions);
            self.destroy_session(&session).await?;
            return Err(UraniumError::SessionExpired);
        }

        Ok(session)
    }

    pub async fn get_user(&self, session: &Session) -> Result<User> {
        if session.is_expired() {
            return Err(UraniumError::SessionExpired);
        }

        // Fetch user from auth provider
        self.auth_provider.get_user(session.user_id).await
    }

    pub async fn refresh_session(&self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write();

        if let Some(session_arc) = sessions.get_mut(&session_id) {
            let mut session = Session::clone(&session_arc);
            session.refresh(self.session_timeout_minutes);
            *session_arc = Arc::new(session);
            Ok(())
        } else {
            Err(UraniumError::SessionExpired)
        }
    }

    pub async fn destroy_session(&self, session: &Session) -> Result<()> {
        // Remove session
        {
            let mut sessions = self.sessions.write();
            sessions.remove(&session.id);
        }

        // Remove from user sessions
        {
            let mut user_sessions = self.user_sessions.write();
            if let Some(user_session_list) = user_sessions.get_mut(&session.user_id) {
                user_session_list.retain(|&id| id != session.id);
            }
        }

        Ok(())
    }

    pub async fn destroy_user_sessions(&self, user_id: Uuid) -> Result<()> {
        let session_ids = {
            let user_sessions = self.user_sessions.read();
            user_sessions.get(&user_id).cloned().unwrap_or_default()
        };

        // Remove all user's sessions
        {
            let mut sessions = self.sessions.write();
            for session_id in &session_ids {
                sessions.remove(session_id);
            }
        }

        // Clear user session tracking
        {
            let mut user_sessions = self.user_sessions.write();
            user_sessions.remove(&user_id);
        }

        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        let expired_sessions: Vec<Uuid> = {
            let sessions = self.sessions.read();
            sessions
                .iter()
                .filter(|(_, session)| session.is_expired())
                .map(|(id, _)| *id)
                .collect()
        };

        for session_id in expired_sessions {
            if let Ok(session) = self.get_session(session_id).await {
                self.destroy_session(&session).await?;
            }
        }

        Ok(())
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn user_session_count(&self, user_id: Uuid) -> usize {
        self.user_sessions
            .read()
            .get(&user_id)
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }

    pub fn active_session_ids(&self) -> Vec<Uuid> {
        self.sessions
            .read()
            .keys()
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Permission, User};
    use std::collections::HashSet;

    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "test_user".to_string(),
            email: Some("test@example.com".to_string()),
            roles: vec!["developer".to_string()],
            permissions: HashSet::from([Permission::ModelRead]),
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
        }
    }

    #[tokio::test]
    async fn test_session_creation() {
        use crate::auth::DatabaseAuthProvider;
        let pool = sqlx::SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();

        let auth_provider = Arc::new(DatabaseAuthProvider::new(pool));
        let manager = SessionManager::new(60, auth_provider);
        let user = create_test_user();

        let session = manager.create_session(user.clone()).await.unwrap();

        assert_eq!(session.user_id, user.id);
        assert!(!session.is_expired());
        assert_eq!(manager.active_session_count(), 1);
        assert_eq!(manager.user_session_count(user.id), 1);
    }

    #[tokio::test]
    async fn test_session_expiration() {
        use crate::auth::DatabaseAuthProvider;
        let pool = sqlx::SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();

        let auth_provider = Arc::new(DatabaseAuthProvider::new(pool));
        let manager = SessionManager::new(0, auth_provider); // Immediate expiration
        let user = create_test_user();

        let session = manager.create_session(user.clone()).await.unwrap();

        // Session should be expired immediately
        assert!(session.is_expired());

        // Trying to get the session should fail
        let result = manager.get_session(session.id).await;
        assert!(matches!(result, Err(UraniumError::SessionExpired)));
    }
}
