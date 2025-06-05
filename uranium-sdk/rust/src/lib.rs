//! Uranium SDK - Rust client library for Uranium Vault
//!
//! This SDK provides a simple interface to interact with the Uranium Vault server
//! for secure model storage and retrieval.

use anyhow::{Context, Result};
use reqwest::{Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

pub mod models;
pub use models::*;

/// Uranium Vault client
pub struct VaultClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl VaultClient {
    /// Create a new vault client
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300)) // 5 minute timeout for large models
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.into(),
            token: None,
        })
    }

    /// Authenticate with the vault
    pub async fn authenticate(&mut self, username: &str, password: &str) -> Result<String> {
        #[derive(Serialize)]
        struct LoginRequest {
            username: String,
            password: String,
        }

        #[derive(Deserialize)]
        struct LoginResponse {
            token: String,
            expires_at: String,
        }

        let req = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };

        let resp: LoginResponse = self
            .post("/api/v1/auth/login", &req)
            .await
            .context("Authentication failed")?;

        self.token = Some(resp.token.clone());
        Ok(resp.token)
    }

    /// Store a model in the vault
    pub async fn store_model(
        &self,
        name: &str,
        data: Vec<u8>,
        format: ModelFormat,
    ) -> Result<Uuid> {
        self.require_auth()?;

        #[derive(Serialize)]
        struct StoreRequest {
            name: String,
            data: Vec<u8>,
            format: ModelFormat,
        }

        #[derive(Deserialize)]
        struct StoreResponse {
            id: Uuid,
            message: String,
            encrypted_with_se: bool,
        }

        let req = StoreRequest {
            name: name.to_string(),
            data,
            format,
        };

        let resp: StoreResponse = self
            .post("/api/v1/models", &req)
            .await
            .context("Failed to store model")?;

        Ok(resp.id)
    }

    /// Store a model from file
    pub async fn store_model_from_file(
        &self,
        path: impl AsRef<Path>,
        name: &str,
        format: ModelFormat,
    ) -> Result<Uuid> {
        let mut file = File::open(path.as_ref())
            .await
            .context("Failed to open model file")?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .context("Failed to read model file")?;

        self.store_model(name, data, format).await
    }

    /// List all models
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        self.require_auth()?;
        self.get("/api/v1/models").await
    }

    /// Get model metadata
    pub async fn get_model(&self, model_id: Uuid) -> Result<ModelInfo> {
        self.require_auth()?;
        self.get(&format!("/api/v1/models/{}", model_id)).await
    }

    /// Load a model's data
    pub async fn load_model(&self, _model_id: Uuid) -> Result<Vec<u8>> {
        self.require_auth()?;

        // Note: This would need the actual download endpoint
        // For now, returning empty vec as placeholder
        Ok(Vec::new())
    }

    /// Delete a model
    pub async fn delete_model(&self, model_id: Uuid) -> Result<()> {
        self.require_auth()?;

        let resp = self
            .client
            .delete(&format!("{}/api/v1/models/{}", self.base_url, model_id))
            .bearer_auth(self.token.as_ref().unwrap())
            .send()
            .await
            .context("Failed to delete model")?;

        ensure_success(resp).await?;
        Ok(())
    }

    /// Get vault status
    pub async fn status(&self) -> Result<VaultStatus> {
        self.get("/api/v1/status").await
    }

    // Helper methods

    fn require_auth(&self) -> Result<()> {
        if self.token.is_none() {
            anyhow::bail!("Not authenticated. Call authenticate() first.");
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let mut req = self.client.get(&format!("{}{}", self.base_url, path));

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.context("Request failed")?;
        parse_response(resp).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let mut req = self
            .client
            .post(&format!("{}{}", self.base_url, path))
            .json(body);

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.context("Request failed")?;
        parse_response(resp).await
    }
}

async fn ensure_success(resp: Response) -> Result<()> {
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed with status {}: {}", status, text)
    }
}

async fn parse_response<T: DeserializeOwned>(resp: Response) -> Result<T> {
    if resp.status().is_success() {
        resp.json().await.context("Failed to parse response")
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed with status {}: {}", status, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = VaultClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
        assert!(client.token.is_none());
    }
}
