use anyhow::{Context, Result};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

use crate::config;

pub struct UraniumClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl UraniumClient {
    pub fn new(base_url: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true) // For development
            .build()
            .context("Failed to create HTTP client")?;

        let token = config::load_token().ok();

        Ok(Self {
            client,
            base_url,
            token,
        })
    }

    #[allow(dead_code)]
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = self.client.get(&url);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to GET {}", url))?;

        handle_response(response).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = self.client.post(&url).json(body);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to POST {}", url))?;

        handle_response(response).await
    }

    #[allow(dead_code)]
    pub async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = self.client.delete(&url);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to DELETE {}", url))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error = parse_error(response).await?;
            anyhow::bail!("{}", error)
        }
    }

    #[allow(dead_code)]
    pub async fn download(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = self.client.get(&url);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to download from {}", url))?;

        if response.status().is_success() {
            let bytes = response
                .bytes()
                .await
                .context("Failed to read response body")?;
            Ok(bytes.to_vec())
        } else {
            let error = parse_error(response).await?;
            anyhow::bail!("{}", error)
        }
    }
}

async fn handle_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();

    if status.is_success() {
        response.json().await.context("Failed to parse response")
    } else {
        let error = parse_error(response).await?;
        anyhow::bail!("{}", error)
    }
}

async fn parse_error(response: reqwest::Response) -> Result<String> {
    let status = response.status();

    #[derive(Deserialize)]
    struct ApiError {
        error: String,
        code: String,
    }

    if let Ok(api_error) = response.json::<ApiError>().await {
        Ok(format!("{} ({})", api_error.error, api_error.code))
    } else {
        Ok(format!("HTTP {} error", status.as_u16()))
    }
}
