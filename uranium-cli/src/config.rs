use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    pub username: Option<String>,
    pub token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080".to_string(),
            username: None,
            token: None,
        }
    }
}

pub fn config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Failed to get home directory")?;
    Ok(home.join(".uranium"))
}

pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn token_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("token"))
}

pub fn load_config(path: Option<PathBuf>) -> Result<CliConfig> {
    let config_path = match path {
        Some(p) => p,
        None => config_file()?,
    };

    if !config_path.exists() {
        return Ok(CliConfig::default());
    }

    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config from {:?}", config_path))?;

    let config: CliConfig = toml::from_str(&content).context("Failed to parse config file")?;

    Ok(config)
}

pub fn save_config(config: &CliConfig) -> Result<()> {
    let config_path = config_file()?;

    // Create directory if it doesn't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    let content = toml::to_string_pretty(config).context("Failed to serialize config")?;

    fs::write(&config_path, content)
        .with_context(|| format!("Failed to write config to {:?}", config_path))?;

    Ok(())
}

pub fn save_token(token: &str) -> Result<()> {
    let token_path = token_file()?;

    // Create directory if it doesn't exist
    if let Some(parent) = token_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    fs::write(&token_path, token)
        .with_context(|| format!("Failed to write token to {:?}", token_path))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&token_path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&token_path, permissions)?;
    }

    Ok(())
}

pub fn load_token() -> Result<String> {
    let token_path = token_file()?;

    if !token_path.exists() {
        anyhow::bail!("Not authenticated. Run 'uranium auth login' first.");
    }

    let token = fs::read_to_string(&token_path)
        .with_context(|| format!("Failed to read token from {:?}", token_path))?;

    Ok(token.trim().to_string())
}

pub fn delete_token() -> Result<()> {
    let token_path = token_file()?;

    if token_path.exists() {
        fs::remove_file(&token_path).context("Failed to delete token file")?;
    }

    Ok(())
}
