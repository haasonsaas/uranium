use anyhow::Result;
use colored::Colorize;
use dialoguer::{Input, Password};
use serde::{Deserialize, Serialize};

use crate::{client::UraniumClient, config};

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

pub async fn login(server_url: &str, username: Option<String>) -> Result<()> {
    let username = match username {
        Some(u) => u,
        None => Input::new().with_prompt("Username").interact()?,
    };

    let password = Password::new().with_prompt("Password").interact()?;

    println!("Authenticating...");

    let client = UraniumClient::new(server_url.to_string())?;

    let request = LoginRequest {
        username: username.clone(),
        password,
    };
    let response: LoginResponse = client.post("/api/v1/auth/login", &request).await?;

    // Save token
    config::save_token(&response.token)?;

    // Update config with username
    let mut cfg = config::load_config(None)?;
    cfg.username = Some(username.clone());
    config::save_config(&cfg)?;

    println!("{}", "✓ Login successful!".green());
    println!("Token expires at: {}", response.expires_at);

    Ok(())
}

pub async fn logout(server_url: &str) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    // Call logout endpoint
    let _: serde_json::Value = client
        .post("/api/v1/auth/logout", &serde_json::json!({}))
        .await?;

    // Delete local token
    config::delete_token()?;

    println!("{}", "✓ Logged out successfully".green());

    Ok(())
}

pub async fn status(_server_url: &str) -> Result<()> {
    match config::load_token() {
        Ok(_) => {
            let config = config::load_config(None)?;
            println!("{}", "Authenticated".green());
            if let Some(username) = config.username {
                println!("User: {}", username);
            }
        }
        Err(_) => {
            println!("{}", "Not authenticated".yellow());
            println!("Run 'uranium auth login' to authenticate");
        }
    }

    Ok(())
}
