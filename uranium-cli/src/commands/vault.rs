use anyhow::Result;
use colored::Colorize;
use dialoguer::Password;
use serde::{Deserialize, Serialize};

use crate::client::UraniumClient;

#[derive(Serialize)]
struct UnlockRequest {
    master_key: String,
}

#[derive(Deserialize)]
pub struct VaultStatus {
    pub vault_status: String,
    pub secure_enclave_available: bool,
    pub secure_enclave_enabled: bool,
    pub models_count: usize,
}

pub async fn unlock(server_url: &str) -> Result<()> {
    let master_key = Password::new().with_prompt("Master key (hex)").interact()?;

    println!("Unlocking vault...");

    let client = UraniumClient::new(server_url.to_string())?;

    let request = UnlockRequest { master_key };
    let _: serde_json::Value = client.post("/api/v1/vault/unlock", &request).await?;

    println!("{}", "✓ Vault unlocked successfully".green());

    Ok(())
}

pub async fn lock(server_url: &str) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    let _: serde_json::Value = client
        .post("/api/v1/vault/lock", &serde_json::json!({}))
        .await?;

    println!("{}", "✓ Vault locked successfully".green());

    Ok(())
}

pub async fn status(server_url: &str) -> Result<()> {
    let _client = UraniumClient::new(server_url.to_string())?;

    let status = get_status(server_url).await?;

    println!("{}", "Vault Status".cyan().bold());
    println!("{}", "============".cyan());

    println!("Status: {}", status.vault_status.green());
    println!("Models: {}", status.models_count);

    if status.secure_enclave_available {
        println!("Secure Enclave: {} Available", "✅".green());
        if status.secure_enclave_enabled {
            println!("  Encryption: {} Hardware-backed", "🔐".green());
        } else {
            println!("  Encryption: 🔒 Software");
        }
    } else {
        println!("Secure Enclave: ❌ Not available");
        println!("  Encryption: 🔒 Software");
    }

    Ok(())
}

pub async fn get_status(server_url: &str) -> Result<VaultStatus> {
    let client = UraniumClient::new(server_url.to_string())?;
    client.get("/api/v1/status").await
}
