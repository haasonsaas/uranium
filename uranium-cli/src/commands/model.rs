use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::client::UraniumClient;

#[derive(Deserialize)]
struct ModelMetadata {
    id: Uuid,
    name: String,
    version: String,
    format: String,
    size_bytes: u64,
    created_at: DateTime<Utc>,
    modified_at: DateTime<Utc>,
    description: Option<String>,
    tags: Vec<String>,
}

// Match the demo API response
#[derive(Deserialize)]
struct ModelInfo {
    id: Uuid,
    name: String,
    size: usize,
    encrypted_with_se: bool,
    created_at: DateTime<Utc>,
}

pub async fn list(server_url: &str, detailed: bool) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    let models: Vec<ModelInfo> = client.get("/api/v1/models").await?;

    if models.is_empty() {
        println!("No models found.");
        return Ok(());
    }

    println!("{}", "Available Models".cyan().bold());
    println!("{}", "================".cyan());

    for model in models {
        if detailed {
            println!("\n{}", model.name.green().bold());
            println!("  ID: {}", model.id);
            println!("  Size: {} bytes", model.size);
            println!(
                "  Created: {}",
                model.created_at.format("%Y-%m-%d %H:%M:%S")
            );
            if model.encrypted_with_se {
                println!("  🔐 Encrypted with Secure Enclave");
            } else {
                println!("  🔒 Standard encryption");
            }
        } else {
            let se_icon = if model.encrypted_with_se {
                "🔐"
            } else {
                "🔒"
            };
            println!(
                "{} {:<40} {:>10} bytes  {}",
                se_icon,
                model.name.green(),
                model.size,
                model.created_at.format("%Y-%m-%d")
            );
        }
    }

    Ok(())
}

pub async fn load(server_url: &str, model_id: &str, _output: Option<PathBuf>) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    // For the demo, we'll just show a message since download isn't implemented
    println!("Loading model: {}", model_id.cyan());

    // Get model info
    #[derive(Deserialize)]
    struct LoadResponse {
        id: String,
        name: String,
        size: usize,
        encrypted_with_se: bool,
        message: String,
    }

    let response: LoadResponse = client.get(&format!("/api/v1/models/{}", model_id)).await?;

    println!("{} {}", "✓".green(), response.message);
    println!("  Name: {}", response.name.green());
    println!("  Size: {} bytes", response.size);
    if response.encrypted_with_se {
        println!("  🔐 Decrypted with Secure Enclave");
    }

    // Note: Actual download would be implemented here
    println!(
        "\n{}",
        "Note: Download functionality will be implemented in the full version".yellow()
    );

    Ok(())
}

pub async fn store(
    server_url: &str,
    path: PathBuf,
    name: String,
    version: Option<String>,
    format: Option<String>,
) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    // Read model file
    let data = fs::read(&path)?;
    let size_bytes = data.len() as u64;

    let version = version.unwrap_or_else(|| "1.0".to_string());
    let format = format.unwrap_or_else(|| detect_format(&path));

    println!("Storing model: {} ({})", name.green(), version);
    println!("  Format: {}", format);
    println!("  Size: {} MB", size_bytes / (1024 * 1024));

    // Convert format to match API expectations
    let format_enum = match format.as_str() {
        "safetensors" => "SafeTensors",
        "onnx" => "ONNX",
        "pytorch" => "PyTorch",
        "tensorflow" => "TensorFlow",
        _ => "Unknown",
    };

    // Create request body
    #[derive(Serialize)]
    struct StoreRequest {
        name: String,
        data: Vec<u8>,
        format: String,
    }

    let request = StoreRequest {
        name: format!("{} v{}", name, version),
        data,
        format: format_enum.to_string(),
    };

    // Create progress bar
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {percent}% Uploading...",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    // Upload model
    pb.set_position(50);

    #[derive(Deserialize)]
    struct StoreResponse {
        id: String,
        message: String,
        encrypted_with_se: bool,
    }

    let response: StoreResponse = client.post("/api/v1/models", &request).await?;

    pb.finish_and_clear();

    println!("{} Model stored successfully", "✓".green());
    println!("  ID: {}", response.id.cyan());
    println!("  {}", response.message);
    if response.encrypted_with_se {
        println!("  {} Encrypted with Secure Enclave", "🔐".green());
    }

    Ok(())
}

pub async fn delete(server_url: &str, model_id: &str, force: bool) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    // Get model info for confirmation
    #[derive(Deserialize)]
    struct ModelInfo {
        name: String,
    }

    let model: ModelInfo = client.get(&format!("/api/v1/models/{}", model_id)).await?;

    if !force {
        let confirmed = Confirm::new()
            .with_prompt(format!("Are you sure you want to delete '{}'?", model.name))
            .default(false)
            .interact()?;

        if !confirmed {
            println!("Deletion cancelled.");
            return Ok(());
        }
    }

    // Note: Delete not implemented in demo API
    println!(
        "{}",
        "Note: Delete functionality will be implemented in the full version".yellow()
    );
    println!("Would delete model: {}", model_id);

    Ok(())
}

pub async fn info(server_url: &str, model_id: &str) -> Result<()> {
    let client = UraniumClient::new(server_url.to_string())?;

    #[derive(Deserialize)]
    struct ModelDetails {
        id: String,
        name: String,
        size: usize,
        encrypted_with_se: bool,
        message: String,
    }

    let model: ModelDetails = client.get(&format!("/api/v1/models/{}", model_id)).await?;

    println!("{}", "Model Information".cyan().bold());
    println!("{}", "=================".cyan());
    println!("Name: {}", model.name.green().bold());
    println!("ID: {}", model.id);
    println!("Size: {} bytes", model.size);

    if model.encrypted_with_se {
        println!("Encryption: 🔐 Secure Enclave");
    } else {
        println!("Encryption: 🔒 Standard");
    }

    Ok(())
}

fn detect_format(path: &Path) -> String {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("safetensors") => "safetensors".to_string(),
        Some("onnx") => "onnx".to_string(),
        Some("pt") | Some("pth") => "pytorch".to_string(),
        Some("pb") => "tensorflow".to_string(),
        _ => "unknown".to_string(),
    }
}

