use anyhow::Result;
use uranium_sdk::{ModelFormat, VaultClient};

#[tokio::main]
async fn main() -> Result<()> {
    // Create client
    let mut client = VaultClient::new("http://localhost:8080")?;

    // Authenticate
    println!("Authenticating...");
    let token = client.authenticate("admin", "changeme").await?;
    println!("✅ Authenticated successfully");
    println!("Token: {}...", &token[..20]);

    // Check vault status
    println!("\nChecking vault status...");
    let status = client.status().await?;
    println!("Vault status: {}", status.vault_status);
    println!(
        "Secure Enclave available: {}",
        status.secure_enclave_available
    );
    println!("Models count: {}", status.models_count);

    // List models
    println!("\nListing models...");
    let models = client.list_models().await?;
    if models.is_empty() {
        println!("No models found");
    } else {
        for model in &models {
            println!("- {} ({})", model.name, model.id);
            println!("  Size: {} bytes", model.size);
            println!("  Encrypted with SE: {}", model.encrypted_with_se);
        }
    }

    // Store a model
    println!("\nStoring a test model...");
    let test_data = b"This is test model data".to_vec();
    let model_id = client
        .store_model("test-model", test_data, ModelFormat::SafeTensors)
        .await?;
    println!("✅ Model stored with ID: {}", model_id);

    // Get model info
    println!("\nGetting model info...");
    let model_info = client.get_model(model_id).await?;
    println!("Model: {}", model_info.name);
    println!("Created: {}", model_info.created_at);

    Ok(())
}
