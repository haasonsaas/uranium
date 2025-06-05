use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod client;
mod commands;
mod config;

use commands::{auth, model, vault};

#[derive(Parser)]
#[command(
    name = "uranium",
    about = "Secure vault for LLM weights",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true, help = "Vault server URL")]
    server: Option<String>,

    #[arg(short, long, global = true, help = "Configuration file")]
    config: Option<PathBuf>,

    #[arg(short, long, global = true, help = "Enable verbose output")]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Authentication commands")]
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    #[command(about = "Vault management commands")]
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },

    #[command(about = "Model management commands")]
    Model {
        #[command(subcommand)]
        command: ModelCommands,
    },

    #[command(about = "Initialize Uranium configuration")]
    Init,

    #[command(about = "Show Uranium status")]
    Status,
}

#[derive(Subcommand)]
enum AuthCommands {
    #[command(about = "Login to the vault")]
    Login {
        #[arg(short, long, help = "Username")]
        username: Option<String>,
    },

    #[command(about = "Logout from the vault")]
    Logout,

    #[command(about = "Show current authentication status")]
    Status,
}

#[derive(Subcommand)]
enum VaultCommands {
    #[command(about = "Unlock the vault")]
    Unlock,

    #[command(about = "Lock the vault")]
    Lock,

    #[command(about = "Show vault status")]
    Status,
}

#[derive(Subcommand)]
enum ModelCommands {
    #[command(about = "List available models")]
    List {
        #[arg(short, long, help = "Show detailed information")]
        detailed: bool,
    },

    #[command(about = "Load a model")]
    Load {
        #[arg(help = "Model ID or name")]
        model: String,

        #[arg(short, long, help = "Output path for the model")]
        output: Option<PathBuf>,
    },

    #[command(about = "Store a new model")]
    Store {
        #[arg(help = "Path to the model file")]
        path: PathBuf,

        #[arg(short, long, help = "Model name")]
        name: String,

        #[arg(long, help = "Model version")]
        version: Option<String>,

        #[arg(short, long, help = "Model format (safetensors, onnx, pytorch)")]
        format: Option<String>,
    },

    #[command(about = "Delete a model")]
    Delete {
        #[arg(help = "Model ID")]
        model: String,

        #[arg(short, long, help = "Skip confirmation")]
        force: bool,
    },

    #[command(about = "Show model information")]
    Info {
        #[arg(help = "Model ID")]
        model: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("uranium=debug")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter("uranium=info")
            .init();
    }

    // Load configuration
    let config = config::load_config(cli.config)?;
    let server_url = cli.server.unwrap_or(config.server_url);

    // Execute command
    match cli.command {
        Commands::Auth { command } => match command {
            AuthCommands::Login { username } => auth::login(&server_url, username).await?,
            AuthCommands::Logout => auth::logout(&server_url).await?,
            AuthCommands::Status => auth::status(&server_url).await?,
        },

        Commands::Vault { command } => match command {
            VaultCommands::Unlock => vault::unlock(&server_url).await?,
            VaultCommands::Lock => vault::lock(&server_url).await?,
            VaultCommands::Status => vault::status(&server_url).await?,
        },

        Commands::Model { command } => match command {
            ModelCommands::List { detailed } => model::list(&server_url, detailed).await?,
            ModelCommands::Load { model, output } => {
                model::load(&server_url, &model, output).await?
            }
            ModelCommands::Store {
                path,
                name,
                version,
                format,
            } => model::store(&server_url, path, name, version, format).await?,
            ModelCommands::Delete { model, force } => {
                model::delete(&server_url, &model, force).await?
            }
            ModelCommands::Info { model } => model::info(&server_url, &model).await?,
        },

        Commands::Init => init_config().await?,
        Commands::Status => show_status(&server_url).await?,
    }

    Ok(())
}

async fn init_config() -> Result<()> {
    println!("{}", "Initializing Uranium configuration...".green().bold());

    use dialoguer::Input;

    let server_url: String = Input::new()
        .with_prompt("Vault server URL")
        .default("http://localhost:8080".to_string())
        .interact()?;

    let username: String = Input::new().with_prompt("Username").interact()?;

    let config = config::CliConfig {
        server_url,
        username: Some(username),
        token: None,
    };

    config::save_config(&config)?;

    println!("{}", "Configuration saved successfully!".green());
    println!("Run 'uranium auth login' to authenticate.");

    Ok(())
}

async fn show_status(server_url: &str) -> Result<()> {
    println!("{}", "Uranium Status".cyan().bold());
    println!("{}", "=============".cyan());

    // Check configuration
    match config::load_config(None) {
        Ok(config) => {
            println!("Config: {}", "✓".green());
            println!("  Server: {}", config.server_url);
            if let Some(username) = config.username {
                println!("  User: {}", username);
            }
        }
        Err(_) => {
            println!("Config: {} (run 'uranium init')", "✗".red());
        }
    }

    // Check authentication
    match config::load_token() {
        Ok(_) => println!("Auth: {}", "✓".green()),
        Err(_) => println!("Auth: {} (run 'uranium auth login')", "✗".red()),
    }

    // Check vault status
    match vault::get_status(server_url).await {
        Ok(status) => {
            println!(
                "Vault: {} ({} models)",
                status.vault_status.green(),
                status.models_count
            );
            if status.secure_enclave_enabled {
                println!("  🔐 Secure Enclave enabled");
            }
        }
        Err(_) => {
            println!("Vault: {} (cannot connect)", "✗".red());
        }
    }

    Ok(())
}
