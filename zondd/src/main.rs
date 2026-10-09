mod execution;
mod history;
mod security;
mod server;

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use libzond::config::{Config, valid_name};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "SSH-authenticated operations daemon and forced-command bridge"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Serve principal sockets and the separate local approval socket as the current user.
    Serve {
        #[arg(long, default_value_os_t = libzond::paths::config_path())]
        config: PathBuf,
    },
    /// Validate policy without running commands or opening sockets.
    Check {
        #[arg(long, default_value_os_t = libzond::paths::config_path())]
        config: PathBuf,
    },
    /// Fixed command for authorized_keys; bridge protocol bytes to a principal socket.
    Bridge {
        #[arg(long, default_value_os_t = libzond::paths::runtime_dir())]
        runtime_dir: PathBuf,
        #[arg(long)]
        principal: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zondd=info".into()),
        )
        .init();
    match Cli::parse().command {
        Action::Serve { config } => {
            let content = libzond::config::read(&config)?;
            server::serve(
                Config::parse(&content)?,
                config,
                libzond::config::revision(&content),
            )
            .await
        }
        Action::Check { config } => {
            Config::parse(&libzond::config::read(&std::path::absolute(config)?)?)?;
            println!("configuration valid");
            Ok(())
        }
        Action::Bridge {
            runtime_dir,
            principal,
        } => {
            let result = bridge(runtime_dir, principal).await;
            if let Err(error) = &result {
                eprintln!("zondd bridge: {error:#}");
            }
            // Tokio's blocking stdin reader cannot be cancelled. The stateless bridge
            // must exit when the socket closes even if SSH stdin remains open.
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
    }
}

async fn bridge(runtime_dir: PathBuf, principal: String) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    ensure!(valid_name(&principal), "invalid principal");
    ensure!(
        std::env::var_os("SSH_ORIGINAL_COMMAND").is_none_or(|s| s.is_empty()),
        "this key accepts the zondd protocol only; omit the SSH command"
    );
    let socket =
        tokio::net::UnixStream::connect(runtime_dir.join(format!("{principal}.sock"))).await?;
    let (mut read, mut write) = socket.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    tokio::select! {
        r = tokio::io::copy(&mut stdin, &mut write) => { r?; }
        r = tokio::io::copy(&mut read, &mut stdout) => { r?; }
    }
    stdout.flush().await?;
    Ok(())
}
