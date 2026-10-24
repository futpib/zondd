mod create_new;
mod execution;
mod history;
mod requirements;
mod rules;
mod security;
mod server;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use libzond::config::{Config, valid_name};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version = libzond::BUILD_VERSION,
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
        #[arg(long, default_value = "default")]
        principal: String,
        /// SSH key bound to this forced command by authorize-key.
        #[arg(long)]
        key_fingerprint: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    if let Some(path) = std::env::args_os().next().map(PathBuf::from)
        && let Some(token) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("askpass-"))
    {
        return askpass(&path, token).await;
    }
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
            key_fingerprint,
        } => {
            let result = bridge(runtime_dir, principal, key_fingerprint).await;
            if let Err(error) = &result {
                eprintln!("zondd bridge: {error:#}");
            }
            // Tokio's blocking stdin reader cannot be cancelled. The stateless bridge
            // must exit when the socket closes even if SSH stdin remains open.
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        }
    }
}

async fn askpass(path: &Path, token: &str) -> Result<()> {
    use anyhow::Context;
    use tokio::io::BufReader;
    let prompt = std::env::args_os()
        .nth(1)
        .map(|prompt| prompt.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sudo password".into());
    let socket = tokio::net::UnixStream::connect(
        path.parent()
            .context("askpass path has no parent")?
            .join("askpass.sock"),
    )
    .await?;
    let (read, mut write) = socket.into_split();
    libzond::wire::write(
        &mut write,
        &libzond::AskpassRequest {
            token: token.into(),
            prompt,
        },
    )
    .await?;
    let response: libzond::AskpassReply = libzond::wire::read(&mut BufReader::new(read), 8192)
        .await?
        .context("no credential response")?;
    let password = response.password.context("credential request denied")?;
    std::io::stdout().write_all(password.0.as_bytes())?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}

async fn bridge(
    runtime_dir: PathBuf,
    principal: String,
    key_fingerprint: Option<String>,
) -> Result<()> {
    use libzond::protocol;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    ensure!(valid_name(&principal), "invalid principal");
    ensure!(
        std::env::var_os("SSH_ORIGINAL_COMMAND").is_none_or(|s| s.is_empty()),
        "this key accepts the zondd protocol only; omit the SSH command"
    );
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let Some(hello) = protocol::read_hello(&mut stdin, &mut stdout, "zondd bridge").await? else {
        return Ok(());
    };
    let upstream = async {
        let socket =
            tokio::net::UnixStream::connect(runtime_dir.join(format!("{principal}.sock"))).await?;
        let (read, mut write) = socket.into_split();
        let mut read = BufReader::new(read);
        let offer = protocol::Hello {
            capabilities: protocol::Negotiated::select(&hello).capabilities,
            ..protocol::Hello::default()
        };
        let selected =
            protocol::negotiate(&mut read, &mut write, &offer, "running zondd daemon").await?;
        anyhow::Ok((read, write, selected))
    }
    .await;
    let (mut read, mut write, selected) = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            protocol::reply(&mut stdout, "zondd bridge", Err(&format!("{error:#}"))).await?;
            return Ok(());
        }
    };
    protocol::reply(&mut stdout, "zondd bridge", Ok(&selected)).await?;
    let mut envelope: libzond::Envelope<libzond::Request> = tokio::time::timeout(
        protocol::TIMEOUT,
        libzond::wire::read(&mut stdin, libzond::MAX_REQUEST_BYTES),
    )
    .await
    .context("request timeout")??
    .context("no request")?;
    selected.validate(&envelope)?;
    // The account-side bridge overwrites caller-supplied transport metadata.
    envelope.transport = Some(libzond::audit::ssh_actor(key_fingerprint.as_deref()));
    if selected.client_info() {
        envelope.extensions.get_or_insert_with(Default::default).via =
            Some(libzond::ClientInfo::current("zondd bridge"));
    }
    libzond::wire::write(&mut write, &envelope).await?;
    let mut extra = [0u8; 1];
    tokio::select! {
        r = stdin.read(&mut extra) => { r?; }
        r = tokio::io::copy(&mut read, &mut stdout) => { r?; }
    }
    stdout.flush().await?;
    Ok(())
}
