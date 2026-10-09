use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use libzond::{Command, Event, Request};
use libzondctl::{Client, SshOptions};
use std::{
    io::{IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

#[derive(Parser)]
#[command(
    version,
    about = "Run SSH-authenticated operations and review zondd approvals"
)]
struct Cli {
    /// SSH destination, such as automation@server or an ssh_config alias.
    #[arg(long, conflicts_with = "socket")]
    host: Option<String>,
    /// Use iroh-ssh as OpenSSH's ProxyCommand (host must contain the endpoint ID).
    #[arg(long, requires = "host")]
    iroh: bool,
    #[arg(long, requires = "host")]
    identity: Option<PathBuf>,
    #[arg(long, requires = "host")]
    port: Option<u16>,
    #[arg(long, requires = "host")]
    ssh_config: Option<PathBuf>,
    /// Local principal socket for execution, or admin socket for approvals.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Print protocol events as JSON instead of command output.
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Execute an absolute program with argv, subject to policy. No implicit shell.
    Exec {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Invoke a named operation with ordered, schema-validated arguments.
    Invoke {
        operation: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Operations,
    Pending,
    Approve {
        id: String,
    },
    Deny {
        id: String,
    },
    /// Review pending commands interactively on the local admin socket.
    Review,
    Status,
}

impl Cli {
    async fn connect(&self) -> Result<Client> {
        if let Some(host) = &self.host {
            Client::ssh(&SshOptions {
                host: host.clone(),
                identity: self.identity.clone(),
                port: self.port,
                config: self.ssh_config.clone(),
                iroh: self.iroh,
            })
        } else {
            Client::local(
                &self
                    .socket
                    .clone()
                    .unwrap_or_else(|| "/run/zondd/admin.sock".into()),
            )
            .await
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("zondctl: {error:#}");
            ExitCode::from(125)
        }
    }
}

async fn run(cli: Cli) -> Result<u8> {
    if matches!(cli.command, Action::Review) {
        ensure!(cli.host.is_none(), "review requires the local admin socket");
        ensure!(
            std::io::stdin().is_terminal(),
            "review requires an interactive terminal; use pending/approve/deny for scripting"
        );
        return tokio::select! {
            result = review(&cli) => result,
            // Keep one signal subscription alive across queue reads and resolutions.
            // Exiting also stops the otherwise uncancellable blocking terminal read.
            _ = tokio::signal::ctrl_c() => std::process::exit(130),
        };
    }
    let request = match &cli.command {
        Action::Exec { argv } => Request::Run {
            command: Command {
                program: argv[0].clone(),
                args: argv[1..].to_vec(),
            },
        },
        Action::Invoke { operation, args } => Request::Invoke {
            operation: operation.clone(),
            args: args.clone(),
        },
        Action::Operations => Request::ListOperations,
        Action::Pending => Request::Pending,
        Action::Approve { id } => Request::Resolve {
            approval_id: id.clone(),
            approve: true,
        },
        Action::Deny { id } => Request::Resolve {
            approval_id: id.clone(),
            approve: false,
        },
        Action::Status => Request::Status,
        Action::Review => unreachable!(),
    };
    let mut client = cli.connect().await?;
    client.send(request).await?;
    loop {
        let event = tokio::select! {
            r = client.next() => r?,
            _ = tokio::signal::ctrl_c() => return Ok(130),
        };
        if cli.json {
            println!("{}", serde_json::to_string(&event)?);
        }
        match event {
            Event::Pending { request } => {
                if !cli.json {
                    eprintln!(
                        "Pending approval {} (principal {})",
                        request.approval_id, request.principal
                    );
                }
            }
            Event::Completed {
                code,
                signal,
                stdout,
                stderr,
            } => {
                if !cli.json {
                    std::io::stdout().write_all(&STANDARD.decode(stdout)?)?;
                    std::io::stderr().write_all(&STANDARD.decode(stderr)?)?;
                }
                return Ok(code
                    .unwrap_or_else(|| 128 + signal.unwrap_or(0))
                    .clamp(0, 255) as u8);
            }
            Event::Rejected { reason } => {
                if !cli.json {
                    eprintln!("Rejected: {reason}");
                }
                return Ok(126);
            }
            Event::Error { message } => {
                if !cli.json {
                    eprintln!("Error: {message}");
                }
                return Ok(125);
            }
            other => {
                if !cli.json {
                    println!("{}", serde_json::to_string_pretty(&other)?);
                }
                return Ok(0);
            }
        }
    }
}

async fn review(cli: &Cli) -> Result<u8> {
    loop {
        let mut client = cli.connect().await?;
        let Event::Queue { requests } = client.request(Request::Pending).await? else {
            bail!("expected approval queue");
        };
        if requests.is_empty() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        for request in requests {
            // JSON escapes terminal control sequences and makes argv boundaries visible.
            println!("{}", serde_json::to_string_pretty(&request)?);
            print!("Approve once [a], deny [d], skip [s], quit [q]: ");
            std::io::stdout().flush()?;
            let input = tokio::task::spawn_blocking(|| -> std::io::Result<String> {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                Ok(line)
            });
            let answer = input.await.context("read approval answer")??;
            let approve = match answer.trim() {
                "a" => true,
                "d" => false,
                "q" | "" => return Ok(0),
                _ => continue,
            };
            let event = cli
                .connect()
                .await?
                .request(Request::Resolve {
                    approval_id: request.approval_id,
                    approve,
                })
                .await?;
            println!("{}", serde_json::to_string(&event)?);
        }
    }
}
