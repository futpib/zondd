mod authorize;
mod control;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use libzond::{CheckInput, Command, Event, Request, SecretString};
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
    /// Local caller principal; selects PRINCIPAL.sock without SSH.
    #[arg(long, conflicts_with_all = ["host", "socket"])]
    principal: Option<String>,
    /// Runtime directory for the current user's local approval socket.
    #[arg(long, default_value_os_t = libzond::paths::runtime_dir())]
    runtime_dir: PathBuf,
    /// Print protocol events as JSON instead of command output.
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Preview and confirm a restricted caller key in this account's authorized_keys.
    AuthorizeKey(authorize::Options),
    /// Remove one or all zondd-managed entries from this account's authorized_keys.
    RevokeKey(authorize::RevokeOptions),
    /// Execute an absolute program with argv, subject to policy. No implicit shell.
    Exec {
        /// Run from this directory if an exact directory rule permits it.
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Invoke a named operation with ordered, schema-validated arguments.
    Invoke {
        operation: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Stream retained and live job output until it finishes.
    Follow {
        id: String,
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
    /// Inspect the current or final state of a managed job.
    Job {
        id: String,
    },
    /// Stop a managed job and its process group.
    Cancel {
        id: String,
    },
    /// Submit a reusable rule for admin approval; quote inline source to preserve $variables.
    ProposeRule {
        #[arg(required_unless_present = "file", conflicts_with = "file")]
        source: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Observe your rule definitions and pending, active, denied, expired or revoked state.
    Rules,
    /// Approve the exact reviewed rule for a chosen lifetime (admin only).
    ApproveRule {
        id: String,
        #[arg(long)]
        digest: String,
        #[arg(
            long,
            required_unless_present = "permanent",
            conflicts_with = "permanent"
        )]
        for_secs: Option<u64>,
        #[arg(long)]
        permanent: bool,
    },
    /// Reject the exact reviewed rule proposal (admin only).
    DenyRule {
        id: String,
        #[arg(long)]
        digest: String,
    },
    /// Revoke future invocations of an approved rule (admin only).
    RevokeRule {
        id: String,
    },
    Operations,
    /// Inspect this caller's rules, named operations, approvals, and limits.
    Permissions,
    /// Evaluate a command or operation without executing or requesting approval.
    Check {
        #[command(subcommand)]
        input: CheckAction,
    },
    Pending,
    Approve {
        id: String,
    },
    Deny {
        id: String,
    },
    /// Answer a running operation's sudo password challenge from a terminal.
    Credential {
        id: String,
    },
    /// Reject a running operation's sudo password challenge.
    RejectCredential {
        id: String,
    },
    /// Review pending commands interactively on the local admin socket.
    Review,
    Status,
    /// Apply the daemon's saved configuration without interrupting running commands.
    Reload,
    /// Show recent requests, including completed and rejected requests.
    History {
        #[arg(long)]
        before: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Inspect a request and its action history.
    Request {
        id: String,
    },
    /// Submit a completed request again under current policy.
    Retry {
        id: String,
    },
    /// Show the daemon action log.
    Actions {
        #[arg(long)]
        request_id: Option<String>,
        #[arg(long)]
        before: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Trusted management JSON over stdio; invoke through a normal SSH login.
    Control {
        #[arg(long, default_value_os_t = libzond::paths::config_path())]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum CheckAction {
    Exec {
        /// Check a command in this directory.
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    Invoke {
        operation: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
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
            Client::local(&self.socket.clone().unwrap_or_else(|| {
                self.runtime_dir.join(format!(
                    "{}.sock",
                    self.principal.as_deref().unwrap_or("admin")
                ))
            }))
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
    if let Some(principal) = &cli.principal {
        ensure!(
            libzond::config::valid_name(principal) && principal != "admin",
            "invalid caller principal"
        );
    }
    if let Action::AuthorizeKey(options) = &cli.command {
        ensure!(
            cli.host.is_none() && cli.socket.is_none() && cli.principal.is_none(),
            "authorize-key runs on the receiving host; use a normal SSH login with a terminal"
        );
        return authorize::run(options).await;
    }
    if let Action::RevokeKey(options) = &cli.command {
        ensure!(
            cli.host.is_none() && cli.socket.is_none() && cli.principal.is_none(),
            "revoke-key runs on the receiving host; use a normal SSH login with a terminal"
        );
        return authorize::revoke(options, &cli.runtime_dir).await;
    }
    if let Action::Control { config } = &cli.command {
        ensure!(
            cli.host.is_none() && cli.socket.is_none() && cli.principal.is_none(),
            "control runs locally; invoke it through a normal SSH exec channel"
        );
        return control::run(&cli.runtime_dir, config).await;
    }
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
        Action::Exec { argv, cwd } => Request::Run {
            command: Command {
                program: argv[0].clone(),
                args: argv[1..].to_vec(),
            },
            cwd: cwd.clone(),
        },
        Action::Invoke { operation, args } => Request::Invoke {
            operation: operation.clone(),
            args: args.clone(),
        },
        Action::Follow { id, after } => Request::Follow {
            request_id: id.clone(),
            after: *after,
        },
        Action::Job { id } => Request::Job {
            request_id: id.clone(),
        },
        Action::Cancel { id } => Request::Cancel {
            request_id: id.clone(),
        },
        Action::ProposeRule { source, file } => {
            let source = if let Some(path) = file {
                use std::io::Read;
                let mut text = String::new();
                std::fs::File::open(path)?
                    .take(libzond::rules::MAX_SOURCE_BYTES as u64 + 1)
                    .read_to_string(&mut text)?;
                text
            } else {
                source.clone().context("missing rule source")?
            };
            libzond::rules::parse(&source)?;
            Request::ProposeRule { source }
        }
        Action::Rules => Request::Rules,
        Action::ApproveRule {
            id,
            digest,
            for_secs,
            ..
        } => Request::ResolveRule {
            proposal_id: id.clone(),
            digest: digest.clone(),
            approve: true,
            expires_in_secs: *for_secs,
        },
        Action::DenyRule { id, digest } => Request::ResolveRule {
            proposal_id: id.clone(),
            digest: digest.clone(),
            approve: false,
            expires_in_secs: None,
        },
        Action::RevokeRule { id } => Request::RevokeRule {
            grant_id: id.clone(),
        },
        Action::Operations => Request::ListOperations,
        Action::Permissions => Request::Permissions {},
        Action::Check { input } => Request::Check {
            input: match input {
                CheckAction::Exec { argv, cwd } => CheckInput::Run {
                    command: Command {
                        program: argv[0].clone(),
                        args: argv[1..].to_vec(),
                    },
                    cwd: cwd.clone(),
                },
                CheckAction::Invoke { operation, args } => CheckInput::Invoke {
                    operation: operation.clone(),
                    args: args.clone(),
                },
            },
        },
        Action::Pending => Request::Pending,
        Action::Approve { id } => Request::Resolve {
            approval_id: id.clone(),
            approve: true,
        },
        Action::Deny { id } => Request::Resolve {
            approval_id: id.clone(),
            approve: false,
        },
        Action::Credential { id } => {
            ensure!(
                cli.host.is_none() && cli.principal.is_none(),
                "credential requires the local admin socket"
            );
            ensure!(
                std::io::stdin().is_terminal(),
                "credential requires an interactive terminal"
            );
            Request::Credential {
                challenge_id: id.clone(),
                password: Some(SecretString(rpassword::prompt_password("Sudo password: ")?)),
            }
        }
        Action::RejectCredential { id } => Request::Credential {
            challenge_id: id.clone(),
            password: None,
        },
        Action::Status => Request::Status,
        Action::Reload => Request::Reload { revision: None },
        Action::History { before, limit } => Request::History {
            before: *before,
            limit: *limit,
        },
        Action::Request { id } => Request::RequestDetail {
            request_id: id.clone(),
        },
        Action::Retry { id } => Request::Retry {
            request_id: id.clone(),
        },
        Action::Actions {
            request_id,
            before,
            limit,
        } => Request::Actions {
            request_id: request_id.clone(),
            before: *before,
            limit: *limit,
        },
        Action::Review
        | Action::Control { .. }
        | Action::AuthorizeKey(_)
        | Action::RevokeKey(_) => {
            unreachable!()
        }
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
                        "Request {} (principal {}): {} [approval {}]",
                        request.request_id, request.principal, request.reason, request.approval_id
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
            Event::Output { stderr, data, .. } => {
                if !cli.json {
                    if stderr {
                        std::io::stderr().write_all(&STANDARD.decode(data)?)?;
                        std::io::stderr().flush()?;
                    } else {
                        std::io::stdout().write_all(&STANDARD.decode(data)?)?;
                        std::io::stdout().flush()?;
                    }
                }
            }
            Event::OutputTruncated { next_sequence, .. } => {
                if !cli.json {
                    eprintln!(
                        "Earlier job output was discarded; resuming at chunk {next_sequence}"
                    );
                }
            }
            Event::Submitted { request_id } => {
                if !cli.json {
                    eprintln!(
                        "Command continues in background; use follow, job, or cancel with this ID:"
                    );
                    println!("{request_id}");
                }
                return Ok(0);
            }
            Event::Job { request } => {
                if !cli.json {
                    eprintln!(
                        "Job {}: {} ({})",
                        request.request_id, request.status, request.reason
                    );
                }
                if request.is_terminal() {
                    return Ok(match request.status.as_str() {
                        "completed" => request
                            .result
                            .as_ref()
                            .and_then(|r| r["code"].as_i64())
                            .unwrap_or(128)
                            .clamp(0, 255) as u8,
                        "rejected" | "denied" => 126,
                        _ => 125,
                    });
                }
                return Ok(0);
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
        let Event::Queue {
            requests,
            credentials,
            proposals,
        } = client.request(Request::Pending).await?
        else {
            bail!("expected approval queue");
        };
        if requests.is_empty() && credentials.is_empty() && proposals.is_empty() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        for proposal in proposals {
            println!("{}", serde_json::to_string_pretty(&proposal)?);
            println!(
                "Approving this rule authorizes repeated invocations by {} as this Unix user, without another prompt. Commands retain no_new_privs.",
                proposal.principal
            );
            print!(
                "Approve for 1 hour [a], approve until revoked [p], deny [d], skip [s], quit [q]: "
            );
            std::io::stdout().flush()?;
            let answer = tokio::task::spawn_blocking(|| -> std::io::Result<String> {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                Ok(line)
            })
            .await
            .context("read rule approval answer")??;
            let (approve, expires_in_secs) = match answer.trim() {
                "a" => (true, Some(3600)),
                "p" => (true, None),
                "d" => (false, None),
                "q" | "" => return Ok(0),
                _ => continue,
            };
            let event = cli
                .connect()
                .await?
                .request(Request::ResolveRule {
                    proposal_id: proposal.id,
                    digest: proposal.digest,
                    approve,
                    expires_in_secs,
                })
                .await?;
            println!("{}", serde_json::to_string(&event)?);
        }
        for request in requests {
            // JSON escapes terminal control sequences and makes argv boundaries visible.
            println!("{}", serde_json::to_string_pretty(&request)?);
            if request.sudo_password {
                println!("Approval permits sudo password prompts and privileged child processes.");
            }
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
        for challenge in credentials {
            println!("{}", serde_json::to_string_pretty(&challenge)?);
            print!("Provide sudo password [p], reject [d], skip [s], quit [q]: ");
            std::io::stdout().flush()?;
            let answer = tokio::task::spawn_blocking(|| -> std::io::Result<String> {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                Ok(line)
            })
            .await
            .context("read credential answer")??;
            let password = match answer.trim() {
                "p" => Some(SecretString(rpassword::prompt_password("Sudo password: ")?)),
                "d" => None,
                "q" | "" => return Ok(0),
                _ => continue,
            };
            let event = cli
                .connect()
                .await?
                .request(Request::Credential {
                    challenge_id: challenge.challenge_id,
                    password,
                })
                .await?;
            println!("{}", serde_json::to_string(&event)?);
        }
    }
}
