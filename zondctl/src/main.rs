mod authorize;
mod connections;
mod control;
mod credential_adapter;

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
    /// Saved connection name, user@server, or an ssh_config alias.
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
    /// Suppress receiver and lifecycle notices; command stderr and errors remain visible.
    #[arg(long)]
    quiet: bool,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Run a legacy credential adapter as part of an independently owned service.
    CredentialAdapter(credential_adapter::Options),
    /// List saved receivers, or add/remove a named OpenSSH connection on this machine.
    Connections {
        #[command(subcommand)]
        action: Option<connections::Action>,
    },
    /// Show the selected receiver, transport, identities and role without connecting.
    Context,
    /// Preview and confirm a restricted caller key in this account's authorized_keys.
    AuthorizeKey(authorize::Options),
    /// Remove one or all zondd-managed entries from this account's authorized_keys.
    RevokeKey(authorize::RevokeOptions),
    /// Execute an absolute program with argv, subject to policy. No implicit shell.
    Exec {
        /// Run from this directory if an exact directory rule permits it.
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Return the job ID when the command backgrounds instead of following it.
        #[arg(long)]
        detach: bool,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Invoke a named operation with ordered, schema-validated arguments.
    Invoke {
        /// Return the job ID when the command backgrounds instead of following it.
        #[arg(long)]
        detach: bool,
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
    Job { id: String },
    /// Stop a managed job and its process group.
    Cancel { id: String },
    /// Withdraw your request or rule proposal by ID, preserving its audit history.
    Withdraw { id: String },
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
    RevokeRule { id: String },
    /// List named operations available to this caller.
    Operations,
    /// Inspect this caller's rules, named operations, approvals, and limits.
    Permissions,
    /// Evaluate a command or operation without executing or requesting approval.
    Check {
        #[command(subcommand)]
        input: CheckAction,
    },
    /// List requests awaiting review (admin only).
    Pending,
    /// Approve one pending command (admin only).
    Approve { id: String },
    /// Deny one pending command (admin only).
    Deny { id: String },
    /// Answer a running operation's sudo password challenge from a terminal (admin only).
    Credential { id: String },
    /// Reject a running operation's sudo password challenge (admin only).
    RejectCredential { id: String },
    /// Answer an application's input form privately, or decline it (admin only).
    Interaction {
        id: String,
        #[arg(long)]
        reject: bool,
    },
    /// Review pending commands interactively on the local admin socket (admin only).
    Review,
    /// Show receiver-wide daemon state (admin only; callers can use permissions).
    Status,
    /// Apply the daemon's saved configuration without interrupting running commands (admin only).
    Reload,
    /// Show recent requests, including completed and rejected requests (admin only).
    History {
        #[arg(long)]
        before: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
        /// Search request summaries before pagination (literal, case-insensitive text).
        #[arg(long)]
        query: Option<String>,
    },
    /// Inspect your own request and its action history; admins can inspect any request.
    Request { id: String },
    /// Submit a completed request again under current policy (admin only).
    Retry { id: String },
    /// Show the daemon action log (admin only).
    Actions {
        #[arg(long)]
        request_id: Option<String>,
        #[arg(long)]
        before: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
        /// Search action names and details before pagination.
        #[arg(long)]
        query: Option<String>,
    },
    /// Trusted management JSON over stdio; invoke through a normal SSH login.
    Control {
        #[arg(long, default_value_os_t = libzond::paths::config_path())]
        config: PathBuf,
    },
    /// Verify an Android audit export locally, optionally against an independent checkpoint.
    VerifyAudit {
        file: PathBuf,
        /// A checkpoint JSON object, saved phone checkpoint, or an earlier audit export.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
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
    fn ssh_options(&self) -> Result<Option<SshOptions>> {
        self.host
            .as_ref()
            .map(|host| {
                Ok(SshOptions {
                    host: host.clone(),
                    identity: self.identity.clone(),
                    port: self.port,
                    config: match &self.ssh_config {
                        Some(path) => Some(path.clone()),
                        None => connections::saved(host)?,
                    },
                    iroh: self.iroh,
                })
            })
            .transpose()
    }

    fn local_socket(&self) -> PathBuf {
        self.socket.clone().unwrap_or_else(|| {
            self.runtime_dir.join(format!(
                "{}.sock",
                self.principal.as_deref().unwrap_or("admin")
            ))
        })
    }

    fn receiver(&self) -> String {
        match &self.host {
            Some(host) => format!("{host} (remote caller)"),
            None => format!("local socket {}", self.local_socket().display()),
        }
    }

    fn inspect_command(&self, id: &str) -> String {
        let mut args = vec!["zondctl".to_owned()];
        if let Some(host) = &self.host {
            args.extend(["--host".into(), host.clone()]);
            if self.iroh {
                args.push("--iroh".into());
            }
            if let Some(path) = &self.identity {
                args.extend(["--identity".into(), path.display().to_string()]);
            }
            if let Some(port) = self.port {
                args.extend(["--port".into(), port.to_string()]);
            }
            if let Some(path) = &self.ssh_config {
                args.extend(["--ssh-config".into(), path.display().to_string()]);
            }
        } else {
            args.extend(["--socket".into(), self.local_socket().display().to_string()]);
        }
        args.extend(["job".into(), id.into()]);
        args.iter()
            .map(|s| connections::quote(s))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn notices(&self) -> bool {
        !self.json && !self.quiet
    }

    async fn connect(&self) -> Result<Client> {
        if let Some(options) = self.ssh_options()? {
            Client::ssh(&options)
        } else {
            Client::local(&self.local_socket()).await.with_context(|| format!(
                "cannot connect to {}; for a remote receiver use --host NAME; list saved receivers with `zondctl connections`, or inspect the selection with `zondctl context`", self.receiver()
            ))
        }
    }

    async fn context(&self) -> Result<()> {
        if let Some(options) = self.ssh_options()? {
            let info = connections::describe(&options).await?;
            if self.json {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!(
                    "Receiver: {}\nDestination: {}\nPort: {}\nTransport: {}\nRole: {}",
                    info.receiver, info.destination, info.port, info.transport, info.role
                );
                println!("Identities: {}", info.identities.join(", "));
                if let Some(path) = info.ssh_config {
                    println!("SSH config: {}", path.display());
                }
                if let Some(proxy) = info.proxy {
                    println!("Proxy: {proxy}");
                }
                println!(
                    "No connection made. Use permissions to verify the authenticated caller and policy."
                );
            }
        } else {
            let role = if self.principal.is_some() {
                "caller"
            } else if self.socket.is_some() {
                "selected by socket"
            } else {
                "admin"
            };
            if self.json {
                println!(
                    "{}",
                    serde_json::json!({"receiver":"local", "transport":"Unix socket", "role":role, "socket":self.local_socket(), "principal":self.principal})
                );
            } else {
                println!(
                    "Receiver: local\nSocket: {}\nTransport: Unix socket\nRole: {role}",
                    self.local_socket().display()
                );
                println!(
                    "For a remote receiver, use --host NAME. List saved receivers with `zondctl connections`."
                );
            }
        }
        Ok(())
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
    if let Action::VerifyAudit { file, checkpoint } = &cli.command {
        let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(file)?)?;
        let anchor = checkpoint
            .as_ref()
            .map(|path| -> Result<libzond::audit::Checkpoint> {
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
                Ok(serde_json::from_value(
                    value.get("checkpoint").unwrap_or(&value).clone(),
                )?)
            })
            .transpose()?;
        let result = libzond::audit::verify_export(&bundle, anchor.as_ref())?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(0);
    }
    if let Action::CredentialAdapter(options) = &cli.command {
        ensure!(
            cli.host.is_none() && cli.socket.is_none() && cli.principal.is_none(),
            "credential adapter requires local recipient authentication"
        );
        return credential_adapter::run(&cli.runtime_dir, options).await;
    }
    if let Action::Connections { action } = &cli.command {
        match action {
            Some(connections::Action::Add { name }) => {
                let options = SshOptions {
                    host: cli.host.clone().context("connections add requires --host RECEIVER; optionally supply --identity, --port and --iroh before connections")?,
                    identity: cli.identity.clone(), port: cli.port, config: cli.ssh_config.clone(), iroh: cli.iroh,
                };
                let path = connections::add(name, &options)?;
                if cli.json {
                    println!("{}", serde_json::json!({"name":name,"ssh_config":path}));
                } else {
                    println!(
                        "Saved {name}: {}\nInspect: zondctl --host {name} context\nConnect: zondctl --host {name} permissions\nRun: zondctl --host {name} exec /usr/bin/uptime",
                        path.display()
                    );
                }
            }
            Some(connections::Action::Remove { name }) => {
                connections::remove(name)?;
                if cli.json {
                    println!("{}", serde_json::json!({"removed":name}));
                } else {
                    println!("Removed connection {name}. Receiver key authorization is unchanged.");
                }
            }
            None => {
                let mut entries = Vec::new();
                for name in connections::names()? {
                    entries.push(
                        connections::describe(&SshOptions {
                            config: connections::saved(&name)?,
                            host: name,
                            identity: None,
                            port: None,
                            iroh: false,
                        })
                        .await?,
                    );
                }
                if cli.json {
                    println!("{}", serde_json::to_string(&entries)?);
                } else if entries.is_empty() {
                    println!(
                        "No saved connections. Save a receiver with:\n  zondctl --host USER@HOST --identity KEY connections add NAME\nAdd --iroh before connections for an Iroh endpoint ID."
                    );
                } else {
                    println!("#  NAME  DESTINATION  TRANSPORT  ROLE");
                    for (i, entry) in entries.iter().enumerate() {
                        println!(
                            "{}  {}  {}  {}  caller",
                            i + 1,
                            entry.receiver,
                            entry.destination,
                            entry.transport
                        );
                    }
                }
            }
        }
        return Ok(0);
    }
    if matches!(cli.command, Action::Context) {
        cli.context().await?;
        return Ok(0);
    }
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
        Action::Exec { argv, cwd, .. } => Request::Run {
            command: Command {
                program: argv[0].clone(),
                args: argv[1..].to_vec(),
            },
            cwd: cwd.clone(),
        },
        Action::Invoke {
            operation, args, ..
        } => Request::Invoke {
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
        Action::Withdraw { id } => Request::Withdraw { id: id.clone() },
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
        Action::Interaction { id, reject } => {
            ensure!(
                cli.host.is_none() && cli.principal.is_none(),
                "interaction requires the local admin socket"
            );
            let values = if *reject {
                None
            } else {
                ensure!(
                    std::io::stdin().is_terminal(),
                    "interaction requires an interactive terminal"
                );
                let Event::Queue { interactions, .. } =
                    cli.connect().await?.request(Request::Pending).await?
                else {
                    bail!("expected interaction queue")
                };
                let challenge = interactions
                    .into_iter()
                    .find(|c| c.challenge_id == *id)
                    .context("interaction not pending")?;
                Some(read_interaction(&challenge)?)
            };
            Request::AnswerInteraction {
                challenge_id: id.clone(),
                values,
            }
        }
        Action::Status => Request::Status,
        Action::Reload => Request::Reload { revision: None },
        Action::History {
            before,
            limit,
            query,
        } => Request::History {
            before: *before,
            limit: *limit,
            query: query.clone(),
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
            query,
        } => Request::Actions {
            request_id: request_id.clone(),
            before: *before,
            limit: *limit,
            query: query.clone(),
            subject_id: None,
            include_reads: true,
        },
        Action::CredentialAdapter(..)
        | Action::Connections { .. }
        | Action::Context
        | Action::Review
        | Action::Control { .. }
        | Action::VerifyAudit { .. }
        | Action::AuthorizeKey(_)
        | Action::RevokeKey(_) => {
            unreachable!()
        }
    };
    let auto_follow = matches!(
        cli.command,
        Action::Exec { detach: false, .. } | Action::Invoke { detach: false, .. }
    );
    let mut following = None;
    if cli.notices()
        && matches!(
            cli.command,
            Action::Exec { .. } | Action::Invoke { .. } | Action::Follow { .. }
        )
    {
        eprintln!("Receiver: {}", cli.receiver());
    }
    let mut client = cli.connect().await?;
    client.send(request).await?;
    loop {
        let event = tokio::select! {
            r = client.next() => match &following {
                Some(id) => r.with_context(|| format!("following job {id}; resume with follow {id}"))?,
                None => r?,
            },
            _ = tokio::signal::ctrl_c() => return Ok(130),
        };
        if cli.json {
            println!("{}", serde_json::to_string(&event)?);
        }
        match event {
            Event::Pending { request } => {
                if cli.notices() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis() as u64;
                    let seconds = request.expires_unix_ms.saturating_sub(now).div_ceil(1000);
                    eprintln!(
                        "Request: {} (principal {})\nWaiting for approval in Zond. Expires in {seconds} seconds.\nApproval: {}\nReason: {}\nInspect: {}",
                        request.request_id,
                        request.principal,
                        request.approval_id,
                        request.reason,
                        cli.inspect_command(&request.request_id)
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
                if cli.notices() {
                    if let Some(signal) = signal {
                        eprintln!("Completed: signal {signal}.");
                    } else {
                        eprintln!("Completed: exit {}.", code.unwrap_or(128));
                    }
                }
                return Ok(code
                    .unwrap_or_else(|| 128 + signal.unwrap_or(0))
                    .clamp(0, 255) as u8);
            }
            Event::Rejected { reason } => {
                if !cli.json {
                    eprintln!("Rejected: {reason}");
                    if reason.contains("administration is unavailable") {
                        if let Action::Request { id } = &cli.command {
                            eprintln!(
                                "This receiver requires admin access for request history. Inspect your own request with: {}",
                                cli.inspect_command(id)
                            );
                        } else {
                            eprintln!(
                                "This is a caller connection. Use permissions to inspect its policy; administrative commands require the receiver's local admin socket or the Zond controller."
                            );
                        }
                    }
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
                if auto_follow {
                    if cli.notices() {
                        eprintln!(
                            "Following job {request_id}; Ctrl-C stops following, cancel stops the job"
                        );
                    }
                    following = Some(request_id.clone());
                    drop(client);
                    let connect = async {
                        let mut next = cli.connect().await?;
                        next.send(Request::Follow {
                            request_id: request_id.clone(),
                            after: 0,
                        })
                        .await?;
                        Ok::<_, anyhow::Error>(next)
                    };
                    client = tokio::select! {
                        result = connect => result.with_context(|| format!(
                            "following job {request_id}; resume with follow {request_id}"
                        ))?,
                        _ = tokio::signal::ctrl_c() => return Ok(130),
                    };
                    continue;
                }
                if !cli.json {
                    if cli.notices() {
                        eprintln!(
                            "Command continues in background; use follow, job, or cancel with this ID:"
                        );
                    }
                    println!("{request_id}");
                }
                return Ok(0);
            }
            Event::Job { request } => {
                if !cli.json && (cli.notices() || matches!(cli.command, Action::Job { .. })) {
                    eprintln!(
                        "Job {}: {} ({})",
                        request.request_id, request.status, request.reason
                    );
                }
                if request.is_terminal() {
                    if cli.notices()
                        && let Some(result) = &request.result
                    {
                        if let Some(code) = result.get("code").and_then(|v| v.as_i64()) {
                            eprintln!("Completed: exit {code}.");
                        } else if let Some(signal) = result.get("signal").and_then(|v| v.as_i64()) {
                            eprintln!("Completed: signal {signal}.");
                        }
                    }
                    return Ok(match request.status.as_str() {
                        "completed" => request
                            .result
                            .as_ref()
                            .and_then(|r| {
                                r["code"].as_i64().or_else(|| {
                                    r["signal"]
                                        .as_i64()
                                        .map(|signal| signal.saturating_add(128))
                                })
                            })
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
            interactions,
            ..
        } = client.request(Request::Pending).await?
        else {
            bail!("expected approval queue");
        };
        if requests.is_empty()
            && credentials.is_empty()
            && proposals.is_empty()
            && interactions.is_empty()
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        for proposal in proposals {
            println!("{}", serde_json::to_string_pretty(&proposal)?);
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
        for challenge in interactions {
            println!("{}", serde_json::to_string_pretty(&challenge.recipient)?);
            print!("Answer application form [a], reject [d], skip [s], quit [q]: ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let values = match line.trim() {
                "a" => Some(read_interaction(&challenge)?),
                "d" => None,
                "q" | "" => return Ok(0),
                _ => continue,
            };
            let event = cli
                .connect()
                .await?
                .request(Request::AnswerInteraction {
                    challenge_id: challenge.challenge_id,
                    values,
                })
                .await?;
            println!("{}", serde_json::to_string(&event)?);
        }
    }
}

fn read_interaction(
    challenge: &libzond::interaction::Challenge,
) -> Result<std::collections::BTreeMap<String, SecretString>> {
    println!(
        "Configured recipient: {}",
        serde_json::to_string_pretty(&challenge.recipient)?
    );
    println!(
        "Permitted provider origin: {}",
        challenge.provider_origin.escape_default()
    );
    println!(
        "Application-supplied form: {}",
        serde_json::to_string_pretty(
            &serde_json::json!({"prompt":challenge.prompt,"fields":challenge.fields,"context":challenge.context})
        )?
    );
    let mut values = std::collections::BTreeMap::new();
    for field in &challenge.fields {
        let prompt = format!("{} (input hidden): ", field.label.escape_default());
        values.insert(
            field.id.clone(),
            SecretString(rpassword::prompt_password(prompt)?),
        );
    }
    challenge.validate_answer(&values)?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detach_option_does_not_consume_command_arguments() {
        let cli = Cli::try_parse_from(["zondctl", "exec", "printf", "%s", "--detach"]).unwrap();
        let Action::Exec { detach, argv, .. } = cli.command else {
            panic!("expected exec")
        };
        assert!(!detach);
        assert_eq!(argv, ["printf", "%s", "--detach"]);

        let cli = Cli::try_parse_from(["zondctl", "invoke", "greet", "--", "--detach"]).unwrap();
        let Action::Invoke { detach, args, .. } = cli.command else {
            panic!("expected invoke")
        };
        assert!(!detach);
        assert_eq!(args, ["--detach"]);
    }
}
