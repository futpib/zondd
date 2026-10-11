//! Trusted management over local stdin/stdout, also usable through a normal SSH exec.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use libzond::{
    Request, SecretString,
    config::{Config, revision},
};
use libzondctl::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Pending {},
    Rules {},
    ResolveRule {
        proposal_id: String,
        digest: String,
        approve: bool,
        expires_in_secs: Option<u64>,
    },
    RevokeRule {
        grant_id: String,
    },
    Resolve {
        approval_id: String,
        approve: bool,
    },
    Credential {
        challenge_id: String,
        password: Option<SecretString>,
    },
    Status {},
    History {
        before: Option<u64>,
        limit: Option<usize>,
    },
    RequestDetail {
        request_id: String,
    },
    Retry {
        request_id: String,
    },
    Actions {
        request_id: Option<String>,
        before: Option<u64>,
        limit: Option<usize>,
    },
    ReadConfig {},
    ValidateConfig {
        content: String,
    },
    SaveConfig {
        content: String,
        revision: String,
    },
    ReloadConfig {
        revision: String,
    },
    Service {
        action: ServiceAction,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceAction {
    Status,
    Start,
    Stop,
    Restart,
}

/// One bounded request per process. Errors are JSON too; no TTY or root needed.
pub async fn run(runtime: &Path, config: &Path) -> Result<u8> {
    // Read before starting async work: unlike tokio stdin, this leaves no blocked worker
    // behind when an SSH client keeps stdin open after its complete request.
    let mut line = zeroize::Zeroizing::new(Vec::new());
    let read = std::io::stdin()
        .lock()
        .take(1024 * 1024 + 1)
        .read_until(b'\n', &mut line);
    let result = async {
        read?;
        ensure!(line.len() <= 1024 * 1024, "control request exceeds 1 MiB");
        ensure!(
            line.last() == Some(&b'\n'),
            "expected newline-terminated JSON"
        );
        #[derive(Deserialize)]
        struct Envelope {
            version: u32,
            #[serde(flatten)]
            request: Control,
        }
        let envelope: Envelope = serde_json::from_slice(&line)?;
        ensure!(
            envelope.version == 1,
            "unsupported control protocol version"
        );
        dispatch(envelope.request, runtime, config).await
    }
    .await;
    let (response, code) = match result {
        Ok(result) => (json!({"version":1,"ok":true,"result":result}), 0),
        Err(error) => (
            json!({"version":1,"ok":false,"error":format!("{error:#}")}),
            125,
        ),
    };
    println!("{response}");
    Ok(code)
}

async fn dispatch(request: Control, runtime: &Path, config: &Path) -> Result<Value> {
    let request = match request {
        Control::Pending {} => Request::Pending,
        Control::Rules {} => Request::Rules,
        Control::ResolveRule {
            proposal_id,
            digest,
            approve,
            expires_in_secs,
        } => Request::ResolveRule {
            proposal_id,
            digest,
            approve,
            expires_in_secs,
        },
        Control::RevokeRule { grant_id } => Request::RevokeRule { grant_id },
        Control::Resolve {
            approval_id,
            approve,
        } => Request::Resolve {
            approval_id,
            approve,
        },
        Control::Credential {
            challenge_id,
            password,
        } => Request::Credential {
            challenge_id,
            password,
        },
        Control::Status {} => Request::Status,
        Control::History { before, limit } => Request::History { before, limit },
        Control::RequestDetail { request_id } => Request::RequestDetail { request_id },
        Control::Retry { request_id } => Request::Retry { request_id },
        Control::Actions {
            request_id,
            before,
            limit,
        } => Request::Actions {
            request_id,
            before,
            limit,
        },
        Control::ReloadConfig { revision } => Request::Reload {
            revision: Some(revision),
        },
        Control::ReadConfig {} => {
            let result = read_config(config);
            audit_control(runtime, "read_config", &result).await;
            return result;
        }
        Control::ValidateConfig { content } => {
            let result = Config::parse(&content).map(|_| json!({"valid":true}));
            audit_control(runtime, "validate_config", &result).await;
            return result;
        }
        Control::SaveConfig { content, revision } => {
            let result = save_config(config, &content, &revision);
            audit_control(runtime, "save_config", &result).await;
            return result;
        }
        Control::Service { action } => {
            audit_control(
                runtime,
                "service_requested",
                &Ok(json!({"action":format!("{action:?}")})),
            )
            .await;
            let result = service(action).await;
            audit_control(runtime, "service_finished", &result).await;
            return result;
        }
    };
    let event = Client::local(&runtime.join("admin.sock"))
        .await?
        .request(request)
        .await?;
    if let libzond::Event::Error { message } = event {
        bail!("{message}");
    }
    Ok(serde_json::to_value(event)?)
}

async fn audit_control(runtime: &Path, action: &str, result: &Result<Value>) {
    let detail = match result {
        Ok(value) => {
            json!({"ok":true,"revision":value.get("revision"),"action":value.get("action")})
        }
        Err(error) => json!({"ok":false,"error":error.to_string()}),
    };
    // File editing also works while the daemon is stopped; no daemon action exists to log then.
    if let Ok(mut client) = Client::local(&runtime.join("admin.sock")).await {
        match client
            .request(Request::Audit {
                action: action.into(),
                detail,
            })
            .await
        {
            Ok(libzond::Event::Audited) => {}
            Ok(event) => eprintln!("Could not record management action: {event:?}"),
            Err(error) => eprintln!("Could not record management action: {error}"),
        }
    }
}

fn content(path: &Path) -> Result<String> {
    libzond::config::read(&std::path::absolute(path)?)
}

fn read_config(path: &Path) -> Result<Value> {
    let content = content(path)?;
    let displayed = if content.is_empty() {
        libzond::config::default_policy()
    } else {
        content.clone()
    };
    Ok(
        json!({"path":path,"revision":revision(&content),"content":displayed,"defaults":libzond::config::default_policy()}),
    )
}

fn save_config(path: &Path, text: &str, expected: &str) -> Result<Value> {
    ensure!(text.len() <= 512 * 1024, "config exceeds 512 KiB");
    Config::parse(text).context("configuration was not saved")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    // A stable sibling lock serializes saves even as rename replaces the config inode.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path.with_extension("toml.lock"))?;
    lock.lock_exclusive()?;
    ensure!(
        revision(&content(path)?) == expected,
        "configuration changed; reload before saving"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(text.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(json!({"revision":revision(text),"apply_required":true,"restart_required":false}))
}

async fn service(action: ServiceAction) -> Result<Value> {
    let verb = match action {
        ServiceAction::Status => "show",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
    };
    let mut command = tokio::process::Command::new("systemctl");
    command.args(["--user", "--no-pager", verb, "zondd.service"]);
    if matches!(action, ServiceAction::Status) {
        command.args([
            "--property=ActiveState",
            "--property=SubState",
            "--property=LoadState",
        ]);
    }
    // Ordinary SSH logins can lack PAM's user-bus variables.
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        command.env(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", libzond::paths::current_uid()),
        );
    }
    command.kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output()).await??;
    ensure!(
        output.status.success(),
        "systemctl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(json!({"output":String::from_utf8_lossy(&output.stdout)}))
}
