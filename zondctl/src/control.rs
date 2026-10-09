//! Trusted management over local stdin/stdout, also usable through a normal SSH exec.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use libzond::{
    Request,
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
    Resolve { approval_id: String, approve: bool },
    Status {},
    ReadConfig {},
    ValidateConfig { content: String },
    SaveConfig { content: String, revision: String },
    ReloadConfig { revision: String },
    Service { action: ServiceAction },
}

#[derive(Deserialize)]
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
    let mut line = Vec::new();
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
        let mut envelope: serde_json::Map<String, Value> = serde_json::from_slice(&line)?;
        ensure!(
            envelope.remove("version") == Some(json!(1)),
            "unsupported control protocol version"
        );
        let request = serde_json::from_value(Value::Object(envelope))?;
        dispatch(request, runtime, config).await
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
        Control::Resolve {
            approval_id,
            approve,
        } => Request::Resolve {
            approval_id,
            approve,
        },
        Control::Status {} => Request::Status,
        Control::ReloadConfig { revision } => Request::Reload {
            revision: Some(revision),
        },
        Control::ReadConfig {} => return read_config(config),
        Control::ValidateConfig { content } => {
            Config::parse(&content)?;
            return Ok(json!({"valid":true}));
        }
        Control::SaveConfig { content, revision } => {
            return save_config(config, &content, &revision);
        }
        Control::Service { action } => return service(action).await,
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

fn content(path: &Path) -> Result<String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => ensure!(meta.is_file(), "config must be a regular file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e.into()),
    }
    let content = fs::read_to_string(path)?;
    ensure!(content.len() <= 512 * 1024, "config exceeds 512 KiB");
    Ok(content)
}

fn read_config(path: &Path) -> Result<Value> {
    let content = content(path)?;
    Ok(json!({"path":path,"revision":revision(&content),"content":content}))
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
