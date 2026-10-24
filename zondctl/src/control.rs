//! Trusted management over local stdin/stdout, also usable through a normal SSH exec.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use libzond::{
    Request, SecretString,
    config::{Config, revision},
};
use libzondctl::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

#[derive(Deserialize, Serialize)]
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
    AnswerInteraction {
        challenge_id: String,
        values: Option<std::collections::BTreeMap<String, SecretString>>,
    },
    Status {},
    History {
        before: Option<u64>,
        limit: Option<usize>,
        query: Option<String>,
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
        query: Option<String>,
        #[serde(default)]
        subject_id: Option<String>,
        #[serde(default = "include_reads")]
        include_reads: bool,
    },
    AuditSnapshot {},
    AuditPage {
        after: u64,
        through: u64,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ServiceAction {
    Status,
    Start,
    Stop,
    Restart,
}

fn include_reads() -> bool {
    true
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
            #[serde(default)]
            actor: Option<libzond::audit::ActorProof>,
            #[serde(default)]
            client: Option<libzond::ClientInfo>,
            #[serde(flatten)]
            request: Control,
        }
        let envelope: Envelope = serde_json::from_slice(&line)
            .map_err(|_| anyhow::anyhow!("invalid control request"))?;
        ensure!(
            envelope.version == 1,
            "unsupported control protocol version"
        );
        dispatch(
            envelope.request,
            runtime,
            config,
            envelope.actor,
            envelope.client,
        )
        .await
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

async fn dispatch(
    request: Control,
    runtime: &Path,
    config: &Path,
    proof: Option<libzond::audit::ActorProof>,
    client_info: Option<libzond::ClientInfo>,
) -> Result<Value> {
    let transport = libzond::audit::ssh_actor(None);
    let identify = |client: Client| {
        client.with_client_info(
            client_info.clone(),
            Some(libzond::ClientInfo::current("zondctl control")),
        )
    };
    let request = match request {
        Control::AnswerInteraction {
            challenge_id,
            values,
        } => Request::AnswerInteraction {
            challenge_id,
            values,
        },
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
        Control::History {
            before,
            limit,
            query,
        } => Request::History {
            before,
            limit,
            query,
        },
        Control::RequestDetail { request_id } => Request::RequestDetail { request_id },
        Control::Retry { request_id } => Request::Retry { request_id },
        Control::Actions {
            request_id,
            before,
            limit,
            query,
            subject_id,
            include_reads,
        } => Request::Actions {
            request_id,
            before,
            limit,
            query,
            subject_id,
            include_reads,
        },
        Control::AuditSnapshot {} => {
            if let Ok(client) = Client::local(&runtime.join("admin.sock")).await {
                return Ok(serde_json::to_value(
                    identify(client).request(Request::AuditSnapshot).await?,
                )?);
            }
            let history = libzond::history::History::open(config)?;
            return Ok(
                json!({"type":"audit_snapshot","checkpoint":history.checkpoint()?,"legacy_through_sequence":history.legacy_through_sequence()?,"chain_version":libzond::audit::VERSION,"daemon_online":false}),
            );
        }
        Control::AuditPage {
            after,
            through,
            limit,
        } => {
            if let Ok(client) = Client::local(&runtime.join("admin.sock")).await {
                return Ok(serde_json::to_value(
                    identify(client)
                        .request(Request::AuditPage {
                            after,
                            through,
                            limit,
                        })
                        .await?,
                )?);
            }
            let history = libzond::history::History::open(config)?;
            let mut actions =
                history.audit_page(after, through, limit.unwrap_or(100).clamp(1, 100))?;
            while serde_json::to_vec(&actions)?.len() + 1024 > libzond::MAX_RESPONSE_BYTES {
                ensure!(
                    actions.len() > 1,
                    "audit event exceeds protocol response limit"
                );
                actions.pop();
            }
            let last = actions.last().map_or(after, |v| v.sequence);
            ensure!(
                last == through || !actions.is_empty(),
                "audit snapshot is missing events"
            );
            return Ok(
                json!({"type":"audit_page","actions":actions,"next_after":(last < through).then_some(last),"through":through}),
            );
        }
        Control::ReloadConfig { revision } => Request::Reload {
            revision: Some(revision),
        },
        Control::ReadConfig {} => {
            let history = libzond::history::History::open(config)?;
            let result = read_config(config);
            audit_control(
                &history,
                "read_config",
                &result,
                json!({"transport":transport,"unix_uid":libzond::paths::current_uid(),"peer_pid":std::process::id(),"device_key_evidence":"not_provided"}),
            )?;
            return result;
        }
        Control::ValidateConfig { content } => {
            let history = libzond::history::History::open(config)?;
            let result = Config::parse(&content).map(|_| json!({"valid":true}));
            audit_control(
                &history,
                "validate_config",
                &result,
                json!({"transport":transport,"unix_uid":libzond::paths::current_uid(),"peer_pid":std::process::id(),"device_key_evidence":"not_provided"}),
            )?;
            return result;
        }
        Control::SaveConfig { content, revision } => {
            let history = libzond::history::History::open(config)?;
            let metadata = json!({"method":"save_config","revision":revision,"new_revision":libzond::config::revision(&content)});
            let actor = history.actor(
                proof.as_ref(),
                &transport,
                &metadata,
                None,
                Some(std::process::id()),
            )?;
            let before = read_config(config)?["content"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let changed_paths = changed_paths(&before, &content)?;
            history.audit(None, "control.save_config_requested", json!({"revision":revision,"new_revision":metadata["new_revision"],"changed_paths":changed_paths,"actor":actor}))?;
            let result = save_config(config, &content, &revision);
            audit_control(&history, "save_config", &result, actor)?;
            return result;
        }
        Control::Service { action } => {
            let history = libzond::history::History::open(config)?;
            let metadata = serde_json::to_value(Control::Service {
                action: action.clone(),
            })?;
            let actor = history.actor(
                proof.as_ref(),
                &transport,
                &metadata,
                None,
                Some(std::process::id()),
            )?;
            let name = if matches!(action, ServiceAction::Status) {
                "service_status"
            } else {
                "service_requested"
            };
            audit_control(
                &history,
                name,
                &Ok(json!({"action":format!("{action:?}")})),
                actor.clone(),
            )?;
            let result = service(action).await;
            audit_control(
                &history,
                if name == "service_status" {
                    "service_status"
                } else {
                    "service_finished"
                },
                &result,
                actor,
            )?;
            return result;
        }
    };
    let event = identify(Client::local(&runtime.join("admin.sock")).await?)
        .request_as(request, proof, Some(transport))
        .await?;
    if let libzond::Event::Error { message } = event {
        bail!("{message}");
    }
    Ok(serde_json::to_value(event)?)
}

fn audit_control(
    history: &libzond::history::History,
    action: &str,
    result: &Result<Value>,
    actor: Value,
) -> Result<()> {
    let detail = match result {
        Ok(value) => {
            json!({"ok":true,"revision":value.get("revision"),"action":value.get("action"),"actor":actor})
        }
        // TOML diagnostics can quote configuration values. Keep the outcome,
        // while returning the full diagnostic only to the management caller.
        Err(_) => json!({"ok":false,"error_kind":"operation_failed","actor":actor}),
    };
    history.audit(None, &format!("control.{action}"), detail)
}

fn changed_paths(before: &str, after: &str) -> Result<Vec<String>> {
    fn walk(path: &str, before: &Value, after: &Value, changes: &mut Vec<String>) {
        if before == after {
            return;
        }
        if let (Some(before), Some(after)) = (before.as_object(), after.as_object()) {
            let keys: std::collections::BTreeSet<_> = before.keys().chain(after.keys()).collect();
            for key in keys {
                walk(
                    &if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    },
                    before.get(key).unwrap_or(&Value::Null),
                    after.get(key).unwrap_or(&Value::Null),
                    changes,
                );
            }
        } else {
            changes.push(if path.is_empty() {
                "configuration".into()
            } else {
                path.to_owned()
            });
        }
    }
    let parse = |text: &str| -> Value {
        match libzond::config::Config::parse(text) {
            Ok(config) => {
                json!({"principals":config.principals,"operations":config.operations,"credential_recipients":config.credential_recipients,"runtime_dir":config.runtime_dir,"approvals":config.approvals,"limits":config.limits})
            }
            Err(_) => Value::Null,
        }
    };
    // Principal/operation/recipient values are intentionally absent from audit.
    // Whole-file revisions bind the exact edit; changed sections aid review.
    let mut changes = Vec::new();
    walk("", &parse(before), &parse(after), &mut changes);
    if libzond::config::revision(before) != libzond::config::revision(after) && changes.is_empty() {
        changes.push("configuration".into());
    }
    Ok(changes)
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
