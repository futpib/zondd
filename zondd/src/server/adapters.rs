use super::*;
use libzond::interaction::{
    AdapterConfig, AdapterEvent, AdapterRequest, AdapterStatus, Challenge, Recipient,
};
use std::process::Stdio;

pub(super) struct Session {
    pub status: AdapterStatus,
    config: AdapterConfig,
    delivered: Option<String>,
    send: mpsc::Sender<AdapterEvent>,
}
pub(super) struct Waiting {
    pub challenge: Challenge,
    send: mpsc::Sender<AdapterEvent>,
}

struct Guard {
    state: Arc<State>,
    name: String,
    session_id: String,
    pid: u32,
}
impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: the child was placed in its own process group before exec.
        unsafe {
            libc::kill(-(self.pid as i32), libc::SIGKILL);
        }
        let mut active = self.state.active.lock().unwrap();
        let reason = if active.stopping {
            "interrupted"
        } else {
            "disconnected"
        };
        let ids: Vec<_> = active
            .interactions
            .values()
            .filter(|w| w.challenge.recipient.session_id == self.session_id)
            .map(|w| w.challenge.challenge_id.clone())
            .collect();
        for id in ids {
            let _ = finish(&mut active, &id, reason, None);
        }
        if let Some(session) = active.adapters.get_mut(&self.name)
            && session.status.recipient.session_id == self.session_id
        {
            session.status.state = "stopped".into();
            if let Some(id) = session.delivered.take() {
                let _ = active.history.audit(
                    None,
                    "interaction_result",
                    json!({"challenge_id":id,"outcome":"interrupted"}),
                );
            }
        }
        let _ = active.history.audit(
            None,
            "adapter_stopped",
            json!({"adapter":self.name,"session_id":self.session_id}),
        );
        self.state.changed.send_replace(());
    }
}

pub(super) async fn supervise(state: Arc<State>) -> Result<()> {
    let mut changed = state.changed.subscribe();
    let mut tasks = JoinSet::new();
    let mut running: BTreeMap<String, (AdapterConfig, tokio::task::AbortHandle)> = BTreeMap::new();
    loop {
        let config = state.active.lock().unwrap().config.clone();
        let retired: Vec<_> = running
            .iter()
            .filter(|(name, (old, _))| config.credential_adapters.get(*name) != Some(old))
            .map(|(name, _)| name.clone())
            .collect();
        let retiring = retired.len();
        for name in retired {
            running.remove(&name).unwrap().1.abort();
        }
        // Finish old guards before replacing their session and audit state.
        for _ in 0..retiring {
            tasks.join_next().await;
        }
        for (name, adapter) in &config.credential_adapters {
            if running.contains_key(name) {
                continue;
            }
            let (name, adapter, state) = (name.clone(), adapter.clone(), state.clone());
            let entry = (name.clone(), adapter.clone());
            let task = tasks.spawn(async move {
                loop {
                    if run(state.clone(), &name, &adapter).await.is_err() {
                        // Adapter bytes and parser errors can contain sensitive application text.
                        let active = state.active.lock().unwrap();
                        let _ =
                            active
                                .history
                                .audit(None, "adapter_failed", json!({"adapter":name}));
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
            running.insert(entry.0, (entry.1, task));
        }
        tokio::select! {
            _ = changed.changed() => {},
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}

fn recipient(name: &str, config: &AdapterConfig) -> Recipient {
    Recipient {
        adapter: name.into(),
        label: config.label.clone(),
        session_id: uuid::Uuid::new_v4().to_string(),
        command: config.command(),
        cwd: config.cwd.clone(),
        origin: "configured service".into(),
    }
}

async fn run(state: Arc<State>, name: &str, config: &AdapterConfig) -> Result<()> {
    let recipient = recipient(name, config);
    let (outgoing, mut replies) = mpsc::channel(16);
    {
        let mut active = state.active.lock().unwrap();
        active.adapters.insert(
            name.into(),
            Session {
                status: AdapterStatus {
                    recipient: recipient.clone(),
                    state: "starting".into(),
                },
                config: config.clone(),
                delivered: None,
                send: outgoing.clone(),
            },
        );
    }
    let mut command = tokio::process::Command::new(&config.program);
    command
        .args(&config.args)
        .current_dir(&config.cwd)
        .envs(&config.env)
        .env("ZOND_ADAPTER_PROTOCOL", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            state
                .active
                .lock()
                .unwrap()
                .adapters
                .get_mut(name)
                .unwrap()
                .status
                .state = "failed".into();
            state.changed.send_replace(());
            anyhow::bail!("could not start configured adapter");
        }
    };
    let _guard = Guard {
        state: state.clone(),
        name: name.into(),
        session_id: recipient.session_id.clone(),
        pid: child.id().context("adapter has no pid")?,
    };
    {
        let active = state.active.lock().unwrap();
        active
            .history
            .audit(None, "adapter_started", json!({"recipient":recipient}))?;
    }
    state.changed.send_replace(());
    let mut input = child.stdin.take().context("adapter stdin")?;
    let mut output = BufReader::new(child.stdout.take().context("adapter stdout")?);
    wire::write(
        &mut input,
        &AdapterEvent::Ready {
            version: 1,
            session_id: recipient.session_id.clone(),
        },
    )
    .await?;
    let (incoming, mut messages) = mpsc::channel(16);
    let mut reader = JoinSet::new();
    reader.spawn(async move {
        loop {
            let message = wire::read::<AdapterRequest>(&mut output, MAX_REQUEST_BYTES).await;
            let message = match message {
                Ok(Some(message)) => message,
                _ => break,
            };
            if incoming.send(message).await.is_err() {
                break;
            }
        }
    });
    let mut expiry = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            message = messages.recv() => {
                let Some(message) = message else { break; };
                let event = handle(&state, &recipient, message, &outgoing)
                    .unwrap_or_else(|_| AdapterEvent::Error { message:"adapter request rejected".into() });
                wire::write(&mut input, &event).await?;
            },
            Some(event) = replies.recv() => wire::write(&mut input, &event).await?,
            _ = expiry.tick() => {
                let mut active = state.active.lock().unwrap();
                let expired: Vec<_> = active.interactions.values()
                    .filter(|w| w.challenge.recipient.session_id == recipient.session_id && w.challenge.expires_unix_ms <= now())
                    .map(|w| w.challenge.challenge_id.clone()).collect();
                if !expired.is_empty() {
                    for id in expired { finish(&mut active, &id, "expired", None)?; }
                    state.changed.send_replace(());
                }
            },
            _ = child.wait() => break,
        }
    }
    Ok(())
}

fn current<'a>(active: &'a Active, recipient: &Recipient) -> Result<&'a Session> {
    let session = active
        .adapters
        .get(&recipient.adapter)
        .context("adapter stopped")?;
    ensure!(
        session.status.recipient.session_id == recipient.session_id
            && active.config.credential_adapters.get(&recipient.adapter) == Some(&session.config),
        "adapter changed"
    );
    Ok(session)
}

fn handle(
    state: &State,
    recipient: &Recipient,
    request: AdapterRequest,
    send: &mpsc::Sender<AdapterEvent>,
) -> Result<AdapterEvent> {
    let mut active = state.active.lock().unwrap();
    current(&active, recipient)?;
    let event = match request {
        AdapterRequest::Challenge {
            prompt,
            fields,
            context,
            timeout_secs,
        } => {
            ensure!(
                (1..=86400).contains(&timeout_secs),
                "invalid interaction timeout"
            );
            Challenge::validate_fields(&fields, &prompt, &context)?;
            ensure!(
                !active
                    .interactions
                    .values()
                    .any(|w| w.challenge.recipient.adapter == recipient.adapter),
                "interaction already pending"
            );
            ensure!(active.interactions.len() < 16, "interaction queue full");
            ensure!(
                active.adapters[&recipient.adapter].delivered.is_none(),
                "report previous result first"
            );
            let challenge = Challenge {
                challenge_id: uuid::Uuid::new_v4().to_string(),
                recipient: recipient.clone(),
                prompt,
                fields,
                context,
                expires_unix_ms: now() + timeout_secs * 1000,
            };
            let id = challenge.challenge_id.clone();
            active.history.audit(None, "interaction_requested", json!({"challenge_id":id,"recipient":recipient,"field_ids":challenge.fields.iter().map(|f| &f.id).collect::<Vec<_>>(),"expires_unix_ms":challenge.expires_unix_ms}))?;
            active.interactions.insert(
                id.clone(),
                Waiting {
                    challenge,
                    send: send.clone(),
                },
            );
            active
                .adapters
                .get_mut(&recipient.adapter)
                .unwrap()
                .status
                .state = "waiting".into();
            AdapterEvent::Opened { challenge_id: id }
        }
        AdapterRequest::Withdraw { challenge_id } => {
            let waiting = active
                .interactions
                .get(&challenge_id)
                .context("interaction not pending")?;
            ensure!(
                waiting.challenge.recipient.session_id == recipient.session_id,
                "wrong recipient"
            );
            finish(&mut active, &challenge_id, "withdrawn", None)?;
            AdapterEvent::Recorded
        }
        AdapterRequest::Result {
            challenge_id,
            outcome,
        } => {
            ensure!(
                matches!(outcome.as_str(), "succeeded" | "failed" | "cancelled"),
                "invalid outcome"
            );
            ensure!(
                active.adapters[&recipient.adapter].delivered.as_deref() == Some(&challenge_id),
                "unknown delivered interaction"
            );
            active.history.audit(
                None,
                "interaction_result",
                json!({"challenge_id":challenge_id,"outcome":outcome,"adapter":recipient.adapter}),
            )?;
            active
                .adapters
                .get_mut(&recipient.adapter)
                .unwrap()
                .delivered = None;
            AdapterEvent::Recorded
        }
        AdapterRequest::Status { state: status } => {
            ensure!(
                matches!(
                    status.as_str(),
                    "starting" | "waiting" | "working" | "ready" | "unavailable" | "failed"
                ),
                "invalid adapter status"
            );
            if active.adapters[&recipient.adapter].status.state != status {
                active.history.audit(None, "adapter_status", json!({"adapter":recipient.adapter,"session_id":recipient.session_id,"state":status}))?;
                active
                    .adapters
                    .get_mut(&recipient.adapter)
                    .unwrap()
                    .status
                    .state = status;
            }
            AdapterEvent::Recorded
        }
    };
    state.changed.send_replace(());
    Ok(event)
}

fn finish(
    active: &mut Active,
    id: &str,
    status: &str,
    values: Option<BTreeMap<String, SecretString>>,
) -> Result<()> {
    let pending = active
        .interactions
        .get(id)
        .context("interaction not pending")?;
    active.history.audit(
        None,
        "interaction_ended",
        json!({"challenge_id":id,"adapter":pending.challenge.recipient.adapter,"status":status}),
    )?;
    let pending = active.interactions.remove(id).unwrap();
    let recipient = &pending.challenge.recipient;
    if let Some(session) = active.adapters.get_mut(&recipient.adapter)
        && session.status.recipient.session_id == recipient.session_id
    {
        session.status.state = if values.is_some() {
            "working"
        } else {
            "unavailable"
        }
        .into();
        if values.is_some() {
            session.delivered = Some(id.into());
        }
    }
    let _ = pending.send.try_send(AdapterEvent::Answered {
        challenge_id: id.into(),
        status: status.into(),
        values,
    });
    Ok(())
}

pub(super) fn answer(
    state: &State,
    id: String,
    values: Option<BTreeMap<String, SecretString>>,
) -> Result<Event> {
    let mut active = state.active.lock().unwrap();
    let pending = active
        .interactions
        .get(&id)
        .context("interaction not pending")?;
    current(&active, &pending.challenge.recipient)?;
    ensure!(
        pending.challenge.expires_unix_ms > now(),
        "interaction expired"
    );
    ensure!(!pending.send.is_closed(), "adapter disconnected");
    // All senders hold this same state lock; capacity cannot decrease here.
    ensure!(
        pending.send.capacity() > 0,
        "adapter is not ready for a response"
    );
    if let Some(values) = &values {
        pending.challenge.validate_answer(values)?;
    }
    finish(
        &mut active,
        &id,
        if values.is_some() {
            "answered"
        } else {
            "rejected"
        },
        values,
    )?;
    state.changed.send_replace(());
    Ok(Event::CredentialAnswered { challenge_id: id })
}

pub(super) fn retry(state: &State, name: String) -> Result<Event> {
    let active = state.active.lock().unwrap();
    let session = active.adapters.get(&name).context("adapter not running")?;
    current(&active, &session.status.recipient)?;
    ensure!(
        matches!(session.status.state.as_str(), "unavailable" | "failed"),
        "adapter is not waiting for retry"
    );
    ensure!(
        !active
            .interactions
            .values()
            .any(|w| w.challenge.recipient.adapter == name)
            && session.delivered.is_none(),
        "interaction still active"
    );
    active.history.audit(
        None,
        "adapter_retry",
        json!({"adapter":name,"session_id":session.status.recipient.session_id}),
    )?;
    session
        .send
        .try_send(AdapterEvent::Retry)
        .map_err(|_| anyhow::anyhow!("adapter unavailable"))?;
    Ok(Event::AdapterRetried { adapter: name })
}
