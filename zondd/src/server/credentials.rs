use super::*;
use libzond::{
    credential::{self, Event as Reply, RecipientConfig, Request as Message},
    interaction::{Challenge, Recipient, RecipientStatus},
};

pub(super) struct Session {
    pub status: RecipientStatus,
    config: RecipientConfig,
    delivered: Option<String>,
    revoked: watch::Sender<bool>,
}

pub(super) struct Waiting {
    pub challenge: Challenge,
    request_id: u64,
    send: mpsc::Sender<Envelope<Reply>>,
}

struct Guard {
    state: Arc<State>,
    recipient: Recipient,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut active = self.state.active.lock().unwrap();
        close(&mut active, &self.recipient, "disconnected");
        self.state.changed.send_replace(());
    }
}

fn close(active: &mut Active, recipient: &Recipient, reason: &str) {
    let reason = if active.stopping {
        "interrupted"
    } else {
        reason
    };
    let ids: Vec<_> = active
        .interactions
        .values()
        .filter(|w| w.challenge.recipient.session_id == recipient.session_id)
        .map(|w| w.challenge.challenge_id.clone())
        .collect();
    for id in ids {
        if finish(active, &id, reason, None).is_err() {
            // Revocation must discard pending input even if its audit write fails.
            active.interactions.remove(&id);
        }
    }
    if active
        .recipients
        .get(&recipient.name)
        .is_some_and(|s| s.status.recipient.session_id == recipient.session_id)
    {
        let session = active.recipients.remove(&recipient.name).unwrap();
        session.revoked.send_replace(true);
        if let Some(id) = session.delivered {
            let _ = active.history.audit(
                None,
                "interaction_result",
                json!({"challenge_id":id,"outcome":"interrupted"}),
            );
        }
        let _ = active.history.audit(
            None,
            "credential_session_closed",
            json!({"recipient":recipient.name,"session_id":recipient.session_id,"reason":reason}),
        );
    }
}

pub(super) fn invalidate(active: &mut Active) {
    let retired: Vec<_> = active
        .recipients
        .values()
        .filter(|s| {
            active
                .config
                .credential_recipients
                .get(&s.status.recipient.name)
                != Some(&s.config)
        })
        .map(|s| s.status.recipient.clone())
        .collect();
    for recipient in retired {
        close(active, &recipient, "recipient_changed");
    }
}

fn current<'a>(active: &'a Active, recipient: &Recipient) -> Result<&'a Session> {
    let session = active
        .recipients
        .get(&recipient.name)
        .context("credential session closed")?;
    ensure!(
        session.status.recipient.session_id == recipient.session_id
            && active.config.credential_recipients.get(&recipient.name) == Some(&session.config)
            && !*session.revoked.borrow()
            && !active.stopping,
        "credential recipient changed"
    );
    Ok(session)
}

pub(super) async fn accept(listener: UnixListener, state: Arc<State>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(32));
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (socket, _) = connection?;
                let peer = socket.peer_cred()?;
                if peer.uid() != libzond::paths::current_uid() { continue; }
                let Some(pid) = peer.pid().and_then(|p| u32::try_from(p).ok()) else { continue; };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    // Never log frames, authentication keys, answers, or parser errors.
                    let _ = run(socket, state, peer.uid(), pid).await;
                });
            },
            _ = clients.join_next(), if !clients.is_empty() => {},
        }
    }
}

async fn write(writer: &mut (impl AsyncWrite + Unpin), id: u64, reply: Reply) -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(5),
        wire::write(writer, &Envelope::new(id, reply)),
    )
    .await??;
    Ok(())
}

async fn run(socket: UnixStream, state: Arc<State>, uid: u32, pid: u32) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let first: Envelope<Message> = tokio::time::timeout(
        Duration::from_secs(10),
        wire::read(&mut reader, credential::MAX_REQUEST_BYTES),
    )
    .await??
    .context("empty credential session")?;
    if first.version != credential::VERSION {
        return write(&mut writer, first.id, Reply::error("unsupported_version")).await;
    }
    let Message::Authenticate {
        recipient: name,
        key,
    } = first.body
    else {
        return write(&mut writer, first.id, Reply::error("authentication_failed")).await;
    };
    let (revoked, mut revocation) = watch::channel(false);
    let authenticated = {
        let mut active = state.active.lock().unwrap();
        active
            .config
            .credential_recipients
            .get(&name)
            .cloned()
            .and_then(|config| {
                let digest = libzond::config::revision(&key.0);
                let difference = digest
                    .bytes()
                    .zip(config.key_sha256.bytes())
                    .fold(0u8, |d, (a, b)| d | (a ^ b));
                if first.id == 0 || !credential::valid_key(&key.0) || difference != 0 {
                    return None;
                }
                if active.recipients.contains_key(&name) {
                    return Some(Err("busy"));
                }
                let recipient = Recipient {
                    name: name.clone(),
                    label: config.label.clone(),
                    session_id: uuid::Uuid::new_v4().to_string(),
                    peer_uid: uid,
                    peer_pid: pid,
                    configuration_revision: active.revision.clone(),
                    identity: "private connection key and Unix peer credentials".into(),
                    origin: "configured service".into(),
                };
                if active
                    .history
                    .audit(
                        None,
                        "credential_session_opened",
                        json!({"recipient":recipient}),
                    )
                    .is_err()
                {
                    return Some(Err("unavailable"));
                }
                active.recipients.insert(
                    name.clone(),
                    Session {
                        config,
                        delivered: None,
                        revoked,
                        status: RecipientStatus {
                            recipient: recipient.clone(),
                            state: "idle".into(),
                        },
                    },
                );
                Some(Ok(recipient))
            })
            .unwrap_or(Err("authentication_failed"))
    };
    drop(key);
    let recipient = match authenticated {
        Ok(recipient) => recipient,
        Err(code) => return write(&mut writer, first.id, Reply::error(code)).await,
    };
    let _guard = Guard {
        state: state.clone(),
        recipient: recipient.clone(),
    };
    state.changed.send_replace(());
    write(
        &mut writer,
        first.id,
        Reply::Ready {
            session_id: recipient.session_id.clone(),
        },
    )
    .await?;
    let (incoming, mut messages) = mpsc::channel(8);
    let (alive, mut connected) = watch::channel(true);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        while let Ok(Some(message)) =
            wire::read::<Envelope<Message>>(&mut reader, credential::MAX_REQUEST_BYTES).await
        {
            if incoming.send(message).await.is_err() {
                break;
            }
        }
        alive.send_replace(false);
    });
    let (send, mut replies) = mpsc::channel(8);
    let mut last_id = first.id;
    let mut expiry = tokio::time::interval(Duration::from_millis(100));
    loop {
        let reply = tokio::select! {
            _ = connected.changed() => break,
            _ = revocation.changed() => break,
            message = messages.recv() => {
                let Some(message) = message else { break; };
                if message.version != credential::VERSION || message.id <= last_id {
                    write(&mut writer, message.id, Reply::error("invalid_frame")).await?;
                    break;
                }
                last_id = message.id;
                let reply = handle(&state, &recipient, message.id, message.body, &send);
                Some(Envelope::new(message.id, reply))
            },
            reply = replies.recv() => reply,
            _ = expiry.tick() => {
                let mut active = state.active.lock().unwrap();
                let expired: Vec<_> = active.interactions.values()
                    .filter(|w| w.challenge.recipient.session_id == recipient.session_id && w.challenge.expires_unix_ms <= now())
                    .map(|w| w.challenge.challenge_id.clone()).collect();
                for id in expired { finish(&mut active, &id, "expired", None)?; state.changed.send_replace(()); }
                None
            },
        };
        if let Some(reply) = reply {
            current(&state.active.lock().unwrap(), &recipient)?;
            tokio::select! {
                biased;
                _ = connected.changed() => break,
                _ = revocation.changed() => break,
                result = write(&mut writer, reply.id, reply.body) => result?,
            }
        }
    }
    Ok(())
}

fn handle(
    state: &State,
    recipient: &Recipient,
    id: u64,
    message: Message,
    send: &mpsc::Sender<Envelope<Reply>>,
) -> Reply {
    let mut active = state.active.lock().unwrap();
    let result = (|| -> std::result::Result<Reply, &'static str> {
        let session = current(&active, recipient).map_err(|_| "session_closed")?;
        match message {
            Message::Authenticate { .. } => Err("already_authenticated"),
            Message::Challenge {
                origin,
                prompt,
                fields,
                context,
                timeout_secs,
            } => {
                if !session.config.origins.contains(&origin) {
                    return Err("origin_not_allowed");
                }
                if fields
                    .iter()
                    .any(|f| !session.config.field_ids.contains(&f.id))
                {
                    return Err("field_not_allowed");
                }
                if !(1..=86400).contains(&timeout_secs)
                    || Challenge::validate_fields(&fields, &prompt, &context).is_err()
                {
                    return Err("invalid_challenge");
                }
                if session.delivered.is_some() {
                    return Err("result_required");
                }
                if active
                    .interactions
                    .values()
                    .any(|w| w.challenge.recipient.session_id == recipient.session_id)
                {
                    return Err("busy");
                }
                if active.interactions.len() >= 16 {
                    return Err("queue_full");
                }
                let challenge = Challenge {
                    challenge_id: uuid::Uuid::new_v4().to_string(),
                    recipient: recipient.clone(),
                    provider_origin: origin,
                    prompt,
                    fields,
                    context,
                    expires_unix_ms: now() + timeout_secs * 1000,
                };
                let challenge_id = challenge.challenge_id.clone();
                active.history.audit(None, "interaction_requested", json!({"challenge_id":challenge_id,"recipient":recipient,"provider_origin":challenge.provider_origin,"field_ids":challenge.fields.iter().map(|f| &f.id).collect::<Vec<_>>(),"expires_unix_ms":challenge.expires_unix_ms})).map_err(|_| "unavailable")?;
                active.interactions.insert(
                    challenge_id.clone(),
                    Waiting {
                        challenge,
                        request_id: id,
                        send: send.clone(),
                    },
                );
                active
                    .recipients
                    .get_mut(&recipient.name)
                    .unwrap()
                    .status
                    .state = "waiting".into();
                Ok(Reply::Opened { challenge_id })
            }
            Message::Withdraw { challenge_id } => {
                if let Some(pending) = active.interactions.get(&challenge_id)
                    && pending.challenge.recipient.session_id == recipient.session_id
                {
                    finish(&mut active, &challenge_id, "withdrawn", None)
                        .map_err(|_| "unavailable")?;
                } else if session.delivered.as_deref() == Some(&challenge_id) {
                    // Values may already be in transit. Preserve the outcome obligation.
                    return Err("answer_delivered");
                } else {
                    return Err("unknown_challenge");
                }
                Ok(Reply::Recorded { challenge_id })
            }
            Message::Result {
                challenge_id,
                outcome,
            } => {
                if !matches!(outcome.as_str(), "succeeded" | "failed" | "cancelled") {
                    return Err("invalid_outcome");
                }
                if session.delivered.as_deref() != Some(&challenge_id) {
                    return Err("unknown_challenge");
                }
                active.history.audit(None, "interaction_result", json!({"challenge_id":challenge_id,"outcome":outcome,"recipient":recipient.name})).map_err(|_| "unavailable")?;
                let session = active.recipients.get_mut(&recipient.name).unwrap();
                session.delivered = None;
                session.status.state = "idle".into();
                Ok(Reply::Recorded { challenge_id })
            }
        }
    })();
    state.changed.send_replace(());
    result.unwrap_or_else(Reply::error)
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
        json!({"challenge_id":id,"recipient":pending.challenge.recipient.name,"status":status}),
    )?;
    let pending = active.interactions.remove(id).unwrap();
    let recipient = &pending.challenge.recipient;
    if let Some(session) = active.recipients.get_mut(&recipient.name)
        && session.status.recipient.session_id == recipient.session_id
    {
        session.status.state = if values.is_some() {
            "answer_delivered"
        } else {
            "idle"
        }
        .into();
        if values.is_some() {
            session.delivered = Some(id.into());
        }
    }
    if pending
        .send
        .try_send(Envelope::new(
            pending.request_id,
            Reply::Answered {
                challenge_id: id.into(),
                status: status.into(),
                values,
            },
        ))
        .is_err()
    {
        if let Some(session) = active.recipients.get(&recipient.name) {
            session.revoked.send_replace(true);
        }
        anyhow::bail!("credential session unavailable");
    }
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
    ensure!(
        !pending.send.is_closed() && pending.send.capacity() > 0,
        "credential session unavailable"
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
