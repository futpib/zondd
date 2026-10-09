use crate::{execution, security::Runtime};
use anyhow::{Context, Result, bail, ensure};
use libzond::{
    Command, Envelope, Event, MAX_REQUEST_BYTES, Pending, Request, VERSION,
    config::{Config, Decision, Principal, validate_command},
    wire,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, oneshot},
    task::JoinSet,
    time::Instant,
};

struct Entry {
    request: Pending,
    deadline: Instant,
    decision: oneshot::Sender<bool>,
}
struct State {
    config: Config,
    pending: Mutex<BTreeMap<String, Entry>>,
    running: Semaphore,
}
struct PendingGuard {
    state: Arc<State>,
    id: String,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.state.pending.lock().unwrap().remove(&self.id);
    }
}

pub async fn serve(config: Config) -> Result<()> {
    let mut runtime = Runtime::create(&config.runtime_dir)?;
    let mut endpoints = vec![(
        runtime.listen(config.runtime_dir.join("admin.sock"))?,
        None,
        libzond::paths::current_uid(),
    )];
    for name in config.principals.keys() {
        endpoints.push((
            runtime.listen(config.runtime_dir.join(format!("{name}.sock")))?,
            Some(name.clone()),
            libzond::paths::current_uid(),
        ));
    }
    let connections = Arc::new(Semaphore::new(config.limits.max_connections));
    let state = Arc::new(State {
        running: Semaphore::new(config.limits.max_running),
        config,
        pending: Mutex::new(BTreeMap::new()),
    });
    let mut listeners = JoinSet::new();
    for (listener, principal, uid) in endpoints {
        // Waiting remote requests must not consume the capacity needed to approve them.
        let permits = if principal.is_none() {
            Arc::new(Semaphore::new(16))
        } else {
            connections.clone()
        };
        listeners.spawn(accept(listener, principal, uid, state.clone(), permits));
    }
    tracing::info!(runtime = %state.config.runtime_dir.display(), "zondd ready");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let outcome = tokio::select! {
        r = tokio::signal::ctrl_c() => r.map_err(anyhow::Error::from),
        _ = terminate.recv() => Ok(()),
        r = listeners.join_next() => { bail!("listener stopped: {r:?}"); }
    };
    listeners.abort_all();
    while listeners.join_next().await.is_some() {}
    drop(runtime);
    outcome
}

async fn accept(
    listener: UnixListener,
    principal: Option<String>,
    uid: u32,
    state: Arc<State>,
    connections: Arc<Semaphore>,
) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (socket, _) = connection?;
                let peer = socket.peer_cred()?;
                if peer.uid() != uid { continue; }
                let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let principal = principal.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle(socket, principal, state).await { tracing::debug!(%error, "session ended"); }
                });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
}

async fn handle(socket: UnixStream, principal: Option<String>, state: Arc<State>) -> Result<()> {
    let (read, mut write) = socket.into_split();
    let mut read = BufReader::new(read);
    let envelope: Envelope<Request> = tokio::time::timeout(
        Duration::from_secs(10),
        wire::read(&mut read, MAX_REQUEST_BYTES),
    )
    .await
    .context("request timeout")??
    .context("no request")?;
    ensure!(envelope.version == VERSION, "unsupported protocol version");
    let id = envelope.id;
    let result = {
        let task = dispatch(state, principal, envelope.body, id, &mut write);
        tokio::pin!(task);
        let mut extra = [0u8; 1];
        tokio::select! {
            value = &mut task => value,
            _ = read.read(&mut extra) => return Ok(()),
        }
    };
    let mut event = result.unwrap_or_else(|error| Event::Error {
        message: format!("{error:#}"),
    });
    if serde_json::to_vec(&Envelope::new(id, &event))?.len() + 1 > libzond::MAX_RESPONSE_BYTES {
        event = Event::Error {
            message: "response exceeds protocol limit; reduce queue or operation schema size"
                .into(),
        };
    }
    wire::write(&mut write, &Envelope::new(id, event)).await
}

async fn dispatch(
    state: Arc<State>,
    principal: Option<String>,
    request: Request,
    id: u64,
    write: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<Event> {
    let Some(name) = principal else {
        return admin(&state, request);
    };
    let p = state
        .config
        .principals
        .get(&name)
        .context("principal missing")?;
    let (command, operation, decision) = match request {
        Request::Run { command } => {
            if !p.allow_exec {
                return Ok(reject("this principal only permits named operations"));
            }
            validate_command(&command)?;
            let decision = p.decision(&command);
            (command, None, decision)
        }
        Request::Invoke { operation, args } => {
            let (command, decision) = state.config.operation(p, &operation, &args)?;
            (command, Some(operation), decision)
        }
        Request::ListOperations => {
            return Ok(Event::Operations {
                operations: state.config.operations_for(p),
            });
        }
        _ => {
            return Ok(reject(
                "administration is unavailable on principal endpoints",
            ));
        }
    };
    tracing::info!(principal = %name, ?command, ?decision, "request policy");
    match decision {
        Decision::Deny => return Ok(reject("command denied by policy")),
        Decision::Ask => {
            if !state.config.approvals.enabled {
                return Ok(reject("approval required, but approvals are disabled"));
            }
            let approved =
                approval(state.clone(), &name, command.clone(), operation, id, write).await?;
            if !approved {
                return Ok(reject("approval denied or expired"));
            }
        }
        Decision::Allow => {}
    }
    run(&state, p, &name, &command).await
}

async fn run(state: &State, p: &Principal, name: &str, command: &Command) -> Result<Event> {
    let _permit = state
        .running
        .try_acquire()
        .context("execution capacity exhausted")?;
    tracing::info!(principal = name, ?command, "execution started");
    let result = execution::execute(command, p, &state.config.limits).await;
    match &result {
        Ok(Event::Completed { code, signal, .. }) => {
            tracing::info!(principal = name, ?code, ?signal, "execution finished");
        }
        Err(error) => tracing::warn!(principal = name, %error, "execution failed"),
        _ => {}
    }
    result
}

async fn approval(
    state: Arc<State>,
    name: &str,
    command: Command,
    operation: Option<String>,
    id: u64,
    write: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<bool> {
    let timeout = Duration::from_secs(state.config.approvals.timeout_secs);
    let deadline = Instant::now() + timeout;
    let request = Pending {
        approval_id: uuid::Uuid::new_v4().to_string(),
        principal: name.to_owned(),
        command,
        operation,
        reason: "command not permitted without one-time approval".into(),
        expires_unix_ms: (SystemTime::now().duration_since(UNIX_EPOCH)? + timeout).as_millis()
            as u64,
    };
    let (decision, receive) = oneshot::channel();
    {
        let mut queue = state.pending.lock().unwrap();
        ensure!(
            queue.len() < state.config.approvals.max_pending,
            "approval queue full"
        );
        queue.insert(
            request.approval_id.clone(),
            Entry {
                request: request.clone(),
                deadline,
                decision,
            },
        );
    }
    let _guard = PendingGuard {
        state,
        id: request.approval_id.clone(),
    };
    wire::write(write, &Envelope::new(id, Event::Pending { request })).await?;
    Ok(matches!(
        tokio::time::timeout_at(deadline, receive).await,
        Ok(Ok(true))
    ) && Instant::now() < deadline)
}

fn admin(state: &State, request: Request) -> Result<Event> {
    match request {
        Request::Pending => {
            let queue = state.pending.lock().unwrap();
            Ok(Event::Queue {
                requests: queue
                    .values()
                    .filter(|e| e.deadline > Instant::now())
                    .map(|e| e.request.clone())
                    .collect(),
            })
        }
        Request::Resolve {
            approval_id,
            approve,
        } => {
            let entry =
                state.pending.lock().unwrap().remove(&approval_id).context(
                    "approval not pending (unknown, expired, resolved, or disconnected)",
                )?;
            ensure!(entry.deadline > Instant::now(), "approval expired");
            entry
                .decision
                .send(approve)
                .map_err(|_| anyhow::anyhow!("request no longer waiting"))?;
            tracing::info!(%approval_id, principal = %entry.request.principal, approve, "approval resolved");
            Ok(Event::Resolved {
                approval_id,
                approved: approve,
            })
        }
        Request::Status => Ok(Event::Status {
            pending: state.pending.lock().unwrap().len(),
            running: state.config.limits.max_running - state.running.available_permits(),
        }),
        _ => Ok(reject(
            "execution is unavailable on the administration endpoint",
        )),
    }
}

fn reject(reason: &str) -> Event {
    Event::Rejected {
        reason: reason.into(),
    }
}
