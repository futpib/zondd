use crate::{
    execution,
    security::{self, Runtime},
};
use anyhow::{Context, Result, ensure};
use libzond::{
    Command, Envelope, Event, MAX_REQUEST_BYTES, Pending, Request, VERSION,
    config::{Config, Decision, Principal, validate_command},
    wire,
};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};

struct Entry {
    request: Pending,
    deadline: Instant,
    decision: oneshot::Sender<Result<(), String>>,
}
struct Active {
    config: Arc<Config>,
    revision: String,
    generation: u64,
    pending: BTreeMap<String, Entry>,
    running: usize,
    connections: usize,
}
struct Reload {
    revision: Option<String>,
    reply: oneshot::Sender<Result<Event>>,
}
struct State {
    active: Mutex<Active>,
    reload: mpsc::Sender<Reload>,
}
struct PendingGuard {
    state: Arc<State>,
    id: String,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.state.active.lock().unwrap().pending.remove(&self.id);
    }
}
struct CapacityGuard {
    state: Arc<State>,
    execution: bool,
}
impl Drop for CapacityGuard {
    fn drop(&mut self) {
        let mut active = self.state.active.lock().unwrap();
        if self.execution {
            active.running -= 1;
        } else {
            active.connections -= 1;
        }
    }
}

type Endpoints = BTreeMap<String, watch::Sender<bool>>;

pub async fn serve(config: Config, config_path: PathBuf, revision: String) -> Result<()> {
    let mut runtime = Runtime::create(&config.runtime_dir)?;
    let admin_socket = runtime.listen(config.runtime_dir.join("admin.sock"))?;
    let (reload_tx, mut reload_rx) = mpsc::channel(16);
    let state = Arc::new(State {
        active: Mutex::new(Active {
            config: Arc::new(config),
            revision,
            generation: 0,
            pending: BTreeMap::new(),
            running: 0,
            connections: 0,
        }),
        reload: reload_tx,
    });
    let mut listeners = JoinSet::new();
    let (_admin_stop, admin_shutdown) = watch::channel(false);
    listeners.spawn(accept(admin_socket, None, state.clone(), admin_shutdown));
    let mut endpoints = Endpoints::new();
    let config = state.active.lock().unwrap().config.clone();
    for name in config.principals.keys() {
        let listener = runtime.listen(config.runtime_dir.join(format!("{name}.sock")))?;
        start_endpoint(
            name.clone(),
            listener,
            &state,
            &mut endpoints,
            &mut listeners,
        );
    }
    tracing::info!(runtime = %config.runtime_dir.display(), "zondd ready");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let outcome = loop {
        tokio::select! {
            r = tokio::signal::ctrl_c() => break r.map_err(anyhow::Error::from),
            _ = terminate.recv() => break Ok(()),
            _ = hangup.recv() => {
                if let Err(error) = reload(&config_path, None, &state, &mut runtime, &mut endpoints, &mut listeners) {
                    tracing::error!(%error, "policy reload rejected; active policy unchanged");
                }
            }
            Some(request) = reload_rx.recv() => {
                let result = reload(&config_path, request.revision.as_deref(), &state, &mut runtime, &mut endpoints, &mut listeners);
                let _ = request.reply.send(result);
            }
            result = listeners.join_next() => {
                // Retired principal listeners finish after their existing clients drain.
                if !matches!(result, Some(Ok(Ok(())))) { break Err(anyhow::anyhow!("listener stopped: {result:?}")); }
            }
        }
    };
    listeners.abort_all();
    while listeners.join_next().await.is_some() {}
    drop(runtime);
    outcome
}

fn start_endpoint(
    name: String,
    listener: UnixListener,
    state: &Arc<State>,
    endpoints: &mut Endpoints,
    listeners: &mut JoinSet<Result<()>>,
) {
    let (stop, shutdown) = watch::channel(false);
    endpoints.insert(name.clone(), stop);
    listeners.spawn(accept(listener, Some(name), state.clone(), shutdown));
}

fn reload(
    path: &Path,
    expected: Option<&str>,
    state: &Arc<State>,
    runtime: &mut Runtime,
    endpoints: &mut Endpoints,
    listeners: &mut JoinSet<Result<()>>,
) -> Result<Event> {
    security::trusted_path(path)?;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(512 * 1024 + 1)
        .read_to_string(&mut text)?;
    ensure!(text.len() <= 512 * 1024, "config exceeds 512 KiB");
    let config = Arc::new(Config::parse(&text)?);
    let revision = libzond::config::revision(&text);
    ensure!(
        expected.is_none_or(|expected| expected == revision),
        "configuration changed; reload the editor before applying"
    );
    {
        let active = state.active.lock().unwrap();
        ensure!(
            config.runtime_dir == active.config.runtime_dir,
            "changing runtime_dir requires a restart"
        );
        if revision == active.revision {
            return Ok(Event::Reloaded {
                revision,
                cancelled_approvals: 0,
            });
        }
    }
    // Prepare every new socket before publishing any of the new policy.
    let mut added = Vec::new();
    for name in config
        .principals
        .keys()
        .filter(|name| !endpoints.contains_key(*name))
    {
        let path = config.runtime_dir.join(format!("{name}.sock"));
        match runtime.add(path.clone()) {
            Ok(listener) => added.push((name.clone(), path, listener)),
            Err(error) => {
                for (_, path, _) in &added {
                    let _ = runtime.remove(path);
                }
                return Err(error)
                    .context("could not create new principal socket; active policy unchanged");
            }
        }
    }
    let cancelled_approvals;
    {
        let mut active = state.active.lock().unwrap();
        active.config = config.clone();
        active.revision = revision.clone();
        active.generation += 1;
        let pending = std::mem::take(&mut active.pending);
        cancelled_approvals = pending.len();
        for (_, entry) in pending {
            let _ = entry
                .decision
                .send(Err("policy reloaded; submit the request again".into()));
        }
    }
    let removed: Vec<_> = endpoints
        .keys()
        .filter(|name| !config.principals.contains_key(*name))
        .cloned()
        .collect();
    for name in removed {
        if let Err(error) = runtime.remove(&config.runtime_dir.join(format!("{name}.sock"))) {
            tracing::warn!(%name, %error, "could not remove retired socket");
        }
        if let Some(stop) = endpoints.remove(&name) {
            let _ = stop.send(true);
        }
    }
    for (name, _, listener) in added {
        start_endpoint(name, listener, state, endpoints, listeners);
    }
    tracing::info!(%revision, cancelled_approvals, "policy reloaded");
    Ok(Event::Reloaded {
        revision,
        cancelled_approvals,
    })
}

async fn accept(
    listener: UnixListener,
    principal: Option<String>,
    state: Arc<State>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut clients = JoinSet::new();
    let admin_permits = Arc::new(Semaphore::new(16));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            connection = listener.accept() => {
                let (socket, _) = connection?;
                if socket.peer_cred()?.uid() != libzond::paths::current_uid() { continue; }
                let mut admin_permit = None;
                let mut caller_permit = None;
                if principal.is_none() {
                    let Ok(permit) = admin_permits.clone().try_acquire_owned() else { continue; };
                    admin_permit = Some(permit);
                } else {
                    let mut active = state.active.lock().unwrap();
                    if active.connections >= active.config.limits.max_connections { continue; }
                    active.connections += 1;
                    caller_permit = Some(CapacityGuard { state: state.clone(), execution: false });
                }
                let state = state.clone();
                let principal = principal.clone();
                clients.spawn(async move {
                    let _permits = (admin_permit, caller_permit);
                    if let Err(error) = handle(socket, principal, state).await { tracing::debug!(%error, "session ended"); }
                });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    drop(listener);
    while clients.join_next().await.is_some() {}
    Ok(())
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
        return admin(&state, request).await;
    };
    let (config, generation) = {
        let active = state.active.lock().unwrap();
        (active.config.clone(), active.generation)
    };
    let Some(p) = config.principals.get(&name) else {
        return Ok(reject("principal is no longer configured"));
    };
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
            let (command, decision) = config.operation(p, &operation, &args)?;
            (command, Some(operation), decision)
        }
        Request::ListOperations => {
            return Ok(Event::Operations {
                operations: config.operations_for(p),
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
            if !config.approvals.enabled {
                return Ok(reject("approval required, but approvals are disabled"));
            }
            if let Err(reason) = approval(
                state.clone(),
                generation,
                &name,
                command.clone(),
                operation,
                id,
                write,
            )
            .await?
            {
                return Ok(reject(&reason));
            }
        }
        Decision::Allow => {}
    }
    run(state, &config, p, generation, &name, &command).await
}

async fn run(
    state: Arc<State>,
    config: &Config,
    p: &Principal,
    generation: u64,
    name: &str,
    command: &Command,
) -> Result<Event> {
    {
        let mut active = state.active.lock().unwrap();
        if generation != active.generation {
            return Ok(reject("policy reloaded; submit the request again"));
        }
        ensure!(
            active.running < active.config.limits.max_running,
            "execution capacity exhausted"
        );
        active.running += 1;
    }
    let _permit = CapacityGuard {
        state,
        execution: true,
    };
    tracing::info!(principal = name, ?command, "execution started");
    let result = execution::execute(command, p, &config.limits).await;
    match &result {
        Ok(Event::Completed { code, signal, .. }) => {
            tracing::info!(principal = name, ?code, ?signal, "execution finished")
        }
        Err(error) => tracing::warn!(principal = name, %error, "execution failed"),
        _ => {}
    }
    result
}

async fn approval(
    state: Arc<State>,
    generation: u64,
    name: &str,
    command: Command,
    operation: Option<String>,
    id: u64,
    write: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<Result<(), String>> {
    let (decision, receive) = oneshot::channel();
    let (request, deadline) = {
        let mut active = state.active.lock().unwrap();
        if generation != active.generation {
            return Ok(Err("policy reloaded; submit the request again".into()));
        }
        ensure!(
            active.pending.len() < active.config.approvals.max_pending,
            "approval queue full"
        );
        let timeout = Duration::from_secs(active.config.approvals.timeout_secs);
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
        active.pending.insert(
            request.approval_id.clone(),
            Entry {
                request: request.clone(),
                deadline,
                decision,
            },
        );
        (request, deadline)
    };
    let _guard = PendingGuard {
        state,
        id: request.approval_id.clone(),
    };
    wire::write(write, &Envelope::new(id, Event::Pending { request })).await?;
    match tokio::time::timeout_at(deadline, receive).await {
        Ok(Ok(decision)) if Instant::now() < deadline => Ok(decision),
        _ => Ok(Err("approval denied or expired".into())),
    }
}

async fn admin(state: &State, request: Request) -> Result<Event> {
    match request {
        Request::Pending => {
            let active = state.active.lock().unwrap();
            Ok(Event::Queue {
                requests: active
                    .pending
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
            let entry = state
                .active
                .lock()
                .unwrap()
                .pending
                .remove(&approval_id)
                .context("approval not pending (unknown, expired, resolved, or disconnected)")?;
            ensure!(entry.deadline > Instant::now(), "approval expired");
            entry
                .decision
                .send(if approve {
                    Ok(())
                } else {
                    Err("approval denied".into())
                })
                .map_err(|_| anyhow::anyhow!("request no longer waiting"))?;
            tracing::info!(%approval_id, principal = %entry.request.principal, approve, "approval resolved");
            Ok(Event::Resolved {
                approval_id,
                approved: approve,
            })
        }
        Request::Status => {
            let active = state.active.lock().unwrap();
            Ok(Event::Status {
                pending: active.pending.len(),
                running: active.running,
                revision: active.revision.clone(),
            })
        }
        Request::Reload { revision } => {
            let (reply, receive) = oneshot::channel();
            state
                .reload
                .send(Reload { revision, reply })
                .await
                .context("daemon shutting down")?;
            receive.await.context("daemon shutting down")?
        }
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
