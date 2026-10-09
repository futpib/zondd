use crate::{
    execution,
    history::{History, now},
    security::Runtime,
};
use anyhow::{Context, Result, ensure};
use libzond::{
    Command, Envelope, Event, MAX_REQUEST_BYTES, Pending, Request, RequestRecord, VERSION,
    config::{Config, Decision, Principal, validate_command},
    wire,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};

#[derive(Clone)]
struct Entry {
    record: RequestRecord,
    request: Pending,
    deadline: Instant,
    decision: Decision,
    approved: bool,
    fresh_review: bool,
    had_pending: bool,
}
struct Active {
    config: Arc<Config>,
    revision: String,
    pending: BTreeMap<String, Entry>,
    running: usize,
    connections: usize,
    history: History,
    stopping: bool,
}
enum Control {
    Reload {
        revision: Option<String>,
        reply: oneshot::Sender<Result<Event>>,
    },
    Retry {
        request_id: String,
        reply: oneshot::Sender<Result<Event>>,
    },
}
struct State {
    active: Mutex<Active>,
    control: mpsc::Sender<Control>,
    changed: watch::Sender<()>,
}
struct RequestGuard {
    state: Arc<State>,
    id: String,
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        let mut active = self.state.active.lock().unwrap();
        active.pending.remove(&self.id);
        if let Ok(mut record) = active.history.get(&self.id)
            && !record.is_terminal()
        {
            record.status = if active.stopping {
                "interrupted"
            } else {
                "cancelled"
            }
            .into();
            record.reason = if active.stopping {
                "daemon stopped"
            } else {
                "caller disconnected"
            }
            .into();
            let reason = record.reason.clone();
            if let Err(error) =
                active
                    .history
                    .record(&mut record, "request_cancelled", json!({"reason":reason}))
            {
                tracing::error!(%error, "could not record cancellation");
            }
        }
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
            self.state.changed.send_replace(());
        } else {
            active.connections -= 1;
        }
    }
}

type Endpoints = BTreeMap<String, watch::Sender<bool>>;

pub async fn serve(config: Config, config_path: PathBuf, revision: String) -> Result<()> {
    let mut runtime = Runtime::create(&config.runtime_dir)?;
    let admin_socket = runtime.listen(config.runtime_dir.join("admin.sock"))?;
    let (control, mut control_rx) = mpsc::channel(16);
    let (changed, _) = watch::channel(());
    let state = Arc::new(State {
        active: Mutex::new(Active {
            config: Arc::new(config),
            revision,
            history: History::open(&config_path)?,
            stopping: false,
            pending: BTreeMap::new(),
            running: 0,
            connections: 0,
        }),
        control,
        changed,
    });
    let mut listeners = JoinSet::new();
    let mut retries = JoinSet::new();
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
                state.active.lock().unwrap().history.audit(None, "reload_requested", json!({"source":"SIGHUP"}))?;
                if let Err(error) = reload(&config_path, None, &state, &mut runtime, &mut endpoints, &mut listeners) {
                    let _ = state.active.lock().unwrap().history.audit(None, "reload_failed", json!({"error":error.to_string()}));
                    tracing::error!(%error, "policy reload rejected; active policy unchanged");
                }
            }
            Some(request) = control_rx.recv() => match request {
                Control::Reload { revision, reply } => {
                    let result = reload(&config_path, revision.as_deref(), &state, &mut runtime, &mut endpoints, &mut listeners);
                    if let Err(error) = &result { let _ = state.active.lock().unwrap().history.audit(None, "reload_failed", json!({"error":error.to_string()})); }
                    let _ = reply.send(result);
                }
                Control::Retry { request_id, reply } => {
                    let record = (|| {
                        let old = state.active.lock().unwrap().history.get(&request_id)?;
                        ensure!(old.is_terminal(), "request is still active");
                        submit(&state, old.principal, old.input, Some(request_id))
                    })();
                    let result = record.map(|record| {
                        let request_id = record.request_id.clone();
                        let state = state.clone();
                        retries.spawn(async move { let _ = execute_request(state, record, 0, &mut tokio::io::sink()).await; });
                        Event::Submitted { request_id }
                    });
                    let _ = reply.send(result);
                }
            },
            _ = retries.join_next(), if !retries.is_empty() => {},
            result = listeners.join_next() => {
                // Retired principal listeners finish after their existing clients drain.
                if !matches!(result, Some(Ok(Ok(())))) { break Err(anyhow::anyhow!("listener stopped: {result:?}")); }
            }
        }
    };
    {
        let mut active = state.active.lock().unwrap();
        active.stopping = true;
        active.history.audit(None, "daemon_stopping", json!({}))?;
    }
    retries.abort_all();
    while retries.join_next().await.is_some() {}
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
    let text = libzond::config::read(path)?;
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
                retained_approvals: 0,
                allowed_approvals: 0,
                refreshed_approvals: 0,
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
    let mut cancelled_approvals = 0;
    let mut retained_approvals = 0;
    let mut allowed_approvals = 0;
    let mut refreshed_approvals = 0;
    {
        let mut active = state.active.lock().unwrap();
        let mut pending = active.pending.clone();
        for entry in pending.values_mut().filter(|e| !e.record.is_terminal()) {
            let old_id = entry.request.approval_id.clone();
            reevaluate(&config, entry);
            if entry.record.is_terminal() {
                cancelled_approvals += 1;
            } else if entry.request.approval_id != old_id {
                refreshed_approvals += 1;
            } else if entry.decision == Decision::Allow {
                allowed_approvals += 1;
            } else {
                retained_approvals += 1;
            }
        }
        let records: Vec<_> = pending.values().map(|e| e.record.clone()).collect();
        if let Err(error) = active.history.reevaluated(&records, &revision) {
            for (_, path, _) in &added {
                let _ = runtime.remove(path);
            }
            return Err(error).context("could not log policy change; active policy unchanged");
        }
        active.config = config.clone();
        active.revision = revision.clone();
        active.pending = pending;
    }
    state.changed.send_replace(());
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
        retained_approvals,
        allowed_approvals,
        refreshed_approvals,
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
                let uid = socket.peer_cred()?.uid();
                if uid != libzond::paths::current_uid() {
                    state.active.lock().unwrap().history.audit(None, "connection_rejected", json!({"uid":uid,"reason":"different Unix user"}))?;
                    continue;
                }
                let mut admin_permit = None;
                let mut caller_permit = None;
                if principal.is_none() {
                    let Ok(permit) = admin_permits.clone().try_acquire_owned() else {
                        state.active.lock().unwrap().history.audit(None, "connection_rejected", json!({"reason":"admin capacity exhausted"}))?;
                        continue;
                    };
                    admin_permit = Some(permit);
                } else {
                    let mut active = state.active.lock().unwrap();
                    if active.connections >= active.config.limits.max_connections {
                        active.history.audit(None, "connection_rejected", json!({"principal":principal,"reason":"caller capacity exhausted"}))?;
                        continue;
                    }
                    active.connections += 1;
                    caller_permit = Some(CapacityGuard { state: state.clone(), execution: false });
                }
                let state = state.clone();
                let principal = principal.clone();
                clients.spawn(async move {
                    let _permits = (admin_permit, caller_permit);
                    if let Err(error) = handle(socket, principal.clone(), state.clone()).await {
                        let _ = state.active.lock().unwrap().history.audit(None, "session_error", json!({"principal":principal,"error":error.to_string()}));
                    }
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

fn evaluate(
    config: &Config,
    name: &str,
    input: &Request,
) -> Result<(Command, Option<String>, Decision)> {
    let p = config
        .principals
        .get(name)
        .context("principal is no longer configured")?;
    match input {
        Request::Run { command } => {
            ensure!(p.allow_exec, "this principal only permits named operations");
            validate_command(command)?;
            Ok((command.clone(), None, p.decision(command)))
        }
        Request::Invoke { operation, args } => {
            let (command, decision) = config.operation(p, operation, args)?;
            Ok((command, Some(operation.clone()), decision))
        }
        _ => anyhow::bail!("not an executable request"),
    }
}

fn reevaluate(config: &Config, entry: &mut Entry) {
    let reject = |entry: &mut Entry, status: &str, reason: String| {
        entry.record.status = status.into();
        entry.record.reason = reason;
        entry.record.updated_unix_ms = now();
    };
    if Instant::now() >= entry.deadline {
        reject(entry, "expired", "approval expired".into());
        return;
    }
    let (command, _, decision) =
        match evaluate(config, &entry.record.principal, &entry.record.input) {
            Ok(value) => value,
            Err(error) => {
                reject(entry, "rejected", format!("policy changed: {error}"));
                return;
            }
        };
    if decision == Decision::Deny {
        reject(entry, "rejected", "command denied by updated policy".into());
        return;
    }
    let cwd = config.principals[&entry.record.principal].cwd.clone();
    if command != entry.request.command || cwd != entry.request.cwd {
        entry.request.command = command.clone();
        entry.request.cwd = cwd.clone();
        entry.request.approval_id = uuid::Uuid::new_v4().to_string();
        entry.record.approval_id = Some(entry.request.approval_id.clone());
        entry.request.reason =
            "Policy changed the command or working directory; review this request again".into();
        entry.approved = false;
        entry.fresh_review = true;
        entry.record.command = Some(command);
        entry.record.cwd = Some(cwd);
    }
    entry.decision = if entry.fresh_review {
        Decision::Ask
    } else {
        decision
    };
    if entry.decision == Decision::Ask && !config.approvals.enabled {
        reject(
            entry,
            "rejected",
            "approval required, but approvals are disabled".into(),
        );
        return;
    }
    entry.had_pending |= entry.decision == Decision::Ask;
    if entry.decision == Decision::Ask && !entry.approved {
        entry.request.reason = if entry.fresh_review {
            "Policy changed the command or working directory; review this request again"
        } else {
            "command not permitted without one-time approval"
        }
        .into();
    }
    entry.record.status = if entry.approved {
        "approved"
    } else if entry.decision == Decision::Allow {
        "allowed"
    } else {
        "pending"
    }
    .into();
    entry.record.reason = if entry.approved {
        "approved once; waiting for execution capacity".into()
    } else if entry.decision == Decision::Allow {
        "allowed by updated policy".into()
    } else {
        entry.request.reason.clone()
    };
    entry.record.updated_unix_ms = now();
}

fn submit(
    state: &State,
    principal: String,
    input: Request,
    retry_of: Option<String>,
) -> Result<RequestRecord> {
    ensure!(
        matches!(input, Request::Run { .. } | Request::Invoke { .. }),
        "not an executable request"
    );
    let mut record = RequestRecord {
        sequence: 0,
        request_id: uuid::Uuid::new_v4().to_string(),
        retry_of,
        approval_id: None,
        principal,
        input,
        command: None,
        cwd: None,
        status: "received".into(),
        authorization: None,
        reason: String::new(),
        created_unix_ms: now(),
        updated_unix_ms: now(),
        result: None,
    };
    let input_detail =
        json!({"input":record.input,"principal":record.principal,"retry_of":record.retry_of});
    state
        .active
        .lock()
        .unwrap()
        .history
        .record(&mut record, "request_received", input_detail)?;
    Ok(record)
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
    if matches!(request, Request::Run { .. } | Request::Invoke { .. }) {
        let record = submit(&state, name, request, None)?;
        return execute_request(state, record, id, write).await;
    }
    let active = state.active.lock().unwrap();
    active.history.audit(
        None,
        "caller_request",
        json!({"principal":name,"request":request}),
    )?;
    let Some(p) = active.config.principals.get(&name) else {
        return Ok(reject("principal is no longer configured"));
    };
    if matches!(request, Request::ListOperations) {
        Ok(Event::Operations {
            operations: active.config.operations_for(p),
        })
    } else {
        Ok(reject(
            "administration is unavailable on principal endpoints",
        ))
    }
}

fn prepare(state: &State, record: &mut RequestRecord) -> Result<Option<Event>> {
    let mut active = state.active.lock().unwrap();
    let config = active.config.clone();
    let (command, operation, decision) = match evaluate(&config, &record.principal, &record.input) {
        Ok(value) => value,
        Err(error) => {
            let reason = error.to_string();
            let unauthorized = !config.principals.contains_key(&record.principal)
                || matches!(&record.input, Request::Run { .. })
                    && !config.principals[&record.principal].allow_exec;
            return Ok(Some(if unauthorized {
                reject(&reason)
            } else {
                Event::Error { message: reason }
            }));
        }
    };
    let cwd = config.principals[&record.principal].cwd.clone();
    record.command = Some(command.clone());
    record.cwd = Some(cwd.clone());
    if decision == Decision::Deny {
        return Ok(Some(reject("command denied by policy")));
    }
    if decision == Decision::Ask {
        if !config.approvals.enabled {
            return Ok(Some(reject(
                "approval required, but approvals are disabled",
            )));
        }
        ensure!(
            active
                .pending
                .values()
                .filter(|e| e.had_pending && !e.record.is_terminal())
                .count()
                < config.approvals.max_pending,
            "approval queue full"
        );
    }
    let timeout = Duration::from_secs(config.approvals.timeout_secs);
    let deadline = Instant::now() + timeout;
    let request = Pending {
        approval_id: uuid::Uuid::new_v4().to_string(),
        principal: record.principal.clone(),
        command,
        operation,
        reason: "command not permitted without one-time approval".into(),
        expires_unix_ms: now() + timeout.as_millis() as u64,
        request_id: record.request_id.clone(),
        cwd,
    };
    record.reason = if decision == Decision::Ask {
        request.reason.clone()
    } else {
        "allowed by policy".into()
    };
    record.approval_id = (decision == Decision::Ask).then(|| request.approval_id.clone());
    record.status = if decision == Decision::Ask {
        "pending"
    } else {
        "allowed"
    }
    .into();
    let detail = json!({"decision":decision,"revision":active.revision,"approval_id":request.approval_id,"command":request.command,"cwd":request.cwd});
    active.history.record(record, "policy_evaluated", detail)?;
    active.pending.insert(
        record.request_id.clone(),
        Entry {
            record: record.clone(),
            request,
            deadline,
            decision,
            approved: false,
            fresh_review: false,
            had_pending: decision == Decision::Ask,
        },
    );
    Ok(None)
}

enum Step {
    Wait(Pending, Instant),
    Execute {
        config: Arc<Config>,
        principal: Principal,
        command: Command,
        permit: CapacityGuard,
    },
    Done(Event),
}

fn advance(state: &Arc<State>, id: &str) -> Result<Step> {
    let mut active = state.active.lock().unwrap();
    let mut entry = active
        .pending
        .remove(id)
        .context("request no longer active")?;
    if entry.record.is_terminal() {
        return Ok(Step::Done(reject(&entry.record.reason)));
    }
    if entry.had_pending && Instant::now() >= entry.deadline {
        entry.record.status = "expired".into();
        entry.record.reason = "approval expired".into();
        active
            .history
            .record(&mut entry.record, "approval_expired", json!({}))?;
        return Ok(Step::Done(reject("approval expired")));
    }
    // Reload, approval and admission all hold this lock. An approval never carries an old policy snapshot.
    if entry.decision == Decision::Allow || entry.approved {
        if active.running < active.config.limits.max_running {
            let config = active.config.clone();
            let principal = config.principals[&entry.record.principal].clone();
            entry.record.status = "running".into();
            entry.record.authorization =
                Some(if entry.approved { "approval" } else { "policy" }.into());
            entry.record.reason = if entry.approved {
                "approved once"
            } else {
                "allowed by policy"
            }
            .into();
            let detail = json!({"revision":active.revision,"authorization":entry.record.reason,"command":entry.request.command,"cwd":entry.request.cwd,"command_timeout_secs":config.limits.command_timeout_secs,"max_output_bytes":config.limits.max_output_bytes});
            active
                .history
                .record(&mut entry.record, "execution_started", detail)?;
            active.running += 1;
            return Ok(Step::Execute {
                config,
                principal,
                command: entry.request.command,
                permit: CapacityGuard {
                    state: state.clone(),
                    execution: true,
                },
            });
        }
        if !entry.had_pending {
            anyhow::bail!("execution capacity exhausted");
        }
        entry.request.reason = "Authorized; waiting for execution capacity".into();
    }
    let step = Step::Wait(entry.request.clone(), entry.deadline);
    active.pending.insert(id.to_owned(), entry);
    Ok(step)
}

async fn execute_request(
    state: Arc<State>,
    mut record: RequestRecord,
    wire_id: u64,
    write: &mut (impl AsyncWrite + Unpin),
) -> Result<Event> {
    let _guard = RequestGuard {
        state: state.clone(),
        id: record.request_id.clone(),
    };
    let mut changed = state.changed.subscribe();
    let result: Result<Event> = async {
        if let Some(event) = prepare(&state, &mut record)? {
            return Ok(event);
        }
        let mut notice = None;
        loop {
            match advance(&state, &record.request_id)? {
                Step::Done(event) => return Ok(event),
                Step::Execute {
                    config,
                    principal,
                    command,
                    permit,
                } => {
                    let _permit = permit;
                    return execution::execute(&command, &principal, &config.limits).await;
                }
                Step::Wait(request, deadline) => {
                    let current = (request.approval_id.clone(), request.reason.clone());
                    if notice.as_ref() != Some(&current) {
                        notice = Some(current);
                        wire::write(write, &Envelope::new(wire_id, Event::Pending { request }))
                            .await?;
                        continue;
                    }
                    let _ = tokio::time::timeout_at(deadline, changed.changed()).await;
                }
            }
        }
    }
    .await;
    let event = result.unwrap_or_else(|error| Event::Error {
        message: format!("{error:#}"),
    });
    let mut active = state.active.lock().unwrap();
    // A refreshed request or admission may have replaced the initial command/context.
    let stored = active.history.get(&record.request_id)?;
    if stored.command.is_some() {
        record = stored;
    }
    match &event {
        Event::Completed { code, signal, .. } => {
            record.status = "completed".into();
            record.reason = code.map_or_else(
                || format!("Terminated by signal {}", signal.unwrap_or_default()),
                |code| format!("Exited with status {code}"),
            );
        }
        Event::Rejected { reason } => {
            if !matches!(record.status.as_str(), "expired" | "denied") {
                record.status = "rejected".into();
            }
            record.reason = reason.clone();
        }
        Event::Error { message } => {
            record.status = "failed".into();
            record.reason = message.clone();
        }
        _ => {}
    }
    record.result = Some(serde_json::to_value(&event)?);
    let detail = json!({"status":record.status,"reason":record.reason});
    active
        .history
        .record(&mut record, "request_finished", detail)?;
    Ok(event)
}

async fn admin(state: &State, request: Request) -> Result<Event> {
    // Audit management intent before performing its side effects. Policy contents are never duplicated here.
    state.active.lock().unwrap().history.audit(
        None,
        "admin_request",
        serde_json::to_value(&request)?,
    )?;
    let result = admin_request(state, request).await;
    if let Err(error) = &result {
        state.active.lock().unwrap().history.audit(
            None,
            "admin_error",
            json!({"error":error.to_string()}),
        )?;
    }
    result
}

async fn admin_request(state: &State, request: Request) -> Result<Event> {
    match request {
        Request::Pending => {
            let active = state.active.lock().unwrap();
            Ok(Event::Queue {
                requests: active
                    .pending
                    .values()
                    .filter(|e| {
                        e.deadline > Instant::now()
                            && !e.record.is_terminal()
                            && e.decision == Decision::Ask
                            && !e.approved
                    })
                    .map(|e| e.request.clone())
                    .collect(),
            })
        }
        Request::Resolve {
            approval_id,
            approve,
        } => {
            let mut active = state.active.lock().unwrap();
            let id = active
                .pending
                .iter()
                .find(|(_, e)| {
                    e.request.approval_id == approval_id
                        && !e.record.is_terminal()
                        && e.decision == Decision::Ask
                        && !e.approved
                })
                .map(|(id, _)| id.clone())
                .context(
                    "approval not pending (unknown, expired, resolved, changed, or disconnected)",
                )?;
            let mut entry = active.pending.remove(&id).unwrap();
            if entry.deadline <= Instant::now() {
                active.pending.insert(id, entry);
                anyhow::bail!("approval expired");
            }
            entry.approved = approve;
            entry.record.status = if approve { "approved" } else { "denied" }.into();
            entry.record.reason = if approve {
                "approved once"
            } else {
                "approval denied"
            }
            .into();
            let result = active.history.record(
                &mut entry.record,
                if approve {
                    "approval_granted"
                } else {
                    "approval_denied"
                },
                json!({"approval_id":approval_id}),
            );
            if let Err(error) = result {
                entry.approved = false;
                entry.record.status = "pending".into();
                active.pending.insert(id, entry);
                return Err(error);
            }
            active.pending.insert(id, entry);
            state.changed.send_replace(());
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
                .control
                .send(Control::Reload { revision, reply })
                .await
                .context("daemon shutting down")?;
            receive.await.context("daemon shutting down")?
        }
        Request::Retry { request_id } => {
            let (reply, receive) = oneshot::channel();
            state
                .control
                .send(Control::Retry { request_id, reply })
                .await
                .context("daemon shutting down")?;
            receive.await.context("daemon shutting down")?
        }
        Request::History { before, limit } => {
            let limit = limit.unwrap_or(30).clamp(1, 100);
            let mut requests = state.active.lock().unwrap().history.list(before, limit)?;
            let full = requests.len() == limit;
            let trimmed = trim_page(&mut requests, serde_json::to_vec)?;
            let next_before = (full || trimmed).then(|| requests.last().unwrap().sequence);
            Ok(Event::History {
                requests,
                next_before,
            })
        }
        Request::RequestDetail { request_id } => {
            let active = state.active.lock().unwrap();
            let mut actions = active.history.actions(Some(&request_id), None, 30)?;
            let full = actions.len() == 30;
            let trimmed = trim_page(&mut actions, serde_json::to_vec)?;
            let next_before = (full || trimmed).then(|| actions.last().unwrap().sequence);
            Ok(Event::RequestDetail {
                request: Box::new(active.history.get(&request_id)?),
                actions,
                next_before,
            })
        }
        Request::Actions {
            request_id,
            before,
            limit,
        } => {
            let limit = limit.unwrap_or(50).clamp(1, 100);
            let mut actions = state.active.lock().unwrap().history.actions(
                request_id.as_deref(),
                before,
                limit,
            )?;
            let full = actions.len() == limit;
            let trimmed = trim_page(&mut actions, serde_json::to_vec)?;
            let next_before = (full || trimmed).then(|| actions.last().unwrap().sequence);
            Ok(Event::Actions {
                actions,
                next_before,
            })
        }
        Request::Audit { action, detail } => {
            ensure!(action.len() <= 128, "action name too long");
            state.active.lock().unwrap().history.audit(
                None,
                &format!("control.{action}"),
                detail,
            )?;
            Ok(Event::Audited)
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

fn trim_page<T>(
    rows: &mut Vec<T>,
    serialize: impl Fn(&T) -> serde_json::Result<Vec<u8>>,
) -> Result<bool> {
    let mut sizes: Vec<_> = rows
        .iter()
        .map(|row| serialize(row).map(|bytes| bytes.len() + 1))
        .collect::<serde_json::Result<_>>()?;
    let mut total: usize = sizes.iter().sum();
    let original = rows.len();
    while rows.len() > 1 && total > 1024 * 1024 {
        rows.pop();
        total -= sizes.pop().unwrap();
    }
    Ok(rows.len() != original)
}
