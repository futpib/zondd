//! Service-side migration bridge for the v1 adapter pipes. Systemd owns this
//! wrapper and its child; the daemon never starts or retries either process.

use anyhow::{Context, Result, ensure};
use clap::Args;
use libzond::{
    credential::{Event, Request},
    interaction::{AdapterEvent, AdapterRequest},
    wire,
};
use libzondctl::credential::{Client, read_key};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{io::BufReader, task::JoinSet};

#[derive(Args)]
pub struct Options {
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub key_file: PathBuf,
    /// Registered provider origin for every form emitted by the legacy adapter.
    #[arg(long)]
    pub origin: String,
    #[arg(required = true, trailing_var_arg = true)]
    pub argv: Vec<String>,
}

struct ChildGuard(u32);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // SAFETY: the child is launched in its own process group below.
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}

pub async fn run(runtime: &Path, options: &Options) -> Result<u8> {
    let mut broker: Option<Client> = None;
    let mut pending_challenge: Option<String> = None;
    let mut child = tokio::process::Command::new(&options.argv[0])
        .args(&options.argv[1..])
        .env("ZOND_ADAPTER_PROTOCOL", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let _guard = ChildGuard(child.id().context("adapter has no pid")?);
    let mut input = child.stdin.take().context("adapter stdin")?;
    wire::write(
        &mut input,
        &AdapterEvent::Ready {
            version: 1,
            session_id: format!("service-pipes-{}", std::process::id()),
        },
    )
    .await?;
    let mut output = BufReader::new(child.stdout.take().context("adapter stdout")?);
    let (send, mut messages) = tokio::sync::mpsc::channel(8);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        while let Ok(Some(request)) = wire::read(&mut output, libzond::MAX_REQUEST_BYTES).await {
            if send.send(request).await.is_err() {
                break;
            }
        }
    });
    loop {
        tokio::select! {
            message = messages.recv() => {
                let Some(message) = message else { return Ok(0); };
                let request = match message {
                    AdapterRequest::Challenge { prompt, fields, context, timeout_secs } => Request::Challenge {
                        origin: options.origin.clone(), prompt, fields, context, timeout_secs,
                    },
                    AdapterRequest::Withdraw { challenge_id } => Request::Withdraw { challenge_id },
                    AdapterRequest::Result { challenge_id, outcome } => Request::Result { challenge_id, outcome },
                    // Application availability stays with the application. Old adapters
                    // can still publish status locally without putting it in zondd.
                    AdapterRequest::Status { .. } => {
                        wire::write(&mut input, &AdapterEvent::Recorded).await?;
                        continue;
                    },
                };
                if broker.is_none() && matches!(request, Request::Challenge { .. }) {
                    broker = match read_key(&options.key_file) {
                        Ok(key) => Client::connect(&runtime.join("credential.sock"), &options.recipient, key).await.ok(),
                        Err(_) => None,
                    };
                }
                let sent = match broker.as_mut() {
                    Some(client) => client.send(request).await.is_ok(),
                    None => false,
                };
                if !sent {
                    broker = None;
                    wire::write(&mut input, &AdapterEvent::Error { message: "credential broker unavailable".into() }).await?;
                }
            },
            event = async {
                match broker.as_mut() {
                    Some(client) => client.receive().await,
                    None => std::future::pending().await,
                }
            } => {
                let event = match event {
                    Ok(event) => event,
                    Err(_) => {
                        broker = None;
                        if let Some(challenge_id) = pending_challenge.take() {
                            wire::write(&mut input, &AdapterEvent::Answered { challenge_id, status: "interrupted".into(), values: None }).await?;
                        }
                        continue;
                    },
                };
                let reply = match event.body {
                    Event::Opened { challenge_id } => {
                        pending_challenge = Some(challenge_id.clone());
                        AdapterEvent::Opened { challenge_id }
                    },
                    Event::Answered { challenge_id, status, values } => {
                        pending_challenge = None;
                        AdapterEvent::Answered { challenge_id, status, values }
                    },
                    Event::Recorded { .. } => AdapterEvent::Recorded,
                    Event::Error { .. } => AdapterEvent::Error { message: "credential request rejected".into() },
                    Event::Ready { .. } => anyhow::bail!("unexpected credential handshake"),
                };
                tokio::time::timeout(std::time::Duration::from_secs(5), wire::write(&mut input, &reply)).await??;
            },
            result = child.wait() => {
                let status = result?;
                ensure!(status.success(), "credential adapter exited unsuccessfully");
                return Ok(0);
            },
        }
    }
}
