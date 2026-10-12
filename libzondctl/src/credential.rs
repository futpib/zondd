//! Reference client for independently running applications. Dropping the client
//! closes its session and cancels pending input; reconnect never replays values.

use anyhow::{Context, Result, ensure};
use libzond::{
    Envelope, SecretString,
    credential::{self, Event, Request},
    wire,
};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};
use tokio::{
    io::BufReader,
    net::{UnixStream, unix::OwnedWriteHalf},
    sync::mpsc,
};

pub fn read_key(path: &Path) -> Result<SecretString> {
    libzond::paths::trusted_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.mode() & 0o077 == 0 && metadata.len() <= 128,
        "credential identity must be a private, bounded regular file"
    );
    let mut key = zeroize::Zeroizing::new(String::new());
    file.take(129).read_to_string(&mut key)?;
    let value = SecretString(key.trim().into());
    ensure!(
        credential::valid_key(&value.0),
        "invalid credential identity file"
    );
    Ok(value)
}

pub struct Client {
    writer: OwnedWriteHalf,
    events: mpsc::Receiver<Envelope<Event>>,
    reader: tokio::task::JoinHandle<()>,
    next_id: u64,
    pub session_id: String,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Client {
    pub async fn connect(path: &Path, recipient: &str, key: SecretString) -> Result<Self> {
        libzond::paths::trusted_path(path)?;
        let socket = UnixStream::connect(path).await?;
        ensure!(
            socket.peer_cred()?.uid() == libzond::paths::current_uid(),
            "unexpected credential broker owner"
        );
        let (reader, mut writer) = socket.into_split();
        let mut reader = BufReader::new(reader);
        let request = Envelope::new(
            1,
            Request::Authenticate {
                recipient: recipient.into(),
                key,
            },
        );
        tokio::time::timeout(Duration::from_secs(10), wire::write(&mut writer, &request)).await??;
        drop(request);
        let response: Envelope<Event> = tokio::time::timeout(
            Duration::from_secs(10),
            wire::read(&mut reader, credential::MAX_RESPONSE_BYTES),
        )
        .await??
        .context("credential broker disconnected")?;
        ensure!(
            response.version == credential::VERSION && response.id == 1,
            "invalid credential handshake"
        );
        let Event::Ready { session_id } = response.body else {
            anyhow::bail!("credential session refused");
        };
        let (incoming, events) = mpsc::channel(8);
        let reader = tokio::spawn(async move {
            while let Ok(Some(event)) =
                wire::read(&mut reader, credential::MAX_RESPONSE_BYTES).await
            {
                if incoming.send(event).await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            writer,
            events,
            reader,
            next_id: 1,
            session_id,
        })
    }

    /// Returns the correlation ID. Keep it with the pending application job.
    /// If a send is cancelled or fails, drop this client rather than resending.
    pub async fn send(&mut self, request: Request) -> Result<u64> {
        ensure!(
            !matches!(request, Request::Authenticate { .. }),
            "session already authenticated"
        );
        let id = self
            .next_id
            .checked_add(1)
            .context("credential request IDs exhausted")?;
        let envelope = Envelope::new(id, request);
        ensure!(
            serde_json::to_vec(&envelope)?.len() < credential::MAX_REQUEST_BYTES,
            "credential frame too large"
        );
        self.next_id = id;
        tokio::time::timeout(
            Duration::from_secs(5),
            wire::write(&mut self.writer, &envelope),
        )
        .await??;
        Ok(id)
    }

    /// Cancellation-safe: a dedicated task assembles complete frames. Answers
    /// and keys use SecretString, which redacts Debug and zeroes values on drop.
    pub async fn receive(&mut self) -> Result<Envelope<Event>> {
        let event = self
            .events
            .recv()
            .await
            .context("credential session closed")?;
        ensure!(
            event.version == credential::VERSION && event.id > 1 && event.id <= self.next_id,
            "invalid credential response"
        );
        Ok(event)
    }

    /// Cancel an opened challenge whose answer has not yet been consumed. Drain
    /// the terminal answer and withdrawal reply in either order, dropping all
    /// values. If an answer won the race, report cancellation of its use.
    pub async fn withdraw_and_discard(
        &mut self,
        request_id: u64,
        challenge_id: &str,
    ) -> Result<()> {
        let withdraw_id = self
            .send(Request::Withdraw {
                challenge_id: challenge_id.into(),
            })
            .await?;
        let mut terminal = false;
        let mut acknowledged = false;
        let mut delivered = false;
        while !terminal || !acknowledged {
            let reply = self.receive().await?;
            match reply.body {
                Event::Answered {
                    challenge_id: id,
                    values,
                    ..
                } if reply.id == request_id && id == challenge_id => {
                    delivered = values.is_some();
                    drop(values);
                    terminal = true;
                }
                Event::Recorded { challenge_id: id }
                    if reply.id == withdraw_id && id == challenge_id =>
                {
                    acknowledged = true
                }
                Event::Error { code }
                    if reply.id == withdraw_id
                        && matches!(code.as_str(), "answer_delivered" | "unknown_challenge") =>
                {
                    acknowledged = true
                }
                _ => anyhow::bail!("unexpected credential cancellation response"),
            }
        }
        if delivered {
            let result_id = self
                .send(Request::Result {
                    challenge_id: challenge_id.into(),
                    outcome: "cancelled".into(),
                })
                .await?;
            let reply = self.receive().await?;
            ensure!(
                reply.id == result_id && matches!(reply.body, Event::Recorded { .. }),
                "credential cancellation was not recorded"
            );
        }
        Ok(())
    }
}
