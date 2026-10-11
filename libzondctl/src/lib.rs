use anyhow::{Context, Result, ensure};
use libzond::{Envelope, Event, MAX_RESPONSE_BYTES, Request, VERSION, wire};
use std::{
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    net::UnixStream,
    process::{Child, Command},
};

#[derive(Clone, Debug)]
pub struct SshOptions {
    pub host: String,
    pub identity: Option<PathBuf>,
    pub port: Option<u16>,
    pub config: Option<PathBuf>,
    pub iroh: bool,
}

pub struct Client {
    read: BufReader<Pin<Box<dyn AsyncRead + Send>>>,
    write: Pin<Box<dyn AsyncWrite + Send>>,
    _ssh: Option<SshProcess>,
    active: Option<u64>,
    used: bool,
}

struct SshProcess(Child);

impl Drop for SshProcess {
    fn drop(&mut self) {
        if let Some(pid) = self.0.id() {
            // SAFETY: this child was spawned in its own process group. Closing a
            // client must also stop ProxyCommand children that still hold pipes open.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
}

impl Client {
    pub async fn local(path: &Path) -> Result<Self> {
        let (read, write) = UnixStream::connect(path).await?.into_split();
        Ok(Self {
            read: BufReader::new(Box::pin(read)),
            write: Box::pin(write),
            _ssh: None,
            active: None,
            used: false,
        })
    }

    pub fn ssh(options: &SshOptions) -> Result<Self> {
        ensure!(
            !options.host.is_empty()
                && !options.host.starts_with('-')
                && !options.host.chars().any(char::is_whitespace),
            "invalid SSH destination"
        );
        let mut command = Command::new("ssh");
        command.as_std_mut().process_group(0);
        command.args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "RemoteCommand=none",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
        ]);
        if let Some(path) = &options.config {
            command.arg("-F").arg(path);
        }
        if let Some(path) = &options.identity {
            command
                .arg("-i")
                .arg(path)
                .args(["-o", "IdentitiesOnly=yes"]);
        }
        if let Some(port) = options.port {
            command.arg("-p").arg(port.to_string());
        }
        if options.iroh {
            // ProxyCommand is interpreted by a shell; never interpolate client-controlled text.
            let endpoint = options.host.rsplit('@').next().unwrap_or_default();
            ensure!(
                endpoint.len() == 64 && endpoint.bytes().all(|b| b.is_ascii_hexdigit()),
                "--iroh requires user@<64-hex endpoint ID>"
            );
            command.args(["-o", "ProxyCommand=iroh-ssh proxy %h"]);
        }
        command
            .arg(&options.host)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command.spawn().context("start OpenSSH client")?;
        let read = child.stdout.take().context("missing SSH stdout")?;
        let write = child.stdin.take().context("missing SSH stdin")?;
        Ok(Self {
            read: BufReader::new(Box::pin(read)),
            write: Box::pin(write),
            _ssh: Some(SshProcess(child)),
            active: None,
            used: false,
        })
    }

    pub async fn send(&mut self, request: Request) -> Result<()> {
        ensure!(!self.used, "one request is supported per connection");
        let envelope = Envelope::new(1, request);
        let frame = zeroize::Zeroizing::new(serde_json::to_vec(&envelope)?);
        ensure!(
            frame.len() < libzond::MAX_REQUEST_BYTES,
            "request exceeds protocol limit"
        );
        self.used = true;
        self.active = Some(1);
        wire::write(&mut self.write, &envelope).await
    }

    pub async fn next(&mut self) -> Result<Event> {
        let id = self.active.context("no active request")?;
        let response: Envelope<Event> = wire::read(&mut self.read, MAX_RESPONSE_BYTES)
            .await?
            .context("connection closed before a terminal response")?;
        ensure!(
            response.version == VERSION && response.id == id,
            "response version or ID mismatch"
        );
        if response.body.is_terminal() {
            self.active = None;
        }
        Ok(response.body)
    }

    pub async fn request(&mut self, request: Request) -> Result<Event> {
        self.send(request).await?;
        loop {
            let event = self.next().await?;
            if event.is_terminal() {
                return Ok(event);
            }
        }
    }
}
