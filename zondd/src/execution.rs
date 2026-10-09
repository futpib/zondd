use anyhow::{Context, Result, bail};
use libzond::{
    Command, Event,
    config::{Limits, Principal},
};
use std::{
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process,
    sync::mpsc,
};

struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // SAFETY: kill uses only a numeric process group established for this child.
        // The group is terminated on success as well, so background children do not outlive requests.
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}

pub async fn execute(command: &Command, principal: &Principal, limits: &Limits) -> Result<Event> {
    let mut cmd = process::Command::new(&command.program);
    cmd.args(&command.args)
        .current_dir(&principal.cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &principal.cwd)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // User operations such as systemctl --user need the daemon's home and session bus.
    // These values come from the local daemon, never from a remote request.
    for name in [
        "HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    ] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.as_std_mut().process_group(0);
    // SAFETY: the post-fork closure calls only async-signal-safe limit syscalls,
    // does not allocate or acquire application locks.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("execute {}", command.program))?;
    let group = ProcessGroup(child.id().context("child has no PID")?);
    let stdout = child.stdout.take().context("missing stdout")?;
    let stderr = child.stderr.take().context("missing stderr")?;
    let (tx, mut rx) = mpsc::channel(8);
    let mut readers = tokio::task::JoinSet::new();
    readers.spawn(pump(stdout, false, tx.clone()));
    readers.spawn(pump(stderr, true, tx));
    let run = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut status = None;
        let mut eof = false;
        loop {
            if status.is_some() && eof {
                break;
            }
            tokio::select! {
                result = child.wait(), if status.is_none() => {
                    status = Some(result?);
                    // Close pipes inherited by background children after the main command exits.
                    // SAFETY: group.0 is the child process group created above.
                    unsafe { libc::kill(-(group.0 as i32), libc::SIGKILL); }
                }
                chunk = rx.recv(), if !eof => match chunk {
                    Some((is_err, bytes)) => {
                        let bytes = bytes?;
                        if out.len() + err.len() + bytes.len() > limits.max_output_bytes { bail!("command output limit exceeded"); }
                        if is_err { err.extend(bytes); } else { out.extend(bytes); }
                    }
                    None => eof = true,
                }
            }
        }
        let status = status.context("missing exit status")?;
        use base64::{Engine, engine::general_purpose::STANDARD};
        Ok(Event::Completed {
            code: status.code(),
            signal: status.signal(),
            stdout: STANDARD.encode(out),
            stderr: STANDARD.encode(err),
        })
    };
    tokio::time::timeout(Duration::from_secs(limits.command_timeout_secs), run)
        .await
        .context("command timed out")?
}

async fn pump(
    mut input: impl AsyncRead + Unpin,
    stderr: bool,
    tx: mpsc::Sender<(bool, io::Result<Vec<u8>>)>,
) {
    let mut buf = [0u8; 8192];
    loop {
        match input.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx.send((stderr, Ok(buf[..n].to_vec()))).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.send((stderr, Err(e))).await;
                break;
            }
        }
    }
}
