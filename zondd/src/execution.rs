use anyhow::{Context, Result};
use libzond::{Command, Event};
use std::{
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::Path,
    process::Stdio,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process,
    sync::mpsc,
};

struct ProcessGuard {
    child: Option<process::Child>,
    group: u32,
    reaped: bool,
}
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // SAFETY: kill uses only a numeric process group established for this child.
        // The group is terminated on success as well, so background children do not outlive requests.
        unsafe {
            libc::kill(-(self.group as i32), libc::SIGKILL);
        }
        if !self.reaped
            && let Some(mut child) = self.child.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

pub async fn execute(
    command: &Command,
    cwd: &Path,
    askpass: Option<&Path>,
    mut output: impl FnMut(bool, &[u8]) -> Result<()>,
) -> Result<Event> {
    let mut process = start(command, cwd, askpass)?;
    let stdout = process
        .child
        .as_mut()
        .unwrap()
        .stdout
        .take()
        .context("missing stdout")?;
    let stderr = process
        .child
        .as_mut()
        .unwrap()
        .stderr
        .take()
        .context("missing stderr")?;
    let (tx, mut rx) = mpsc::channel(8);
    let mut readers = tokio::task::JoinSet::new();
    readers.spawn(pump(stdout, false, tx.clone()));
    readers.spawn(pump(stderr, true, tx));
    let mut status = None;
    let mut eof = false;
    loop {
        if status.is_some() && eof {
            break;
        }
        tokio::select! {
            result = process.child.as_mut().unwrap().wait(), if status.is_none() => {
                status = Some(result?);
                process.reaped = true;
                // SAFETY: process.group is the child process group created above.
                unsafe { libc::kill(-(process.group as i32), libc::SIGKILL); }
            }
            chunk = rx.recv(), if !eof => match chunk {
                Some((is_err, bytes)) => output(is_err, &bytes?)?,
                None => eof = true,
            }
        }
    }
    let status = status.context("missing exit status")?;
    Ok(Event::Completed {
        code: status.code(),
        signal: status.signal(),
        stdout: String::new(),
        stderr: String::new(),
    })
}

fn start(command: &Command, cwd: &Path, askpass: Option<&Path>) -> Result<ProcessGuard> {
    let mut cmd = process::Command::new(&command.program);
    cmd.args(&command.args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", cwd)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(path) = askpass {
        cmd.env("SUDO_ASKPASS", path);
    }
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
    let no_new_privs = askpass.is_none();
    // SAFETY: the post-fork closure calls only async-signal-safe limit syscalls,
    // does not allocate or acquire application locks.
    unsafe {
        cmd.pre_exec(move || {
            if no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
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
    let child = cmd
        .spawn()
        .with_context(|| format!("execute {}", command.program))?;
    let group = child.id().context("child has no PID")?;
    Ok(ProcessGuard {
        child: Some(child),
        group,
        reaped: false,
    })
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
