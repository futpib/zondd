//! Isolated Linux process fixtures shared by the daemon and CLI integration tests.

use base64::{Engine, engine::general_purpose::STANDARD};
use nix::{
    poll::{PollFd, PollFlags, poll},
    sys::signal::{Signal, kill, killpg},
    unistd::{Pid, Uid, User},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    fs::{self, File, Permissions},
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::{
        fd::AsFd,
        unix::{fs::PermissionsExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

pub use nix;
pub use serde_json;

pub fn cargo_bin(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(name)
}

pub fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "condition did not become true within ten seconds"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Own a process group so assertions and timeouts clean up children as well.
pub struct Process {
    pub child: Child,
    status: Option<ExitStatus>,
    stopped: bool,
}

impl Process {
    pub fn spawn(command: &mut Command) -> Self {
        command.process_group(0);
        Self {
            child: command
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {command:?}: {e}")),
            status: None,
            stopped: false,
        }
    }

    pub fn signal(&self, signal: Signal) {
        kill(Pid::from_raw(self.child.id() as i32), signal).unwrap();
    }

    pub fn wait(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.status.or_else(|| self.child.try_wait().unwrap()) {
                self.status = Some(status);
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "process {} exceeded {timeout:?}",
                self.child.id()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let group = Pid::from_raw(self.child.id() as i32);
        if self.status.is_some() {
            let _ = killpg(group, Signal::SIGKILL);
            return;
        }
        let _ = killpg(group, Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.status = Some(status);
                let _ = killpg(group, Signal::SIGKILL);
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = killpg(group, Signal::SIGKILL);
        self.status = Some(self.child.wait().unwrap());
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Capture to files so a child inheriting stdout cannot block a reader indefinitely.
pub fn output(command: &mut Command) -> Output {
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    command
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap());
    let mut process = Process::spawn(command);
    let status = process.wait(Duration::from_secs(30));
    use std::io::{Seek, SeekFrom};
    stdout.seek(SeekFrom::Start(0)).unwrap();
    stderr.seek(SeekFrom::Start(0)).unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.read_to_end(&mut out).unwrap();
    stderr.read_to_end(&mut err).unwrap();
    Output {
        status,
        stdout: out,
        stderr: err,
    }
}

pub fn checked(command: &mut Command, code: i32) -> Output {
    let result = output(command);
    assert_eq!(result.status.code(), Some(code), "{command:?}: {result:?}");
    result
}

/// Small-output regression checks must see EOF, including on inherited proxy pipes.
pub fn pipe_output(command: &mut Command) -> Output {
    let mut process = Process::spawn(command.stdout(Stdio::piped()).stderr(Stdio::piped()));
    let status = process.wait(Duration::from_secs(30));
    let stdout = read_to_eof(process.child.stdout.as_mut().unwrap());
    let stderr = read_to_eof(process.child.stderr.as_mut().unwrap());
    Output {
        status,
        stdout,
        stderr,
    }
}

fn read_to_eof(input: &mut (impl Read + AsFd)) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "pipe remained open after process exited: {bytes:?}"
        );
        let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, 100u16).unwrap() == 0 {
            continue;
        }
        let mut buffer = [0; 4096];
        let n = input.read(&mut buffer).unwrap();
        if n == 0 {
            return bytes;
        }
        bytes.extend_from_slice(&buffer[..n]);
        assert!(bytes.len() <= 4 * 1024 * 1024, "test output exceeded limit");
    }
}

/// Bounded reads for actual child stdout pipes and PTY masters.
pub fn read_until(input: &mut (impl Read + AsFd), needle: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = Vec::new();
    loop {
        if bytes.windows(needle.len()).any(|part| part == needle) {
            return bytes;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}: {bytes:?}"
        );
        let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, 100u16).unwrap() == 0 {
            continue;
        }
        // One byte avoids consuming a second JSON event past the newline.
        let mut byte = [0];
        assert_eq!(
            input.read(&mut byte).unwrap(),
            1,
            "EOF before {needle:?}: {bytes:?}"
        );
        bytes.push(byte[0]);
        assert!(
            bytes.len() <= 4 * 1024 * 1024,
            "test response exceeded protocol limit"
        );
    }
}

pub fn read_json(input: &mut (impl Read + AsFd)) -> Value {
    serde_json::from_slice(&read_until(input, b"\n")).unwrap()
}

pub struct Session(BufReader<UnixStream>);
impl Session {
    pub fn new(path: &Path, body: Value) -> Self {
        let mut socket = UnixStream::connect(path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        writeln!(socket, "{}", json!({"version":1,"id":7,"body":body})).unwrap();
        Self(BufReader::new(socket))
    }
    pub fn event(&mut self) -> Value {
        let mut line = String::new();
        self.0.read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["id"], 7);
        value["body"].clone()
    }
}

pub fn command(program: &str, args: &[&str]) -> Value {
    json!({"method":"run","command":{"program":program,"args":args}})
}
pub fn decoded(event: &Value, field: &str) -> Vec<u8> {
    STANDARD.decode(event[field].as_str().unwrap()).unwrap()
}

pub struct TestEnv {
    pub dir: TempDir,
    pub runtime: PathBuf,
    pub daemon: PathBuf,
    pub ctl: PathBuf,
    pub probe: PathBuf,
    pub config: PathBuf,
    pub user: User,
    pub policy: String,
    processes: RefCell<Vec<Process>>,
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEnv {
    pub fn new() -> Self {
        assert!(
            !Uid::effective().is_root(),
            "run these user-daemon tests without sudo"
        );
        let user = User::from_uid(Uid::effective()).unwrap().unwrap();
        let dir = tempfile::Builder::new()
            .prefix(".zondd-test-")
            .tempdir_in(&user.dir)
            .unwrap();
        fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        let runtime_base = dir.path().join("run");
        fs::create_dir(&runtime_base).unwrap();
        let runtime = runtime_base.join("zondd");
        let copy = |name| {
            let path = dir.path().join(name);
            fs::copy(cargo_bin(name), &path).expect("first run cargo build --workspace --bins");
            fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
            path
        };
        let daemon = copy("zondd");
        let ctl = copy("zondctl");
        let probe = copy("zond-test-command");
        let config = dir.path().join("config/zondd/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let policy = include_str!("policy.toml").to_owned();
        fs::write(&config, &policy).unwrap();
        fs::set_permissions(&config, Permissions::from_mode(0o600)).unwrap();
        let env = Self {
            dir,
            runtime,
            daemon,
            ctl,
            probe,
            config,
            user,
            policy,
            processes: RefCell::default(),
        };
        env.start_daemon();
        env
    }

    pub fn start(&self, command: &mut Command, name: &str) -> usize {
        let log = File::create(self.dir.path().join(format!("{name}.log"))).unwrap();
        command.stdout(log.try_clone().unwrap()).stderr(log);
        let mut processes = self.processes.borrow_mut();
        processes.push(Process::spawn(command));
        processes.len() - 1
    }
    pub fn start_daemon(&self) {
        self.start(self.daemon_command().arg("serve"), "daemon");
        wait_for(|| self.runtime.join("ops.sock").exists());
    }
    pub fn daemon_command(&self) -> Command {
        let mut cmd = Command::new(&self.daemon);
        cmd.env(
            "XDG_CONFIG_HOME",
            self.config.parent().unwrap().parent().unwrap(),
        )
        .env("XDG_RUNTIME_DIR", self.runtime.parent().unwrap());
        cmd
    }
    pub fn stop_daemon(&self) {
        self.processes.borrow_mut()[0].stop();
    }
    pub fn session(&self, principal: &str, body: Value) -> Session {
        Session::new(&self.runtime.join(format!("{principal}.sock")), body)
    }
    pub fn request(&self, principal: &str, body: Value) -> Value {
        self.session(principal, body).event()
    }
    pub fn queue(&self) -> Vec<Value> {
        self.request("admin", json!({"method":"pending"}))["requests"]
            .as_array()
            .unwrap()
            .clone()
    }
    pub fn resolve(&self, id: &str, approve: bool) -> Value {
        self.request(
            "admin",
            json!({"method":"resolve","approval_id":id,"approve":approve}),
        )
    }
    pub fn pending(&self, body: Value) -> (Session, String) {
        let mut session = self.session("exec", body);
        let event = session.event();
        assert_eq!(event["type"], "pending", "{event}");
        let id = event["request"]["approval_id"].as_str().unwrap().to_owned();
        (session, id)
    }
    pub fn approved_probe(&self, args: &[&str]) -> Value {
        let (mut session, id) = self.pending(command(self.probe.to_str().unwrap(), args));
        assert_eq!(self.resolve(&id, true)["type"], "resolved");
        session.event()
    }
    pub fn owned_workdir(&self) -> PathBuf {
        let path = self.dir.path().join("work");
        fs::create_dir(&path).unwrap();
        path
    }
    pub fn cli(&self) -> Command {
        let mut cmd = Command::new(&self.ctl);
        cmd.env("XDG_RUNTIME_DIR", self.runtime.parent().unwrap());
        cmd
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for process in self.processes.get_mut().iter_mut().rev() {
            process.stop();
        }
        if thread::panicking() {
            for entry in fs::read_dir(self.dir.path()).unwrap().flatten() {
                if entry.path().extension().is_some_and(|ext| ext == "log") {
                    let data = fs::read(entry.path()).unwrap_or_default();
                    eprintln!(
                        "{}:\n{}",
                        entry.path().display(),
                        String::from_utf8_lossy(&data[data.len().saturating_sub(12000)..])
                    );
                }
            }
        }
    }
}

pub struct SshEnv {
    pub env: TestEnv,
    pub port: u16,
    pub config: PathBuf,
}
impl Default for SshEnv {
    fn default() -> Self {
        Self::new()
    }
}
impl SshEnv {
    pub fn new() -> Self {
        let env = TestEnv::new();
        for key in [
            "host",
            "exec-key",
            "ops-key",
            "unknown-key",
            "management-key",
        ] {
            checked(
                Command::new("ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(env.dir.path().join(key)),
                0,
            );
        }
        let mut authorized = String::new();
        for principal in ["exec", "ops"] {
            let key =
                fs::read_to_string(env.dir.path().join(format!("{principal}-key.pub"))).unwrap();
            authorized.push_str(&format!(
                "restrict,command=\"{} bridge --runtime-dir {} --principal {principal}\" {key}",
                env.daemon.display(),
                env.runtime.display()
            ));
        }
        authorized
            .push_str(&fs::read_to_string(env.dir.path().join("management-key.pub")).unwrap());
        let keys = env.dir.path().join("authorized_keys");
        fs::write(&keys, authorized).unwrap();
        fs::set_permissions(&keys, Permissions::from_mode(0o644)).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sshd_config = env.dir.path().join("sshd_config");
        fs::write(&sshd_config, format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}/host\nPidFile {}/sshd.pid\nAuthorizedKeysFile {}\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nPermitRootLogin no\nStrictModes yes\nAllowUsers {}\nLogLevel VERBOSE\n", env.dir.path().display(), env.dir.path().display(), keys.display(), env.user.name)).unwrap();
        let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect("OpenSSH server required");
        checked(Command::new(sshd).args(["-t", "-f"]).arg(&sshd_config), 0);
        env.start(
            Command::new(sshd)
                .args(["-D", "-e", "-f"])
                .arg(&sshd_config),
            "sshd",
        );
        wait_for(|| TcpStream::connect(("127.0.0.1", port)).is_ok());
        let known = env.dir.path().join("known_hosts");
        fs::write(
            &known,
            format!(
                "zondd-test {}",
                fs::read_to_string(env.dir.path().join("host.pub")).unwrap()
            ),
        )
        .unwrap();
        let config = env.dir.path().join("ssh_config");
        fs::write(&config, format!("Host *\n HostKeyAlias zondd-test\n UserKnownHostsFile {}\n StrictHostKeyChecking yes\n ConnectTimeout 10\n LogLevel ERROR\n", known.display())).unwrap();
        Self { env, port, config }
    }
    pub fn remote(&self, key: &str) -> Command {
        let mut cmd = Command::new(&self.env.ctl);
        cmd.arg("--host")
            .arg(format!("{}@127.0.0.1", self.env.user.name))
            .arg("--port")
            .arg(self.port.to_string())
            .arg("--ssh-config")
            .arg(&self.config)
            .arg("--identity")
            .arg(self.env.dir.path().join(format!("{key}-key")));
        cmd
    }
    pub fn ssh(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.arg("-F")
            .arg(&self.config)
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-i")
            .arg(self.env.dir.path().join("exec-key"))
            .args(["-T", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"])
            .arg(format!("{}@127.0.0.1", self.env.user.name));
        cmd
    }
    pub fn start_iroh(&self) -> String {
        self.env.start(
            Command::new("iroh-ssh")
                .arg("server")
                .arg("--ssh-port")
                .arg(self.port.to_string())
                .args(["--persist", "--key-dir"])
                .arg(self.env.dir.path().join("iroh")),
            "iroh",
        );
        let mut endpoint = None;
        wait_for(|| {
            let log = fs::read_to_string(self.env.dir.path().join("iroh.log")).unwrap();
            endpoint = log
                .split(|c: char| !c.is_ascii_hexdigit())
                .find(|s| s.len() == 64)
                .map(str::to_owned);
            endpoint.is_some()
        });
        let endpoint = endpoint.unwrap();
        // The CLI prints its endpoint before discovery publication completes.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let result = pipe_output(
                Command::new(&self.env.ctl)
                    .arg("--host")
                    .arg(format!("{}@{endpoint}", self.env.user.name))
                    .arg("--iroh")
                    .arg("--identity")
                    .arg(self.env.dir.path().join("ops-key"))
                    .arg("--ssh-config")
                    .arg(&self.config)
                    .args(["--json", "permissions"]),
            );
            if result.status.success() {
                let event: Value = serde_json::from_slice(&result.stdout).unwrap();
                assert_eq!(event["type"], "permissions");
                assert_eq!(event["permissions"]["principal"], "ops");
                return endpoint;
            }
            assert!(
                String::from_utf8_lossy(&result.stderr)
                    .contains("No addressing information available")
                    && Instant::now() < deadline,
                "Iroh server did not become reachable: {result:?}"
            );
            thread::sleep(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn assertion_failure_terminates_and_reaps_owned_process() {
        let pid = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let process = Process::spawn(Command::new("/bin/sleep").arg("30"));
            pid.set(process.child.id());
            panic!("exercise unwinding cleanup");
        }));
        assert!(result.is_err());
        assert_ne!(pid.get(), 0);
        assert_eq!(
            kill(Pid::from_raw(pid.get() as i32), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }
}
