use libzondtest::{
    Process, SshEnv, TestEnv, checked, decoded,
    nix::{
        sys::{signal::Signal, stat::Mode},
        unistd::mkfifo,
    },
    read_json, read_until,
    serde_json::{Value, json},
    wait_for,
};
use std::{
    fs,
    io::Read,
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

struct GatedJob<'a> {
    env: &'a TestEnv,
    gate: PathBuf,
}

impl<'a> GatedJob<'a> {
    fn new(env: &'a TestEnv) -> Self {
        let gate = env.dir.path().join("gate");
        mkfifo(&gate, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let policy = env.policy.replace(
            "operations = [\"greet\"]",
            "operations = [\"greet\", \"wait\"]",
        ) + &format!(
            "\n[[principals.exec.rules]]\nprogram = {program}\ndecision = \"allow\"\n\
             [operations.wait]\nprogram = {program}\nfixed_args = {args}\ndecision = \"allow\"\n",
            program = json!(env.probe),
            args = json!(["stream_gate", gate, "7"]),
        );
        fs::write(&env.config, policy).unwrap();
        assert_eq!(
            env.request("admin", json!({"method":"reload"}))["type"],
            "reloaded"
        );
        Self { env, gate }
    }

    fn cli(&self, invoke: bool, json: bool, detach: bool) -> Command {
        let mut command = self.env.cli();
        command.args(["--principal", if invoke { "ops" } else { "exec" }]);
        if json {
            command.arg("--json");
        }
        command.arg(if invoke { "invoke" } else { "exec" });
        if detach {
            command.arg("--detach");
        }
        if invoke {
            command.arg("wait");
        } else {
            command
                .arg(&self.env.probe)
                .arg("stream_gate")
                .arg(&self.gate)
                .arg("7");
        }
        command
    }

    fn release(&self) {
        let mut writer = None;
        wait_for(|| {
            writer = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libzondtest::nix::libc::O_NONBLOCK)
                .open(&self.gate)
                .ok();
            writer.is_some()
        });
        drop(writer);
    }

    fn job(&self, id: &str) -> Value {
        self.env
            .request("admin", json!({"method":"job", "request_id":id}))
    }
}

#[test]
fn exec_and_invoke_follow_json_through_completion_without_replaying() {
    for invoke in [false, true] {
        let env = TestEnv::new();
        let job = GatedJob::new(&env);
        let mut caller = Process::spawn(
            job.cli(invoke, true, false)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()),
        );
        let stdout = caller.child.stdout.as_mut().unwrap();
        let submitted = read_json(stdout);
        assert_eq!(submitted["type"], "submitted", "{submitted}");
        let id = submitted["request_id"].as_str().unwrap();
        let early = read_json(stdout);
        assert_eq!(early["type"], "output", "{early}");
        assert_eq!(decoded(&early, "data"), b"early\n");
        assert_eq!(early["stderr"], false);
        assert_eq!(job.job(id)["request"]["status"], "running");
        job.release();
        let late = read_json(stdout);
        assert_eq!(late["type"], "output", "{late}");
        assert_eq!(decoded(&late, "data"), b"late\n");
        assert_eq!(late["stderr"], true);
        let terminal = read_json(stdout);
        assert_eq!(terminal["type"], "job", "{terminal}");
        assert_eq!(terminal["request"]["request_id"], id);
        assert_eq!(terminal["request"]["result"]["code"], 7);
        assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(7));
        let history = job.env.request("admin", json!({"method":"history"}));
        assert_eq!(history["requests"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn automatic_follow_keeps_command_stdout_and_stderr_separate() {
    let env = TestEnv::new();
    let job = GatedJob::new(&env);
    let mut caller = Process::spawn(
        job.cli(false, false, false)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(
        read_until(caller.child.stdout.as_mut().unwrap(), b"\n"),
        b"early\n"
    );
    assert!(caller.child.try_wait().unwrap().is_none());
    job.release();
    assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(7));
    let mut stdout = Vec::new();
    caller
        .child
        .stdout
        .as_mut()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(stdout.is_empty(), "{stdout:?}");
    let mut stderr = String::new();
    caller
        .child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("Following job"), "{stderr}");
    assert_eq!(stderr.lines().filter(|line| *line == "late").count(), 1);
}

#[test]
fn explicit_detach_returns_before_completion_for_exec_and_invoke() {
    for invoke in [false, true] {
        let env = TestEnv::new();
        let job = GatedJob::new(&env);
        let output = checked(&mut job.cli(invoke, invoke, true), 0);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let id = if invoke {
            let submitted: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(submitted["type"], "submitted");
            submitted["request_id"].as_str().unwrap().to_owned()
        } else {
            stdout.trim().to_owned()
        };
        assert_eq!(job.job(&id)["request"]["status"], "running");
        job.release();
        let output = checked(job.env.cli().args(["follow", &id]), 7);
        assert_eq!(output.stdout, b"early\n");
        assert!(String::from_utf8_lossy(&output.stderr).contains("late\n"));
    }
}

#[test]
fn interrupting_automatic_follow_leaves_the_job_available() {
    let env = TestEnv::new();
    let job = GatedJob::new(&env);
    let mut caller = Process::spawn(
        job.cli(false, true, false)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let stdout = caller.child.stdout.as_mut().unwrap();
    let submitted = read_json(stdout);
    let id = submitted["request_id"].as_str().unwrap();
    assert_eq!(read_json(stdout)["type"], "output");
    caller.signal(Signal::SIGINT);
    assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(130));
    assert_eq!(job.job(id)["request"]["status"], "running");
    job.release();
    assert_eq!(
        checked(job.env.cli().args(["follow", id]), 7).stdout,
        b"early\n"
    );
}

#[test]
fn automatic_follow_preserves_signal_exit_status() {
    let env = TestEnv::new();
    let marker = env.dir.path().join("pid");
    let mut caller = Process::spawn(
        env.cli()
            .args(["--principal", "exec", "--json", "exec"])
            .arg(&env.probe)
            .arg("sleep")
            .arg(&marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let stdout = caller.child.stdout.as_mut().unwrap();
    let pending = read_json(stdout);
    assert_eq!(pending["type"], "pending");
    env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true);
    assert_eq!(read_json(stdout)["type"], "submitted");
    let pid = fs::read_to_string(marker).unwrap().parse().unwrap();
    libzondtest::nix::sys::signal::kill(
        libzondtest::nix::unistd::Pid::from_raw(pid),
        Signal::SIGTERM,
    )
    .unwrap();
    let terminal = read_json(stdout);
    assert_eq!(terminal["request"]["result"]["signal"], 15);
    assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(143));
}

fn remote_automatic_follow(iroh: bool) {
    let ssh = SshEnv::new();
    let endpoint = iroh.then(|| ssh.start_iroh());
    let job = GatedJob::new(&ssh.env);
    let mut command = if let Some(endpoint) = endpoint {
        let mut command = Command::new(&ssh.env.ctl);
        command
            .arg("--host")
            .arg(format!("{}@{endpoint}", ssh.env.user.name))
            .arg("--iroh")
            .arg("--identity")
            .arg(ssh.env.dir.path().join("ops-key"))
            .arg("--ssh-config")
            .arg(&ssh.config);
        command
    } else {
        ssh.remote("ops")
    };
    let mut caller = Process::spawn(
        command
            .args(["--json", "invoke", "wait"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let stdout = caller.child.stdout.as_mut().unwrap();
    let submitted = read_json(stdout);
    assert_eq!(submitted["type"], "submitted", "{submitted}");
    assert_eq!(decoded(&read_json(stdout), "data"), b"early\n");
    job.release();
    assert_eq!(decoded(&read_json(stdout), "data"), b"late\n");
    let terminal = read_json(stdout);
    assert_eq!(terminal["request"]["request_id"], submitted["request_id"]);
    assert_eq!(terminal["request"]["result"]["code"], 7);
    assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(7));
    // EOF also verifies that the second SSH/proxy did not retain the output pipe.
    let stdout = caller.child.stdout.as_mut().unwrap();
    use libzondtest::nix::poll::{PollFd, PollFlags, poll};
    assert!(
        poll(
            &mut [PollFd::new(stdout.as_fd(), PollFlags::POLLIN)],
            5000u16
        )
        .unwrap()
            > 0
    );
    assert_eq!(stdout.read(&mut [0]).unwrap(), 0);
}

#[test]
#[ignore = "requires OpenSSH client/server"]
fn ssh_automatically_follows_without_restarting_the_command() {
    remote_automatic_follow(false);
}

#[test]
#[ignore = "requires OpenSSH, iroh-ssh, and working discovery/relay connectivity"]
fn iroh_ssh_automatically_follows_and_exits() {
    remote_automatic_follow(true);
}
