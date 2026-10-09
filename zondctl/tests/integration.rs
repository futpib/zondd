use libzondtest::{
    Process, SshEnv, TestEnv, checked, command, decoded,
    nix::{pty::openpty, sys::signal::Signal},
    pipe_output, read_json, read_until,
    serde_json::json,
};
use std::{
    fs::File,
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn cli_version_and_argument_errors() {
    let ctl = env!("CARGO_BIN_EXE_zondctl");
    let version = checked(Command::new(ctl).arg("--version"), 0);
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with("zondctl ")
    );
    checked(Command::new(ctl).args(["--iroh", "exec", "/bin/true"]), 2);
}

#[test]
#[ignore = "requires root and OpenSSH client/server"]
fn ssh_keys_select_policy_and_reject_custom_commands() {
    let ssh = SshEnv::new();
    assert_eq!(
        checked(
            ssh.remote("exec")
                .args(["exec", "/usr/bin/printf", "%s", "hello"]),
            0
        )
        .stdout,
        b"hello"
    );
    assert_eq!(
        checked(ssh.remote("ops").args(["invoke", "greet", "world"]), 0).stdout,
        b"hello world"
    );
    checked(ssh.remote("ops").args(["exec", "/usr/bin/id", "-u"]), 126);
    checked(
        ssh.remote("unknown").args(["exec", "/usr/bin/id", "-u"]),
        125,
    );
    let rejected = checked(ssh.ssh().arg("/usr/bin/id"), 1);
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("protocol only"));
}

#[test]
#[ignore = "requires root and OpenSSH client/server"]
fn ssh_command_waits_for_local_cli_approval() {
    let ssh = SshEnv::new();
    let mut remote = Process::spawn(
        ssh.remote("exec")
            .args(["--json", "exec", "/usr/bin/printf", "%s", "ssh-approved"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let mut stdout = remote.child.stdout.take().unwrap();
    let pending = read_json(&mut stdout);
    assert_eq!(pending["type"], "pending");
    checked(
        ssh.env
            .cli()
            .arg("approve")
            .arg(pending["request"]["approval_id"].as_str().unwrap()),
        0,
    );
    let event = read_json(&mut stdout);
    assert_eq!(decoded(&event, "stdout"), b"ssh-approved");
    assert!(remote.wait(Duration::from_secs(5)).success());
}

#[test]
#[ignore = "requires root and OpenSSH client/server"]
fn forced_bridge_exits_even_while_ssh_stdin_remains_open() {
    let ssh = SshEnv::new();
    let mut remote = Process::spawn(
        ssh.ssh()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let mut stdin = remote.child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"version":1,"id":1,"body":command("/usr/bin/id", &["-u"])})
    )
    .unwrap();
    let event = read_json(remote.child.stdout.as_mut().unwrap());
    assert_eq!(event["body"]["type"], "completed");
    assert!(remote.wait(Duration::from_secs(5)).success());
    drop(stdin);
}

#[test]
#[ignore = "requires root and a PTY"]
fn review_approves_and_denies_through_a_real_terminal() {
    let env = TestEnv::new();
    for (answer, expected) in [(b"a\n", "completed"), (b"d\n", "rejected")] {
        let (mut session, _) = env.pending(command("/usr/bin/printf", &["%s", "terminal"]));
        let pty = openpty(None, None).unwrap();
        let mut master = File::from(pty.master);
        let slave = File::from(pty.slave);
        let mut review = Process::spawn(
            env.cli()
                .arg("review")
                .stdin(slave.try_clone().unwrap())
                .stdout(slave.try_clone().unwrap())
                .stderr(slave),
        );
        read_until(&mut master, b"Approve once");
        master.write_all(answer).unwrap();
        assert_eq!(session.event()["type"], expected);
        review.signal(Signal::SIGINT);
        assert_eq!(review.wait(Duration::from_secs(5)).code(), Some(130));
    }
}

#[test]
#[ignore = "requires root, OpenSSH, iroh-ssh, and working discovery/relay connectivity"]
fn iroh_ssh_operation_completes_and_proxy_exits() {
    let ssh = SshEnv::new();
    let endpoint = ssh.start_iroh();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let result = pipe_output(
            Command::new(&ssh.env.ctl)
                .arg("--host")
                .arg(format!("{}@{endpoint}", ssh.env.bridge.name))
                .arg("--iroh")
                .arg("--identity")
                .arg(ssh.env.dir.path().join("ops-key"))
                .arg("--ssh-config")
                .arg(&ssh.config)
                .args(["invoke", "greet", "world"]),
        );
        if result.status.success() {
            assert_eq!(result.stdout, b"hello world");
            break;
        }
        // The server prints its endpoint before discovery publication completes.
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("No addressing information available")
                && Instant::now() < deadline,
            "{result:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}
