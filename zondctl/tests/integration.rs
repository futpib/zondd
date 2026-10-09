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
fn local_caller_inspects_permissions_and_checks_both_input_types() {
    let env = TestEnv::new();
    for (principal, args, field, expected) in [
        (
            "exec",
            vec!["permissions"],
            "/permissions/principal",
            "exec",
        ),
        (
            "exec",
            vec!["check", "exec", "/usr/bin/id", "-u"],
            "/check/decision",
            "allow",
        ),
        (
            "exec",
            vec!["check", "exec", "/usr/bin/id"],
            "/check/decision",
            "ask",
        ),
        (
            "exec",
            vec!["check", "exec", "/usr/bin/false"],
            "/check/decision",
            "deny",
        ),
        (
            "ops",
            vec!["check", "invoke", "greet", "world"],
            "/check/decision",
            "allow",
        ),
        (
            "ops",
            vec!["check", "invoke", "greet", "--", "--help"],
            "/check/decision",
            "deny",
        ),
    ] {
        let result = checked(
            env.cli()
                .args(["--principal", principal, "--json"])
                .args(args),
            0,
        );
        let event: libzondtest::serde_json::Value =
            libzondtest::serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(event.pointer(field).unwrap(), expected, "{event}");
    }
    assert!(env.queue().is_empty());
}

#[test]
#[ignore = "requires OpenSSH client/server"]
fn restricted_ssh_callers_can_only_introspect_their_own_permissions() {
    let ssh = SshEnv::new();
    for principal in ["exec", "ops"] {
        let result = checked(ssh.remote(principal).args(["--json", "permissions"]), 0);
        let event: libzondtest::serde_json::Value =
            libzondtest::serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(event["permissions"]["principal"], principal);
        assert_eq!(
            event["permissions"]["policy"]["allow_exec"],
            principal == "exec"
        );
    }
    for (principal, args, expected) in [
        ("exec", vec!["exec", "/usr/bin/id", "-u"], "allow"),
        ("exec", vec!["exec", "/usr/bin/id"], "ask"),
        ("ops", vec!["exec", "/usr/bin/id", "-u"], "deny"),
        ("ops", vec!["invoke", "greet", "world"], "allow"),
    ] {
        let result = checked(
            ssh.remote(principal).args(["--json", "check"]).args(args),
            0,
        );
        let event: libzondtest::serde_json::Value =
            libzondtest::serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(event["check"]["decision"], expected, "{event}");
    }
    assert!(ssh.env.queue().is_empty());
}

#[test]
#[ignore = "requires OpenSSH client/server"]
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
#[ignore = "requires OpenSSH client/server"]
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
#[ignore = "requires OpenSSH client/server"]
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
#[ignore = "requires OpenSSH, iroh-ssh, and working discovery/relay connectivity"]
fn iroh_ssh_operation_completes_and_proxy_exits() {
    let ssh = SshEnv::new();
    let endpoint = ssh.start_iroh();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let result = pipe_output(
            Command::new(&ssh.env.ctl)
                .arg("--host")
                .arg(format!("{}@{endpoint}", ssh.env.user.name))
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
    for args in [
        vec!["permissions"],
        vec!["check", "invoke", "greet", "world"],
    ] {
        let result = pipe_output(
            Command::new(&ssh.env.ctl)
                .arg("--host")
                .arg(format!("{}@{endpoint}", ssh.env.user.name))
                .arg("--iroh")
                .arg("--identity")
                .arg(ssh.env.dir.path().join("ops-key"))
                .arg("--ssh-config")
                .arg(&ssh.config)
                .arg("--json")
                .args(args),
        );
        assert!(result.status.success(), "{result:?}");
        let event: libzondtest::serde_json::Value =
            libzondtest::serde_json::from_slice(&result.stdout).unwrap();
        match event["type"].as_str().unwrap() {
            "permissions" => assert_eq!(event["permissions"]["principal"], "ops"),
            "checked" => assert_eq!(event["check"]["decision"], "allow"),
            other => panic!("unexpected event: {other}"),
        }
    }
}

#[test]
#[ignore = "requires OpenSSH client/server and iroh-ssh"]
fn trusted_management_uses_normal_ssh_over_both_transports() {
    let ssh = SshEnv::new();
    let endpoint = ssh.start_iroh();
    for iroh in [false, true] {
        for approve in [true, false] {
            let mut calling = if iroh {
                let mut cmd = Command::new(&ssh.env.ctl);
                cmd.arg("--iroh")
                    .arg("--host")
                    .arg(format!("{}@{endpoint}", ssh.env.user.name))
                    .arg("--ssh-config")
                    .arg(&ssh.config)
                    .arg("--identity")
                    .arg(ssh.env.dir.path().join("exec-key"));
                cmd
            } else {
                ssh.remote("exec")
            };
            let mut caller = Process::spawn(
                calling
                    .args(["--json", "exec", "/usr/bin/printf", "%s", "managed"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit()),
            );
            let pending = read_json(caller.child.stdout.as_mut().unwrap());
            assert_eq!(pending["type"], "pending");
            let id = pending["request"]["approval_id"].as_str().unwrap();
            let mut cmd = Command::new("ssh");
            cmd.arg("-F")
                .arg(&ssh.config)
                .arg("-i")
                .arg(ssh.env.dir.path().join("management-key"))
                .args(["-T", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]);
            if iroh {
                cmd.args(["-o", "ProxyCommand=iroh-ssh proxy %h"])
                    .arg(format!("{}@{endpoint}", ssh.env.user.name));
            } else {
                cmd.arg("-p")
                    .arg(ssh.port.to_string())
                    .arg(format!("{}@127.0.0.1", ssh.env.user.name));
            }
            cmd.arg(format!(
                "{} --runtime-dir {} control --config {}",
                ssh.env.ctl.display(),
                ssh.env.runtime.display(),
                ssh.env.config.display()
            ));
            let mut process = Process::spawn(
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit()),
            );
            let mut stdin = process.child.stdin.take().unwrap();
            writeln!(
                stdin,
                "{}",
                json!({"version":1,"method":"resolve","approval_id":id,"approve":approve})
            )
            .unwrap();
            let response = read_json(process.child.stdout.as_mut().unwrap());
            assert_eq!(response["ok"], true, "{response}");
            assert!(process.wait(Duration::from_secs(5)).success());
            assert_eq!(
                read_json(caller.child.stdout.as_mut().unwrap())["type"],
                if approve { "completed" } else { "rejected" }
            );
            assert_eq!(
                caller.wait(Duration::from_secs(5)).code(),
                Some(if approve { 0 } else { 126 })
            );
        }
    }
    let rejected = checked(
        ssh.ssh().arg(format!("{} control", ssh.env.ctl.display())),
        1,
    );
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("protocol only"));
}
