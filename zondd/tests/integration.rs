use libzondtest::{TestEnv, checked, command, decoded, serde_json::json, wait_for};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

#[test]
fn policy_identity_and_operation_boundaries() {
    let env = TestEnv::new();
    checked(
        env.daemon_command()
            .arg("check")
            .arg("--config")
            .arg(&env.config),
        0,
    );
    checked(
        env.daemon_command()
            .arg("serve")
            .arg("--config")
            .arg(&env.config),
        1,
    );
    let event = env.request("exec", command("/usr/bin/id", &["-u"]));
    assert_eq!(
        decoded(&event, "stdout"),
        format!("{}\n", env.user.uid).as_bytes()
    );
    assert_eq!(
        env.request("exec", command("/usr/bin/false", &[]))["type"],
        "rejected"
    );
    assert_eq!(
        env.request("exec", json!({"method":"pending"}))["type"],
        "rejected"
    );
    assert_eq!(
        env.request("admin", command("/usr/bin/id", &["-u"]))["type"],
        "rejected"
    );
    assert_eq!(
        env.request("ops", command("/usr/bin/id", &["-u"]))["type"],
        "rejected"
    );
    assert_eq!(
        env.request(
            "ops",
            json!({"method":"invoke","operation":"greet","args":["--help"]})
        )["type"],
        "error"
    );
    let event = env.request(
        "ops",
        json!({"method":"invoke","operation":"greet","args":["λ"]}),
    );
    assert_eq!(decoded(&event, "stdout"), "hello λ".as_bytes());
}

#[test]
fn approvals_are_bound_to_one_request_and_cannot_be_replayed() {
    let env = TestEnv::new();
    for approve in [true, false] {
        let (mut session, id) = env.pending(command("/usr/bin/printf", &["%s", "manual"]));
        let queue = env.queue();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0]["command"]["args"], json!(["%s", "manual"]));
        assert_eq!(queue[0]["principal"], "exec");
        assert_eq!(env.resolve(&id, approve)["type"], "resolved");
        let event = session.event();
        assert_eq!(
            event["type"],
            if approve { "completed" } else { "rejected" }
        );
        if approve {
            assert_eq!(decoded(&event, "stdout"), b"manual");
        }
        assert_eq!(env.resolve(&id, true)["type"], "error");
    }
}

#[test]
fn disconnect_and_expiry_remove_pending_requests() {
    let env = TestEnv::new();
    let (session, id) = env.pending(command("/usr/bin/printf", &["cancel"]));
    drop(session);
    wait_for(|| env.queue().is_empty());
    assert_eq!(env.resolve(&id, true)["type"], "error");
    let (mut session, _) = env.pending(command("/usr/bin/printf", &["expire"]));
    assert_eq!(session.event()["type"], "rejected");
    assert!(env.queue().is_empty());
}

#[test]
fn full_remote_capacity_does_not_block_local_approval() {
    let env = TestEnv::new();
    let mut pending: Vec<_> = (0..2)
        .map(|_| env.pending(command("/usr/bin/printf", &["pending"])))
        .collect();
    assert_eq!(
        env.request("exec", command("/usr/bin/printf", &["full"]))["type"],
        "error"
    );
    let _idle: Vec<_> = (0..2)
        .map(|_| UnixStream::connect(env.runtime.join("exec.sock")).unwrap())
        .collect();
    // Let the accept loop acquire all four remote connection permits.
    std::thread::sleep(Duration::from_millis(100));
    for (session, id) in &mut pending {
        assert_eq!(env.resolve(id, false)["type"], "resolved");
        assert_eq!(session.event()["type"], "rejected");
    }
}

#[test]
fn execution_limits_and_disconnect_kill_the_actual_process() {
    let env = TestEnv::new();
    assert!(
        env.request("exec", command("/usr/bin/yes", &[]))["message"]
            .as_str()
            .unwrap()
            .contains("output limit")
    );
    let long = env.request("exec", command("/usr/bin/sleep", &["10"]));
    assert_eq!(long["type"], "submitted", "{long}");
    let long_id = long["request_id"].as_str().unwrap();
    assert_eq!(
        env.request("exec", json!({"method":"cancel","request_id":long_id}))["type"],
        "cancelled"
    );
    let marker = env.owned_workdir().join("child.pid");
    let (session, id) = env.pending(command(
        env.probe.to_str().unwrap(),
        &["sleep", marker.to_str().unwrap()],
    ));
    assert_eq!(env.resolve(&id, true)["type"], "resolved");
    wait_for(|| marker.exists());
    let pid: u32 = fs::read_to_string(marker).unwrap().parse().unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"status"}))["running"],
        1
    );
    drop(session);
    wait_for(|| !std::path::Path::new(&format!("/proc/{pid}")).exists());
    wait_for(|| env.request("admin", json!({"method":"status"}))["running"] == 0);
}

#[test]
fn commands_have_the_same_local_approval_authority_as_the_daemon_user() {
    let env = TestEnv::new();
    let event = env.approved_probe(&["approval", env.runtime.join("admin.sock").to_str().unwrap()]);
    assert_eq!(event["code"], 0, "{event}");
    assert_eq!(decoded(&event, "stdout"), b"approval accessible\n");
    let identity = env.approved_probe(&["identity"]);
    let actual: libzondtest::serde_json::Value =
        libzondtest::serde_json::from_slice(&decoded(&identity, "stdout")).unwrap();
    assert_eq!(actual["uid"], env.user.uid.as_raw());
    assert_eq!(
        actual["gid"],
        libzondtest::nix::unistd::Gid::effective().as_raw()
    );
    assert_eq!(
        actual["groups"],
        json!(
            libzondtest::nix::unistd::getgroups()
                .unwrap()
                .iter()
                .map(|g| g.as_raw())
                .collect::<Vec<_>>()
        )
    );
}

#[test]
fn binary_output_stderr_and_nonzero_exit_status_survive_protocol() {
    let env = TestEnv::new();
    let event = env.approved_probe(&["bytes"]);
    assert_eq!(event["code"], 7);
    assert_eq!(decoded(&event, "stdout"), [0, 255]);
    assert_eq!(decoded(&event, "stderr"), b"err");
}

#[test]
fn malformed_frames_cannot_spoof_identity_or_execute() {
    let env = TestEnv::new();
    for frame in [
        br#"{"version":1,"id":1,"body":{"method":"run","principal":"admin","command":{"program":"/usr/bin/id"}}}
"#.to_vec(),
        vec![b'x'; 64 * 1024 + 1],
    ] {
        let mut socket = UnixStream::connect(env.runtime.join("exec.sock")).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        libzondtest::handshake(&mut socket.try_clone().unwrap(), &mut socket);
        socket.write_all(&frame).unwrap();
        match socket.read(&mut [0]) {
            Ok(0) => {},
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {},
            other => panic!("expected closed connection: {other:?}"),
        }
    }
    assert!(env.queue().is_empty());
}

#[test]
fn restart_discards_pending_requests_and_disabled_approvals_fail_closed() {
    let env = TestEnv::new();
    let (session, id) = env.pending(command("/usr/bin/printf", &["restart"]));
    env.stop_daemon();
    assert!(!env.runtime.join("admin.sock").exists());
    drop(session);
    fs::write(
        &env.config,
        env.policy.replace("enabled = true", "enabled = false"),
    )
    .unwrap();
    env.start_daemon();
    assert!(env.queue().is_empty());
    assert_eq!(env.resolve(&id, true)["type"], "error");
    assert_eq!(
        env.request("exec", command("/usr/bin/printf", &["disabled"]))["type"],
        "rejected"
    );
    assert_eq!(
        env.request("exec", command("/usr/bin/id", &["-u"]))["code"],
        0
    );
    assert_eq!(
        env.request("exec", command("/usr/bin/false", &[]))["type"],
        "rejected"
    );
}

#[test]
fn runtime_and_sockets_are_private_to_the_daemon_user() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let env = TestEnv::new();
    for (path, mode) in [
        (env.runtime.clone(), 0o700),
        (env.runtime.join("admin.sock"), 0o600),
        (env.runtime.join("exec.sock"), 0o600),
    ] {
        let meta = fs::metadata(path).unwrap();
        assert_eq!(meta.uid(), env.user.uid.as_raw());
        assert_eq!(meta.permissions().mode() & 0o777, mode);
    }
    // Approval uses the same user's default XDG socket, without --socket or sudo.
    let result = checked(env.cli().arg("pending"), 0);
    let event: libzondtest::serde_json::Value =
        libzondtest::serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(event["type"], "queue");
}

#[test]
fn daemon_rejects_configuration_writable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;
    let env = TestEnv::new();
    fs::set_permissions(&env.config, fs::Permissions::from_mode(0o666)).unwrap();
    let result = checked(env.daemon_command().arg("serve"), 1);
    assert!(String::from_utf8_lossy(&result.stderr).contains("writable by other users"));
}

#[test]
#[ignore = "requires a running systemd user manager"]
fn shipped_user_service_runs_and_executes_as_the_current_user() {
    use std::{path::PathBuf, process::Command};
    struct Service {
        name: String,
        unit: PathBuf,
    }
    impl Drop for Service {
        fn drop(&mut self) {
            if std::thread::panicking() {
                let log = libzondtest::output(Command::new("journalctl").args([
                    "--user",
                    "-u",
                    &self.name,
                    "-n",
                    "30",
                    "--no-pager",
                ]));
                eprintln!("{}", String::from_utf8_lossy(&log.stdout));
            }
            let _ =
                libzondtest::output(Command::new("systemctl").args(["--user", "stop", &self.name]));
            let _ = libzondtest::output(Command::new("systemctl").args([
                "--user",
                "reset-failed",
                &self.name,
            ]));
            let _ = fs::remove_file(&self.unit);
            let _ =
                libzondtest::output(Command::new("systemctl").args(["--user", "daemon-reload"]));
        }
    }
    let env = TestEnv::new();
    env.stop_daemon();
    let runtime_base = PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR").expect("user runtime directory required"),
    );
    let name = env
        .dir
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .trim_start_matches('.');
    let runtime = runtime_base.join(name);
    let units = runtime_base.join("systemd/user");
    fs::create_dir_all(&units).unwrap();
    let service = Service {
        name: format!("{name}.service"),
        unit: units.join(format!("{name}.service")),
    };
    let contents = include_str!("../../zondd.service")
        .replace(
            "ExecStart=%h/.cargo/bin/zondd serve",
            &format!(
                "ExecStart={} serve\nEnvironment=XDG_CONFIG_HOME={}",
                env.daemon.display(),
                env.config.parent().unwrap().parent().unwrap().display()
            ),
        )
        .replace(
            "RuntimeDirectory=zondd",
            &format!("RuntimeDirectory={name}"),
        );
    fs::write(&service.unit, contents).unwrap();
    let policy = env.policy.replace(
        "operations = [\"greet\"]",
        "operations = [\"greet\", \"privileged\"]",
    ) + &format!(
        "\n[operations.privileged]\nprogram = {:?}\nfixed_args = [\"askpass\"]\ndecision = \"ask\"\nsudo_password = true\n",
        env.probe.display()
    );
    fs::write(
        &env.config,
        format!("runtime_dir = {:?}\n{policy}", runtime),
    )
    .unwrap();
    checked(
        Command::new("systemctl").args(["--user", "daemon-reload"]),
        0,
    );
    checked(
        Command::new("systemctl").args(["--user", "start", &service.name]),
        0,
    );
    libzondtest::wait_for(|| runtime.join("exec.sock").exists());
    checked(
        Command::new("systemctl").args(["--user", "is-active", &service.name]),
        0,
    );
    let result = checked(
        Command::new(&env.ctl)
            .arg("--socket")
            .arg(runtime.join("exec.sock"))
            .args(["exec", "/usr/bin/id", "-u"]),
        0,
    );
    assert_eq!(result.stdout, format!("{}\n", env.user.uid).as_bytes());
    let status = checked(
        Command::new(&env.ctl)
            .arg("--runtime-dir")
            .arg(&runtime)
            .arg("status"),
        0,
    );
    assert_eq!(
        libzondtest::serde_json::from_slice::<libzondtest::serde_json::Value>(&status.stdout)
            .unwrap()["type"],
        "status"
    );
    let mut session = libzondtest::Session::new(
        &runtime.join("exec.sock"),
        command(
            "/usr/bin/systemctl",
            &["--user", "is-active", &service.name],
        ),
    );
    let pending = session.event();
    assert_eq!(pending["type"], "pending");
    checked(
        Command::new(&env.ctl)
            .arg("--runtime-dir")
            .arg(&runtime)
            .arg("approve")
            .arg(pending["request"]["approval_id"].as_str().unwrap()),
        0,
    );
    let result = session.event();
    assert_eq!(result["code"], 0, "{result}");
    assert_eq!(decoded(&result, "stdout"), b"active\n");
    let mut privileged = libzondtest::Session::new(
        &runtime.join("ops.sock"),
        json!({"method":"invoke","operation":"privileged","args":[]}),
    );
    let pending = privileged.event();
    assert_eq!(pending["type"], "pending", "{pending}");
    let approved = libzondtest::Session::new(
        &runtime.join("admin.sock"),
        json!({"method":"resolve","approval_id":pending["request"]["approval_id"],"approve":true}),
    )
    .event();
    assert_eq!(approved["type"], "resolved");
    for password in ["test-password-one", "test-password-two"] {
        let mut id = None;
        wait_for(|| {
            id =
                libzondtest::Session::new(&runtime.join("admin.sock"), json!({"method":"pending"}))
                    .event()["credentials"]
                    .as_array()
                    .and_then(|items| items.first())
                    .and_then(|entry| entry["challenge_id"].as_str())
                    .map(str::to_owned);
            id.is_some()
        });
        let answer = libzondtest::Session::new(
            &runtime.join("admin.sock"),
            json!({"method":"credential","challenge_id":id,"password":password}),
        )
        .event();
        assert_eq!(answer["type"], "credential_answered", "{answer}");
    }
    let result = privileged.event();
    assert_eq!(result["code"], 0, "{result}");
    assert_eq!(decoded(&result, "stdout"), b"two prompts answered\n");
    let pid = || {
        checked(
            Command::new("systemctl").args([
                "--user",
                "show",
                "--property=MainPID",
                "--value",
                &service.name,
            ]),
            0,
        )
        .stdout
    };
    let original_pid = pid();
    let changed = format!(
        "runtime_dir = {:?}\n{}\n# live reload\n",
        runtime, env.policy
    );
    fs::write(&env.config, &changed).unwrap();
    checked(
        Command::new("systemctl").args(["--user", "reload", &service.name]),
        0,
    );
    wait_for(|| {
        let mut status =
            libzondtest::Session::new(&runtime.join("admin.sock"), json!({"method":"status"}));
        status.event()["revision"] == libzond::config::revision(&changed)
    });
    assert_eq!(pid(), original_pid);
    drop(service);
    assert!(
        !runtime.exists(),
        "systemd must clean up the service runtime directory"
    );
}
