use libzondtest::{
    Process, SshEnv, TestEnv, checked, read_json,
    serde_json::{Value, json},
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

fn connect(env: &TestEnv) -> UnixStream {
    let socket = UnixStream::connect(env.runtime.join("exec.sock")).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
}

fn send(socket: &mut UnixStream, value: Value) -> Value {
    writeln!(socket, "{value}").unwrap();
    read_json(socket)
}

#[test]
fn diagnostics_are_optional_and_unknown_extensions_cannot_grant_authority() {
    let env = TestEnv::new();
    let mut socket = connect(&env);
    let welcome = send(
        &mut socket,
        json!({"handshake":1,"protocols":[2],"capabilities":["future-diagnostics"]}),
    );
    assert_eq!(welcome["protocol"], 2);
    assert_eq!(welcome["capabilities"], json!([]));
    let response = send(
        &mut socket,
        json!({"version":1,"id":9,"body":{"method":"status"},"extensions":{"future-diagnostics":{"principal":"admin","approve":true}}}),
    );
    assert_eq!(response["body"]["type"], "rejected", "{response}");
    assert!(
        response["body"]["reason"]
            .as_str()
            .unwrap()
            .contains("admin")
    );

    let mut socket = connect(&env);
    send(
        &mut socket,
        json!({"handshake":1,"protocols":[2],"capabilities":[]}),
    );
    let response = send(
        &mut socket,
        json!({"version":1,"id":10,"body":{"method":"permissions"},"extensions":{"future-diagnostics":{"anything":true}}}),
    );
    assert_eq!(response["body"]["type"], "permissions", "{response}");
}

#[test]
fn unnegotiated_requests_versions_and_diagnostics_fail_before_dispatch() {
    let env = TestEnv::new();
    let mut old = connect(&env);
    let response = send(
        &mut old,
        json!({"version":1,"id":19,"body":{"method":"future-destructive-command"},"client":{"name":"old-client","version":"old"}}),
    );
    assert_eq!(response["id"], 19);
    assert_eq!(response["body"]["type"], "error");
    assert!(
        response["body"]["message"]
            .as_str()
            .unwrap()
            .contains("protocol negotiation required")
    );
    for (handshake, protocols) in [(1, vec![999]), (999, vec![2])] {
        let mut stream = connect(&env);
        let response = send(
            &mut stream,
            json!({"handshake":handshake,"protocols":protocols,"capabilities":[]}),
        );
        assert!(response["protocol"].is_null());
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("incompatible command protocol")
        );
    }
    let mut stream = connect(&env);
    send(
        &mut stream,
        json!({"handshake":1,"protocols":[2],"capabilities":[]}),
    );
    let response = send(
        &mut stream,
        json!({"version":1,"id":1,"body":{"method":"permissions"},"extensions":{"client":{"name":"unnegotiated","version":"1"}}}),
    );
    assert_eq!(response["body"]["type"], "error");
    assert!(
        response["body"]["message"]
            .as_str()
            .unwrap()
            .contains("not negotiated")
    );
    assert!(env.queue().is_empty());
}

#[test]
fn negotiated_commands_still_reject_unknown_and_duplicate_authority_fields() {
    let env = TestEnv::new();
    for frame in [
        r#"{"version":1,"id":1,"body":{"method":"permissions"},"principal":"admin"}"#,
        r#"{"version":1,"id":1,"body":{"method":"permissions","principal":"admin"}}"#,
        r#"{"version":1,"id":1,"body":{"method":"permissions","method":"status"}}"#,
        r#"{"version":1,"id":1,"body":{"method":"permissions"},"actor":null,"actor":null}"#,
        r#"{"handshake":1,"protocols":[2],"capabilities":[]}"#,
    ] {
        let mut stream = connect(&env);
        libzondtest::handshake(&mut stream.try_clone().unwrap(), &mut stream);
        writeln!(stream, "{frame}").unwrap();
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }
    let mut stream = connect(&env);
    libzondtest::handshake(&mut stream.try_clone().unwrap(), &mut stream);
    let response = send(
        &mut stream,
        json!({"version":999,"id":1,"body":{"method":"permissions"}}),
    );
    assert_eq!(response["body"]["type"], "error");
    assert!(env.queue().is_empty());
}

#[test]
fn stalled_handshake_times_out_without_sending_a_command() {
    let env = TestEnv::new();
    let path = env.dir.path().join("stalled.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        read_json(&mut socket);
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    });
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let error = libzondctl::Client::local(&path)
            .await
            .unwrap()
            .send(libzond::Request::Status)
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("protocol handshake timeout"), "{message}");
        assert!(message.contains("restart zondd.service"), "{message}");
    });
    peer.join().unwrap();
}

#[test]
fn failed_handshakes_never_send_or_retry_the_command() {
    let env = TestEnv::new();
    for response in [
        None,
        Some(
            json!({"handshake":1,"protocol":999,"capabilities":[],"peer":{"name":"test","version":"1"},"error":null}),
        ),
        Some(
            json!({"handshake":1,"protocol":2,"capabilities":["unoffered"],"peer":{"name":"test","version":"1"},"error":null}),
        ),
    ] {
        let path = env.dir.path().join("fault.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let hello = read_json(&mut socket);
            assert_eq!(hello["protocols"], json!([2]));
            assert!(hello.get("body").is_none());
            if let Some(response) = response {
                writeln!(socket, "{response}").unwrap();
                let mut byte = [0];
                assert_eq!(
                    socket.read(&mut byte).unwrap(),
                    0,
                    "command sent after failed negotiation"
                );
            }
            listener.set_nonblocking(true).unwrap();
            assert!(
                listener.accept().is_err(),
                "client reconnected after failed negotiation"
            );
        });
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut client = libzondctl::Client::local(&path).await.unwrap();
            let error = client
                .send(libzond::Request::Run {
                    command: libzond::Command {
                        program: "/usr/bin/touch".into(),
                        args: vec![
                            env.dir
                                .path()
                                .join("should-not-exist")
                                .display()
                                .to_string(),
                        ],
                    },
                    cwd: None,
                })
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("protocol negotiation"));
            assert!(
                client
                    .send(libzond::Request::Status)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("one request")
            );
        });
        peer.join().unwrap();
        fs::remove_file(path).unwrap();
    }
    assert!(!env.dir.path().join("should-not-exist").exists());
}

#[test]
fn client_omits_diagnostics_when_the_peer_does_not_offer_them() {
    let env = TestEnv::new();
    let path = env.dir.path().join("no-diagnostics.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_json(&mut socket);
        writeln!(socket, "{}", json!({"handshake":1,"protocol":2,"capabilities":[],"peer":{"name":"test","version":"1"},"error":null})).unwrap();
        let request = read_json(&mut socket);
        assert!(request.get("extensions").is_none(), "{request}");
        assert_eq!(request["body"]["method"], "status");
        writeln!(socket, "{}", json!({"version":1,"id":1,"body":{"type":"status","pending":0,"running":0,"revision":"test"}})).unwrap();
    });
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let event = libzondctl::Client::local(&path)
            .await
            .unwrap()
            .request(libzond::Request::Status)
            .await
            .unwrap();
        assert!(matches!(event, libzond::Event::Status { .. }));
    });
    peer.join().unwrap();
}

#[test]
fn bridge_only_advertises_daemon_capabilities_and_always_binds_transport() {
    let env = TestEnv::new();
    let runtime = env.dir.path().join("capability-peer");
    fs::create_dir(&runtime).unwrap();
    let listener = UnixListener::bind(runtime.join("exec.sock")).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let hello = read_json(&mut socket);
        assert_eq!(hello["capabilities"], json!(["client-info"]));
        writeln!(socket, "{}", json!({"handshake":1,"protocol":2,"capabilities":[],"peer":{"name":"test","version":"1"},"error":null})).unwrap();
        let request = read_json(&mut socket);
        assert!(request.get("extensions").is_none(), "{request}");
        assert_eq!(
            request["transport"]["evidence"],
            "forced_command_key_binding"
        );
        assert_eq!(
            request["transport"]["ssh_key_fingerprint"],
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        writeln!(
            socket,
            "{}",
            json!({"version":1,"id":1,"body":{"type":"error","message":"test response"}})
        )
        .unwrap();
    });
    let mut bridge = Process::spawn(
        env.daemon_command()
            .args(["bridge", "--runtime-dir"])
            .arg(runtime)
            .args([
                "--principal",
                "exec",
                "--key-fingerprint",
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    writeln!(
        bridge.child.stdin.as_mut().unwrap(),
        "{}",
        json!({"handshake":1,"protocols":[2],"capabilities":["client-info","future-capability"]})
    )
    .unwrap();
    let welcome = read_json(bridge.child.stdout.as_mut().unwrap());
    assert_eq!(welcome["protocol"], 2);
    assert_eq!(welcome["capabilities"], json!([]));
    writeln!(bridge.child.stdin.as_mut().unwrap(), "{}", json!({"version":1,"id":1,"body":{"method":"permissions"},"transport":{"evidence":"forged","ssh_key_fingerprint":"forged"}})).unwrap();
    assert_eq!(
        read_json(bridge.child.stdout.as_mut().unwrap())["body"]["message"],
        "test response"
    );
    assert!(bridge.wait(Duration::from_secs(5)).success());
    peer.join().unwrap();
}

fn replace_program(command: Command, program: &Path) -> Command {
    let mut replacement = Command::new(program);
    replacement.args(command.get_args());
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            replacement.env(key, value);
        } else {
            replacement.env_remove(key);
        }
    }
    replacement
}

fn assert_upgrade(command: &mut Command) {
    let output = checked(command, 125);
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("protocol negotiation"), "{error}");
    assert!(error.contains("restart zondd.service"), "{error}");
}

#[test]
#[ignore = "requires OpenSSH and ZONDD_OLD_BIN/ZONDCTL_OLD_BIN pre-negotiation binaries"]
fn real_pre_negotiation_binaries_fail_clearly_in_both_directions_and_at_the_bridge() {
    let old_daemon = std::env::var_os("ZONDD_OLD_BIN").expect("ZONDD_OLD_BIN");
    let old_cli = std::env::var_os("ZONDCTL_OLD_BIN").expect("ZONDCTL_OLD_BIN");
    let ssh = SshEnv::new();
    assert_upgrade(replace_program(ssh.env.cli(), Path::new(&old_cli)).arg("status"));
    assert_upgrade(replace_program(ssh.remote("exec"), Path::new(&old_cli)).arg("permissions"));

    let keys = ssh.env.dir.path().join("authorized_keys");
    let original_keys = fs::read_to_string(&keys).unwrap();
    fs::write(
        &keys,
        original_keys.replace(
            &ssh.env.daemon.display().to_string(),
            &Path::new(&old_daemon).display().to_string(),
        ),
    )
    .unwrap();
    assert_upgrade(ssh.remote("exec").arg("permissions"));

    let bridge = ssh.env.dir.path().join("new-bridge");
    fs::copy(&ssh.env.daemon, &bridge).unwrap();
    fs::write(
        &keys,
        original_keys.replace(
            &ssh.env.daemon.display().to_string(),
            &bridge.display().to_string(),
        ),
    )
    .unwrap();
    ssh.env.stop_daemon();
    fs::copy(old_daemon, &ssh.env.daemon).unwrap();
    ssh.env.start_daemon();
    assert_upgrade(ssh.env.cli().arg("status"));
    assert_upgrade(ssh.remote("exec").arg("permissions"));

    let mut control = Process::spawn(
        ssh.env
            .cli()
            .arg("control")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    writeln!(
        control.child.stdin.as_mut().unwrap(),
        "{}",
        json!({"version":1,"method":"status"})
    )
    .unwrap();
    let result = read_json(control.child.stdout.as_mut().unwrap());
    assert_eq!(result["ok"], false);
    assert!(
        result["error"]
            .as_str()
            .unwrap()
            .contains("protocol negotiation"),
        "{result}"
    );
    assert_eq!(control.wait(Duration::from_secs(5)).code(), Some(125));
}
