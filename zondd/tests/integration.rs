use libzondtest::{TestEnv, checked, command, decoded, serde_json::json, wait_for};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::Command,
    time::Duration,
};

#[test]
#[ignore = "requires root; see the E2E Cargo runner in readme.md"]
fn policy_identity_and_operation_boundaries() {
    let env = TestEnv::new();
    checked(
        Command::new(&env.daemon)
            .arg("check")
            .arg("--config")
            .arg(&env.config),
        0,
    );
    checked(
        Command::new(&env.daemon)
            .arg("serve")
            .arg("--config")
            .arg(&env.config),
        1,
    );
    let event = env.request("exec", command("/usr/bin/id", &["-u"]));
    assert_eq!(
        decoded(&event, "stdout"),
        format!("{}\n", env.execution.uid).as_bytes()
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
#[ignore = "requires root"]
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
#[ignore = "requires root"]
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
#[ignore = "requires root"]
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
#[ignore = "requires root"]
fn execution_limits_and_disconnect_kill_the_actual_process() {
    let env = TestEnv::new();
    assert!(
        env.request("exec", command("/usr/bin/yes", &[]))["message"]
            .as_str()
            .unwrap()
            .contains("output limit")
    );
    assert!(
        env.request("exec", command("/usr/bin/sleep", &["10"]))["message"]
            .as_str()
            .unwrap()
            .contains("timed out")
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
#[ignore = "requires root"]
fn approved_children_cannot_reach_control_sockets() {
    let env = TestEnv::new();
    for name in ["admin.sock", "exec.sock"] {
        let event = env.approved_probe(&["socket", env.runtime.join(name).to_str().unwrap()]);
        assert_eq!(event["code"], 0, "{event}");
        assert_eq!(decoded(&event, "stdout"), b"permission denied\n");
    }
}

#[test]
#[ignore = "requires root"]
fn binary_output_stderr_and_nonzero_exit_status_survive_protocol() {
    let env = TestEnv::new();
    let event = env.approved_probe(&["bytes"]);
    assert_eq!(event["code"], 7);
    assert_eq!(decoded(&event, "stdout"), [0, 255]);
    assert_eq!(decoded(&event, "stderr"), b"err");
}

#[test]
#[ignore = "requires root"]
fn malformed_frames_cannot_spoof_identity_or_execute() {
    let env = TestEnv::new();
    for frame in [
        br#"{"version":99,"id":1,"body":{"method":"status"}}
"#.to_vec(),
        br#"{"version":1,"id":1,"body":{"method":"run","principal":"admin","command":{"program":"/usr/bin/id"}}}
"#.to_vec(),
        vec![b'x'; 64 * 1024 + 1],
    ] {
        let mut socket = UnixStream::connect(env.runtime.join("exec.sock")).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
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
#[ignore = "requires root"]
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
}
