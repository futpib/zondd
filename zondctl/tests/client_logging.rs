use libzondtest::{
    Process, SshEnv, TestEnv, checked, read_json,
    serde_json::{Value, json},
    wait_for,
};
use std::{fs, io::Write, os::unix::net::UnixStream, process::Stdio, time::Duration};

fn log(env: &TestEnv) -> String {
    fs::read_to_string(env.dir.path().join("daemon.log")).unwrap()
}

fn control(env: &TestEnv, request: Value) -> Value {
    let mut process = Process::spawn(
        env.cli()
            .args(["control", "--config"])
            .arg(&env.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    writeln!(process.child.stdin.as_mut().unwrap(), "{request}").unwrap();
    let response = read_json(process.child.stdout.as_mut().unwrap());
    process.wait(Duration::from_secs(5));
    response
}

#[test]
fn local_clients_report_versions_and_missing_metadata_is_explicit() {
    let env = TestEnv::new();
    checked(env.cli().arg("status"), 0);
    assert_eq!(
        env.request("admin", json!({"method":"status"}))["type"],
        "status"
    );
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        libzondctl::Client::local(&env.runtime.join("admin.sock"))
            .await
            .unwrap()
            .request(libzond::Request::Status)
            .await
            .unwrap();
    });
    wait_for(|| {
        log(&env).lines().any(|line| {
            line.contains("client_name=\"libzondctl\"") && line.contains("client disconnected")
        })
    });
    let text = log(&env);
    for name in ["zondctl", "libzondctl", "unknown"] {
        let line = text
            .lines()
            .find(|line| {
                line.contains("client identified")
                    && line.contains(&format!("client_name={name:?}"))
            })
            .unwrap();
        let version = if name == "unknown" {
            "unknown"
        } else {
            libzond::BUILD_VERSION
        };
        assert!(
            line.contains(&format!("client_version={version:?}")),
            "{line}"
        );
        for field in [
            "connection_id=",
            "uid=",
            "pid=",
            "role=\"admin\"",
            "protocol=1",
            "method=\"status\"",
        ] {
            assert!(line.contains(field), "{line}");
        }
    }
    assert!(
        text.contains("client connected")
            && text.contains("client request finished")
            && text.contains("elapsed_ms=")
    );
}

#[test]
fn control_forwards_app_version_including_audit_polls_without_new_audit_events() {
    let env = TestEnv::new();
    let before = control(&env, json!({"version":1,"method":"audit_snapshot"}));
    let through = &before["result"]["checkpoint"]["sequence"];
    for method in ["status", "audit_snapshot", "audit_page"] {
        let mut request = json!({"version":1,"method":method,"client":{"name":"zond-android","version":"26.10.24.17.30+42"}});
        if method == "audit_page" {
            request["after"] = json!(0);
            request["through"] = through.clone();
        }
        let result = control(&env, request);
        assert_eq!(result["ok"], true, "{result}");
        let text = log(&env);
        let line = text
            .lines()
            .find(|line| {
                line.contains("client identified")
                    && line.contains(&format!("method={method:?}"))
                    && line.contains("client_name=\"zond-android\"")
            })
            .unwrap();
        assert!(
            line.contains("client_version=\"26.10.24.17.30+42\""),
            "{line}"
        );
        assert!(line.contains("via_name=\"zondctl control\""), "{line}");
        assert!(
            line.contains(&format!("via_version={:?}", libzond::BUILD_VERSION)),
            "{line}"
        );
    }
    let after = control(&env, json!({"version":1,"method":"audit_snapshot"}));
    assert_eq!(
        before["result"]["checkpoint"],
        after["result"]["checkpoint"]
    );
}

#[test]
fn diagnostic_labels_are_escaped_and_bounded_and_credentials_stay_private() {
    let env = TestEnv::new();
    let response = control(
        &env,
        json!({"version":1,"method":"credential","challenge_id":"missing","password":"DO-NOT-LOG-THIS-PASSWORD","client":{"name":"client\nforged\u{001b}","version":"v".repeat(500)}}),
    );
    assert_eq!(response["ok"], false);
    let text = log(&env);
    let line = text
        .lines()
        .find(|line| line.contains("client identified"))
        .unwrap();
    assert!(line.contains("client\\nforged\\u{1b}"), "{line}");
    assert!(
        line.contains(&format!("client_version={:?}", "v".repeat(128))),
        "{line}"
    );
    assert!(!text.contains(&"v".repeat(129)));
    assert!(!text.contains("DO-NOT-LOG-THIS-PASSWORD"));
    assert!(text.contains("outcome=\"error\""));
    assert!(!text.contains('\u{001b}'));
    let mut socket = UnixStream::connect(env.runtime.join("admin.sock")).unwrap();
    socket.write_all(b"invalid\n").unwrap();
    wait_for(|| log(&env).contains("outcome=\"failed\""));
}

#[test]
#[ignore = "requires OpenSSH server"]
fn ssh_bridge_preserves_client_and_sets_its_own_build_version() {
    let ssh = SshEnv::new();
    checked(ssh.remote("exec").arg("permissions"), 0);
    let mut process = Process::spawn(ssh.ssh().stdin(Stdio::piped()).stdout(Stdio::piped()));
    writeln!(process.child.stdin.as_mut().unwrap(), "{}", json!({"version":1,"id":7,"body":{"method":"permissions"},"client":{"name":"test-peer","version":"test-build"},"via":{"name":"forged-helper","version":"forged-version"}})).unwrap();
    assert_eq!(
        read_json(process.child.stdout.as_mut().unwrap())["body"]["type"],
        "permissions"
    );
    assert!(process.wait(Duration::from_secs(5)).success());
    let text = log(&ssh.env);
    for name in ["zondctl", "test-peer"] {
        let line = text
            .lines()
            .find(|line| {
                line.contains("client identified")
                    && line.contains(&format!("client_name={name:?}"))
            })
            .unwrap();
        assert!(line.contains("via_name=\"zondd bridge\""), "{line}");
        assert!(
            line.contains(&format!("via_version={:?}", libzond::BUILD_VERSION)),
            "{line}"
        );
        assert!(line.contains("principal=\"exec\""), "{line}");
    }
    assert!(!text.contains("forged-helper") && !text.contains("forged-version"));
}
