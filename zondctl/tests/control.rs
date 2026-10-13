use libzondtest::{
    Process, TestEnv, command, read_json,
    serde_json::{Value, json},
};
use std::{io::Write, process::Stdio, time::Duration};

fn control(env: &TestEnv, request: Value) -> Value {
    let mut child = Process::spawn(
        env.cli()
            .arg("control")
            .arg("--config")
            .arg(&env.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let mut stdin = child.child.stdin.take().unwrap();
    writeln!(stdin, "{request}").unwrap();
    let reply = read_json(child.child.stdout.as_mut().unwrap());
    // SSH callers need not close stdin for the helper to exit.
    child.wait(Duration::from_secs(5));
    reply
}

#[test]
fn audit_polls_do_not_create_events_and_offline_edits_remain_exportable() {
    let env = TestEnv::new();
    let before = control(&env, json!({"version":1,"method":"audit_snapshot"}));
    assert_eq!(before["ok"], true, "{before}");
    for method in ["pending", "status", "actions", "history", "audit_snapshot"] {
        assert_eq!(
            control(&env, json!({"version":1,"method":method}))["ok"],
            true
        );
    }
    let after = control(&env, json!({"version":1,"method":"audit_snapshot"}));
    assert_eq!(
        before["result"]["checkpoint"],
        after["result"]["checkpoint"]
    );
    env.stop_daemon();
    let offline = control(&env, json!({"version":1,"method":"audit_snapshot"}));
    assert_eq!(offline["result"]["daemon_online"], false);
    let original = control(&env, json!({"version":1,"method":"read_config"}));
    let changed = format!("{}\n# offline edit\n", env.policy);
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"save_config","content":changed,"revision":original["result"]["revision"]})
        )["ok"],
        true
    );
    let invalid = "runtime_dir = \"DO-NOT-LOG-POLICY-VALUE";
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"validate_config","content":invalid})
        )["ok"],
        false
    );
    let snapshot = control(&env, json!({"version":1,"method":"audit_snapshot"}));
    assert_eq!(snapshot["result"]["daemon_online"], false);
    let through = &snapshot["result"]["checkpoint"]["sequence"];
    let page = control(
        &env,
        json!({"version":1,"method":"audit_page","after":0,"through":through,"limit":100}),
    );
    assert_eq!(page["ok"], true, "{page}");
    let text = page.to_string();
    assert!(text.contains("control.save_config_requested") && text.contains("control.save_config"));
    assert!(text.contains("control.validate_config") && text.contains("operation_failed"));
    assert!(!text.contains("DO-NOT-LOG-POLICY-VALUE"));
    let saved = page["result"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["action"] == "control.save_config")
        .unwrap();
    let operation = saved["detail"]["actor"]["operation_id"].as_str().unwrap();
    let history = libzond::history::History::open(&env.config).unwrap();
    let linked = history
        .filtered_actions(None, None, 100, None, Some(operation), false)
        .unwrap();
    assert_eq!(linked.len(), 2);
    assert_eq!(linked[0].action, "control.save_config");
    assert_eq!(linked[1].action, "control.save_config_requested");
    let bundle = json!({"format":"zondd-audit-export","version":1,"checkpoint":snapshot["result"]["checkpoint"],"legacy_through_sequence":snapshot["result"]["legacy_through_sequence"],"range":{"after":0,"through":through},"events":page["result"]["actions"],"device_receipts":[]});
    libzond::audit::verify_export(&bundle, None).unwrap();
    env.start_daemon();
    assert!(
        control(
            &env,
            json!({"version":1,"method":"actions","query":"offline edit"})
        )["result"]["actions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn exported_audit_is_verified_locally_and_rejects_altered_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit.json");
    let checkpoint = dir.path().join("checkpoint.json");
    let fixture = include_str!("../../testdata/audit-v1.json");
    std::fs::write(&file, fixture).unwrap();
    let mut value: Value = serde_json::from_str(fixture).unwrap();
    std::fs::write(&checkpoint, value["checkpoint"].to_string()).unwrap();
    let output = libzondtest::checked(
        std::process::Command::new(env!("CARGO_BIN_EXE_zondctl"))
            .arg("--socket")
            .arg(dir.path().join("no-daemon.sock"))
            .arg("verify-audit")
            .arg(&file)
            .arg("--checkpoint")
            .arg(&checkpoint),
        0,
    );
    let verified: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verified["external_checkpoint_matched"], true);
    value["events"][0]["detail"]["principal"] = json!("forged");
    std::fs::write(&file, value.to_string()).unwrap();
    libzondtest::checked(
        std::process::Command::new(env!("CARGO_BIN_EXE_zondctl"))
            .arg("verify-audit")
            .arg(&file),
        125,
    );
}

#[test]
fn management_resolves_requests_and_rejects_stale_or_invalid_configuration() {
    let env = TestEnv::new();
    for approve in [true, false] {
        let (mut caller, id) = env.pending(command("/usr/bin/printf", &["%s", "manage"]));
        let queue = control(&env, json!({"version":1,"method":"pending"}));
        assert_eq!(queue["result"]["requests"][0]["approval_id"], id, "{queue}");
        assert_eq!(
            control(
                &env,
                json!({"version":1,"method":"resolve","approval_id":id,"approve":approve})
            )["ok"],
            true
        );
        assert_eq!(
            caller.event()["type"],
            if approve { "completed" } else { "rejected" }
        );
    }
    let original = control(&env, json!({"version":1,"method":"read_config"}));
    let revision = &original["result"]["revision"];
    let changed = format!("{}\n# saved by test\n", env.policy);
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"save_config","content":"invalid","revision":revision})
        )["ok"],
        false
    );
    assert_eq!(std::fs::read_to_string(&env.config).unwrap(), env.policy);
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"save_config","content":changed,"revision":revision})
        )["ok"],
        true
    );
    let stale = control(
        &env,
        json!({"version":1,"method":"save_config","content":env.policy,"revision":revision}),
    );
    assert!(stale["error"].as_str().unwrap().contains("changed"));
    assert_eq!(std::fs::read_to_string(&env.config).unwrap(), changed);
    assert_eq!(
        env.request("admin", json!({"method":"status"}))["revision"],
        *revision
    );
    let stale_reload = control(
        &env,
        json!({"version":1,"method":"reload_config","revision":revision}),
    );
    assert!(stale_reload["error"].as_str().unwrap().contains("changed"));
    let saved = control(&env, json!({"version":1,"method":"read_config"}));
    let applied = control(
        &env,
        json!({"version":1,"method":"reload_config","revision":saved["result"]["revision"]}),
    );
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["result"]["revision"], saved["result"]["revision"]);
    assert_eq!(
        env.request("admin", json!({"method":"status"}))["revision"],
        saved["result"]["revision"]
    );
    assert_eq!(
        control(&env, json!({"version":1,"method":"pending","unknown":true}))["ok"],
        false
    );
    assert_eq!(
        control(&env, json!({"version":99,"method":"pending"}))["ok"],
        false
    );
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"service","action":"arbitrary-shell-command"})
        )["ok"],
        false
    );
}

#[test]
fn local_principal_runs_the_same_caller_protocol() {
    let env = TestEnv::new();
    assert_eq!(
        libzondtest::checked(
            env.cli()
                .args(["--principal", "ops", "invoke", "greet", "world"]),
            0
        )
        .stdout,
        b"hello world"
    );
    libzondtest::checked(env.cli().args(["--principal", "ops", "pending"]), 126);
    libzondtest::checked(env.cli().args(["--principal", "../admin", "pending"]), 125);
}

#[test]
fn history_search_passes_through_management_and_cli() {
    let env = TestEnv::new();
    env.request(
        "exec",
        libzondtest::command("/usr/bin/false", &["searchable-marker"]),
    );
    for method in ["history", "actions"] {
        let page = control(
            &env,
            json!({"version":1,"method":method,"query":"searchable-marker","limit":1}),
        );
        assert_eq!(page["ok"], true, "{page}");
        let rows = if method == "history" {
            "requests"
        } else {
            "actions"
        };
        assert_eq!(page["result"][rows].as_array().unwrap().len(), 1);
        let output = libzondtest::checked(
            env.cli()
                .args([method, "--query", "searchable-marker", "--limit", "1"]),
            0,
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("searchable-marker"));
    }
}

#[test]
fn missing_policy_is_editable_without_creating_it_on_read() {
    let env = TestEnv::new();
    std::fs::remove_file(&env.config).unwrap();
    let result = control(&env, json!({"version":1,"method":"read_config"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["revision"], libzond::config::revision(""));
    let content = result["result"]["content"].as_str().unwrap();
    assert!(
        libzond::config::Config::parse(content)
            .unwrap()
            .approvals
            .enabled
    );
    assert!(!env.config.exists());
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"save_config","content":content,"revision":result["result"]["revision"]})
        )["ok"],
        true
    );
    assert!(env.config.exists());
}
