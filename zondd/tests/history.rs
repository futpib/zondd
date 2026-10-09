use libzondtest::{
    TestEnv, command, decoded,
    serde_json::{Value, json},
    wait_for,
};
use std::{fs, os::unix::fs::MetadataExt};
fn records(env: &TestEnv) -> Vec<Value> {
    env.request("admin", json!({"method":"history"}))["requests"]
        .as_array()
        .unwrap()
        .clone()
}
fn detail(env: &TestEnv, id: &str) -> Value {
    env.request("admin", json!({"method":"request_detail","request_id":id}))
}
fn terminal(env: &TestEnv, id: &str) -> Value {
    wait_for(|| {
        let r = detail(env, id);
        !["received", "pending", "approved", "allowed", "running"]
            .contains(&r["request"]["status"].as_str().unwrap())
    });
    detail(env, id)
}

#[test]
fn all_outcomes_are_durable_with_output_and_action_history() {
    let env = TestEnv::new();
    env.request("exec", command("/usr/bin/id", &["-u"]));
    env.request("exec", command("/usr/bin/false", &[]));
    let (mut caller, id) = env.pending(command("/usr/bin/printf", &["denied"]));
    env.resolve(&id, false);
    assert_eq!(caller.event()["type"], "rejected");
    let (mut caller, _) = env.pending(command("/usr/bin/printf", &["expired"]));
    assert_eq!(caller.event()["type"], "rejected");
    let (caller, _) = env.pending(command("/usr/bin/printf", &["cancelled"]));
    let cancelled = env.queue()[0]["request_id"].as_str().unwrap().to_owned();
    drop(caller);
    assert_eq!(terminal(&env, &cancelled)["request"]["status"], "cancelled");
    env.request(
        "ops",
        json!({"method":"invoke","operation":"greet","args":["invalid"]}),
    );
    env.approved_probe(&["bytes"]);
    let history = records(&env);
    for status in [
        "completed",
        "rejected",
        "denied",
        "expired",
        "cancelled",
        "failed",
    ] {
        assert!(
            history.iter().any(|r| r["status"] == status),
            "missing {status}: {history:?}"
        );
    }
    let id = history[0]["request_id"].as_str().unwrap();
    let record = detail(&env, id);
    assert_eq!(record["request"]["result"]["code"], 7);
    assert_eq!(decoded(&record["request"]["result"], "stdout"), [0, 255]);
    assert!(
        record["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "approval_granted")
    );
    assert_eq!(
        fs::metadata(env.config.with_extension("history.sqlite3"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    let (caller, _) = env.pending(command("/usr/bin/printf", &["restart"]));
    let interrupted = env.queue()[0]["request_id"].as_str().unwrap().to_owned();
    env.stop_daemon();
    drop(caller);
    env.start_daemon();
    assert_eq!(
        detail(&env, &interrupted)["request"]["status"],
        "interrupted"
    );
    assert_eq!(detail(&env, id)["request"]["result"]["code"], 7);
    let page = env.request("admin", json!({"method":"history","limit":1}));
    let next = env.request(
        "admin",
        json!({"method":"history","limit":1,"before":page["next_before"]}),
    );
    assert_ne!(
        page["requests"][0]["request_id"],
        next["requests"][0]["request_id"]
    );
    assert_eq!(
        env.request("exec", json!({"method":"history"}))["type"],
        "rejected"
    );
}

#[test]
fn retry_creates_a_new_request_and_does_not_reuse_approval() {
    let env = TestEnv::new();
    let (mut caller, id) = env.pending(command("/usr/bin/printf", &["manual"]));
    let original = env.queue()[0]["request_id"].as_str().unwrap().to_owned();
    env.resolve(&id, true);
    caller.event();
    let retry = env.request("admin", json!({"method":"retry","request_id":original}));
    let new_id = retry["request_id"].as_str().unwrap();
    assert_ne!(new_id, original);
    wait_for(|| !env.queue().is_empty());
    let fresh = env.queue()[0].clone();
    assert_ne!(fresh["approval_id"], id);
    assert_eq!(fresh["request_id"], new_id);
    assert_eq!(detail(&env, new_id)["request"]["retry_of"], original);
    assert_eq!(env.resolve(&id, true)["type"], "error");
    env.resolve(fresh["approval_id"].as_str().unwrap(), false);
    assert_eq!(terminal(&env, new_id)["request"]["status"], "denied");
    assert_eq!(
        env.request("exec", json!({"method":"retry","request_id":original}))["type"],
        "rejected"
    );
}

#[test]
fn retry_reexpands_original_operation_under_current_policy() {
    let env = TestEnv::new();
    env.request(
        "ops",
        json!({"method":"invoke","operation":"greet","args":["world"]}),
    );
    let original = records(&env)[0]["request_id"].as_str().unwrap().to_owned();
    fs::write(&env.config, env.policy.replace("hello %s", "new %s")).unwrap();
    env.request("admin", json!({"method":"reload"}));
    let retry = env.request("admin", json!({"method":"retry","request_id":original}));
    let record = terminal(&env, retry["request_id"].as_str().unwrap());
    assert_eq!(
        decoded(&record["request"]["result"], "stdout"),
        b"new world"
    );
    assert_eq!(record["request"]["input"]["method"], "invoke");
    let actions = env.request("admin", json!({"method":"actions","limit":100}));
    for action in [
        "daemon_started",
        "request_received",
        "policy_reloaded",
        "execution_started",
        "request_finished",
    ] {
        assert!(
            actions["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["action"] == action),
            "missing {action}"
        );
    }
}

#[test]
fn large_requests_and_long_action_trails_remain_pageable() {
    let env = TestEnv::new();
    let payload = "x".repeat(60_000);
    for _ in 0..20 {
        assert_eq!(
            env.request("exec", command("/usr/bin/false", &[&payload]))["type"],
            "rejected"
        );
    }
    let mut before = Value::Null;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let page = env.request(
            "admin",
            json!({"method":"history","limit":30,"before":before}),
        );
        assert_eq!(page["type"], "history", "{page}");
        for request in page["requests"].as_array().unwrap() {
            assert!(seen.insert(request["request_id"].as_str().unwrap().to_owned()));
        }
        before = page["next_before"].clone();
        if before.is_null() {
            break;
        }
    }
    assert_eq!(seen.len(), 20);
    let policy = env.policy.replace("timeout_secs = 4", "timeout_secs = 120");
    fs::write(&env.config, &policy).unwrap();
    env.request("admin", json!({"method":"reload"}));
    let (caller, _) = env.pending(command("/usr/bin/printf", &[&payload]));
    let id = env.queue()[0]["request_id"].as_str().unwrap().to_owned();
    for i in 0..35 {
        fs::write(&env.config, format!("{policy}\n# {i}")).unwrap();
        env.request("admin", json!({"method":"reload"}));
    }
    let first = detail(&env, &id);
    assert_eq!(first["type"], "request_detail");
    assert!(first["actions"].as_array().unwrap().len() < 30);
    let mut actions = first["actions"].as_array().unwrap().clone();
    let mut before = first["next_before"].clone();
    while !before.is_null() {
        let page = env.request(
            "admin",
            json!({"method":"actions","request_id":id,"before":before,"limit":100}),
        );
        assert_eq!(page["type"], "actions");
        actions.extend(page["actions"].as_array().unwrap().clone());
        before = page["next_before"].clone();
    }
    assert_eq!(
        actions
            .iter()
            .filter(|a| a["action"] == "policy_re_evaluated")
            .count(),
        35
    );
    assert!(actions.iter().all(|a| a["request_id"] == id));
    drop(caller);
}
