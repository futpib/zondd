use libzondtest::{
    TestEnv, checked, command,
    serde_json::{Value, json},
    wait_for,
};
use std::fs;

const RULE: &str = "rule echo-rule(x: repository-name) { run printf '%s' \"$x\" }";

fn env() -> TestEnv {
    let env = TestEnv::new();
    fs::write(
        &env.config,
        env.policy.replace("timeout_secs = 4", "timeout_secs = 60"),
    )
    .unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    env
}

fn propose(env: &TestEnv) -> Value {
    let event = env.request("exec", json!({"method":"propose_rule","source":RULE}));
    assert_eq!(event["type"], "rule_proposed", "{event}");
    event["proposal"].clone()
}

fn withdraw(env: &TestEnv, principal: &str, id: &Value) -> Value {
    env.request(principal, json!({"method":"withdraw","id":id}))
}

fn approve(env: &TestEnv, proposal: &Value) -> Value {
    env.request("admin", json!({"method":"resolve_rule","proposal_id":proposal["id"],"digest":proposal["digest"],"approve":true}))
}

fn detail(env: &TestEnv, id: &Value) -> Value {
    env.request("admin", json!({"method":"request_detail","request_id":id}))
}

fn actions(env: &TestEnv) -> Vec<Value> {
    env.request("admin", json!({"method":"actions","limit":100}))["actions"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn withdrawn_proposal_keeps_its_source_digest_and_audit_after_restart() {
    let env = env();
    let proposal = propose(&env);
    let id = &proposal["id"];
    assert_eq!(withdraw(&env, "ops", id)["type"], "error");
    let result = checked(
        env.cli().args([
            "--principal",
            "exec",
            "--json",
            "withdraw",
            id.as_str().unwrap(),
        ]),
        0,
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["rule"]["status"], "withdrawn");
    assert_eq!(result["rule"]["proposal"], proposal);
    assert!(
        env.request("admin", json!({"method":"pending"}))["proposals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(approve(&env, &proposal)["type"], "error");
    assert_eq!(withdraw(&env, "exec", id)["type"], "error");
    env.stop_daemon();
    env.start_daemon();
    let states = env.request("exec", json!({"method":"rules"}));
    assert_eq!(states["rules"][0]["status"], "withdrawn");
    assert_eq!(states["rules"][0]["proposal"], proposal);
    let audit = actions(&env);
    for action in ["rule_proposed", "rule_withdrawn"] {
        let record = audit
            .iter()
            .find(|a| a["action"] == action && a["detail"]["proposal"]["id"] == *id)
            .unwrap();
        assert!(record["time_unix_ms"].as_u64().unwrap() > 0);
        assert_eq!(record["detail"]["proposal"], proposal);
    }
    assert!(audit.iter().any(|a| a["action"] == "caller_request"
        && a["detail"]["principal"] == "ops"
        && a["detail"]["request"]["id"] == *id));
    assert_ne!(propose(&env)["id"], *id);
}

#[test]
fn withdrawing_an_approved_rule_removes_authority_and_keeps_approval_history() {
    let env = env();
    let proposal = propose(&env);
    assert_eq!(approve(&env, &proposal)["rule"]["status"], "active");
    assert_eq!(withdraw(&env, "ops", &proposal["id"])["type"], "error");
    assert_eq!(
        env.request(
            "exec",
            json!({"method":"invoke","operation":"echo-rule","args":["before"]})
        )["code"],
        0
    );
    assert_eq!(
        withdraw(&env, "exec", &proposal["id"])["rule"]["status"],
        "withdrawn"
    );
    assert_eq!(
        env.request(
            "exec",
            json!({"method":"invoke","operation":"echo-rule","args":["after"]})
        )["type"],
        "error"
    );
    let audit = actions(&env);
    assert!(
        audit
            .iter()
            .any(|a| a["action"] == "rule_approved" && a["detail"]["proposal"] == proposal)
    );
    assert!(
        audit
            .iter()
            .any(|a| a["action"] == "rule_withdrawn" && a["detail"]["proposal"] == proposal)
    );
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(
        env.request(
            "exec",
            json!({"method":"invoke","operation":"echo-rule","args":["after-restart"]})
        )["type"],
        "error"
    );
}

#[test]
fn pending_command_can_be_withdrawn_without_erasing_the_request() {
    let env = env();
    let input = command("/usr/bin/printf", &["manual"]);
    let mut caller = env.session("exec", input.clone());
    let pending = caller.event();
    let id = &pending["request"]["request_id"];
    assert_eq!(pending["type"], "pending");
    assert_eq!(withdraw(&env, "ops", id)["type"], "error");
    assert_eq!(withdraw(&env, "exec", id)["type"], "cancelled");
    assert_eq!(caller.event()["reason"], "withdrawn by caller");
    assert_eq!(
        env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true)["type"],
        "error"
    );
    assert!(env.queue().is_empty());
    env.stop_daemon();
    env.start_daemon();
    let record = detail(&env, id);
    assert_eq!(record["request"]["status"], "cancelled");
    assert_eq!(record["request"]["reason"], "withdrawn by caller");
    assert_eq!(record["request"]["input"], input);
    let audit = record["actions"].as_array().unwrap();
    assert!(audit.iter().any(|a| a["action"] == "request_received"));
    let withdrawal = audit
        .iter()
        .find(|a| a["action"] == "request_withdrawn")
        .unwrap();
    assert_eq!(withdrawal["detail"]["principal"], "exec");
    assert_eq!(withdrawal["request_id"], *id);
    assert_eq!(withdraw(&env, "exec", id)["type"], "error");
}

#[test]
fn withdrawal_stops_a_background_job_and_cannot_rewrite_finished_work() {
    let env = env();
    let marker = env.owned_workdir().join("job.pid");
    let mut caller = env.session(
        "exec",
        command(
            env.probe.to_str().unwrap(),
            &["sleep", marker.to_str().unwrap()],
        ),
    );
    let pending = caller.event();
    let id = &pending["request"]["request_id"];
    assert_eq!(
        env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true)["type"],
        "resolved"
    );
    assert_eq!(caller.event()["type"], "submitted");
    drop(caller);
    wait_for(|| marker.exists());
    let pid = fs::read_to_string(&marker).unwrap();
    assert_eq!(withdraw(&env, "exec", id)["type"], "cancelled");
    wait_for(|| !std::path::Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(detail(&env, id)["request"]["reason"], "withdrawn by caller");
    assert_eq!(
        env.request("exec", command("/usr/bin/id", &["-u"]))["code"],
        0
    );
    let history = env.request("admin", json!({"method":"history"}));
    let finished_id = &history["requests"][0]["request_id"];
    let before = detail(&env, finished_id);
    assert_eq!(before["request"]["status"], "completed");
    assert_eq!(withdraw(&env, "exec", finished_id)["type"], "error");
    assert_eq!(detail(&env, finished_id)["request"], before["request"]);
}

#[test]
fn approved_command_waiting_for_capacity_can_be_withdrawn() {
    let env = env();
    fs::write(
        &env.config,
        env.policy
            .replace("timeout_secs = 4", "timeout_secs = 60")
            .replace("max_running = 2", "max_running = 1"),
    )
    .unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let blocker = env.request("exec", command("/usr/bin/sleep", &["300"]));
    assert_eq!(blocker["type"], "submitted");
    let mut caller = env.session("exec", command("/usr/bin/printf", &["manual"]));
    let pending = caller.event();
    let id = &pending["request"]["request_id"];
    assert_eq!(
        env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true)["type"],
        "resolved"
    );
    assert_eq!(detail(&env, id)["request"]["status"], "approved");
    assert_eq!(withdraw(&env, "exec", id)["type"], "cancelled");
    assert_eq!(
        withdraw(&env, "exec", &blocker["request_id"])["type"],
        "cancelled"
    );
    while caller.event()["type"] == "pending" {}
    let record = detail(&env, id);
    assert_eq!(record["request"]["reason"], "withdrawn by caller");
    assert!(
        !record["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "execution_started")
    );
}

#[test]
fn failed_audit_write_leaves_both_proposal_and_command_pending() {
    let env = env();
    let proposal = propose(&env);
    let mut caller = env.session("exec", command("/usr/bin/printf", &["manual"]));
    let pending = caller.event();
    let id = &pending["request"]["request_id"];
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_withdrawal BEFORE INSERT ON actions WHEN NEW.action IN ('rule_withdrawn','request_withdrawn') BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;").unwrap();
    assert_eq!(withdraw(&env, "exec", &proposal["id"])["type"], "error");
    assert_eq!(withdraw(&env, "exec", id)["type"], "error");
    assert_eq!(
        env.request("exec", json!({"method":"rules"}))["rules"][0]["status"],
        "pending"
    );
    assert_eq!(detail(&env, id)["request"]["status"], "pending");
    assert_eq!(env.queue().len(), 1);
    assert!(
        !actions(&env)
            .iter()
            .any(|a| a["action"] == "rule_withdrawn" || a["action"] == "request_withdrawn")
    );
    db.execute_batch("DROP TRIGGER fail_withdrawal;").unwrap();
    assert_eq!(
        withdraw(&env, "exec", &proposal["id"])["rule"]["status"],
        "withdrawn"
    );
    assert_eq!(withdraw(&env, "exec", id)["type"], "cancelled");
    assert_eq!(caller.event()["reason"], "withdrawn by caller");
}
