use libzondtest::{TestEnv, checked, command, decoded, serde_json::json, wait_for};
use std::{fs, os::unix::fs::MetadataExt};

#[test]
fn reload_replaces_principals_and_policy_without_interrupting_running_commands() {
    let env = TestEnv::new();
    let admin_inode = fs::metadata(env.runtime.join("admin.sock")).unwrap().ino();
    let mut running = env.session("exec", command("/usr/bin/sleep", &["1"]));
    wait_for(|| env.request("admin", json!({"method":"status"}))["running"] == 1);
    let (mut waiting, id) = env.pending(command("/usr/bin/printf", &["manual"]));
    let changed = env
        .policy
        .replace("principals.exec", "principals.replacement")
        .replace("max_running = 2", "max_running = 1")
        .replace("hello %s", "updated %s");
    fs::write(&env.config, &changed).unwrap();
    let applied = env.request("admin", json!({"method":"reload"}));
    assert_eq!(applied["type"], "reloaded", "{applied}");
    assert_eq!(applied["cancelled_approvals"], 1);
    assert_eq!(applied["revision"], libzond::config::revision(&changed));
    assert_eq!(
        waiting.event()["reason"],
        "policy changed: principal is no longer configured"
    );
    assert_eq!(env.resolve(&id, true)["type"], "error");
    assert!(!env.runtime.join("exec.sock").exists());
    assert_eq!(
        fs::metadata(env.runtime.join("replacement.sock"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    let full = env.request("replacement", command("/usr/bin/id", &["-u"]));
    assert!(
        full["message"].as_str().unwrap().contains("capacity"),
        "{full}"
    );
    assert_eq!(running.event()["code"], 0);
    assert_eq!(
        env.request("replacement", command("/usr/bin/id", &["-u"]))["code"],
        0
    );
    let invoked = env.request(
        "ops",
        json!({"method":"invoke", "operation":"greet", "args":["world"]}),
    );
    assert_eq!(decoded(&invoked, "stdout"), b"updated world");
    assert_eq!(
        fs::metadata(env.runtime.join("admin.sock")).unwrap().ino(),
        admin_inode
    );
    assert_eq!(
        env.request("replacement", json!({"method":"reload"}))["type"],
        "rejected"
    );
}

#[test]
fn failed_and_unchanged_reloads_preserve_active_policy_and_pending_approvals() {
    use std::os::unix::fs::PermissionsExt;
    let env = TestEnv::new();
    let before = env.request("admin", json!({"method":"status"}))["revision"].clone();
    let (mut waiting, id) = env.pending(command("/usr/bin/printf", &["manual"]));
    let same = env.request("admin", json!({"method":"reload", "revision":before}));
    assert_eq!(same["cancelled_approvals"], 0);
    assert_eq!(env.queue().len(), 1);
    for (text, revision, reason) in [
        ("invalid config".to_owned(), None, "TOML"),
        (
            format!("{}\n# changed", env.policy),
            Some(before.clone()),
            "changed",
        ),
        (
            format!(
                "runtime_dir = {:?}\n{}",
                env.runtime.join("other"),
                env.policy
            ),
            None,
            "requires a restart",
        ),
    ] {
        fs::write(&env.config, text).unwrap();
        let failed = env.request("admin", json!({"method":"reload", "revision":revision}));
        assert_eq!(failed["type"], "error", "{failed}");
        assert!(
            failed["message"].as_str().unwrap().contains(reason),
            "{failed}"
        );
        assert_eq!(
            env.request("admin", json!({"method":"status"}))["revision"],
            before
        );
        assert_eq!(env.queue()[0]["approval_id"], id);
    }
    let additions = format!(
        "{}\n[principals.added]\ncwd = \"/tmp\"\n[principals.blocked]\ncwd = \"/tmp\"\n",
        env.policy
    );
    fs::write(&env.config, additions).unwrap();
    let collision = env.runtime.join("blocked.sock");
    fs::write(&collision, "preserve me").unwrap();
    let failed = env.request("admin", json!({"method":"reload"}));
    assert!(
        failed["message"]
            .as_str()
            .unwrap()
            .contains("new principal socket"),
        "{failed}"
    );
    assert_eq!(fs::read_to_string(collision).unwrap(), "preserve me");
    assert!(!env.runtime.join("added.sock").exists());
    fs::set_permissions(&env.config, fs::Permissions::from_mode(0o666)).unwrap();
    let failed = env.request("admin", json!({"method":"reload"}));
    assert!(
        failed["message"]
            .as_str()
            .unwrap()
            .contains("writable by other users")
    );
    assert_eq!(env.resolve(&id, true)["type"], "resolved");
    assert_eq!(waiting.event()["code"], 0);
    assert_eq!(
        env.request("admin", json!({"method":"status"}))["revision"],
        before
    );
}

#[test]
fn cli_reload_applies_new_rules_to_existing_principals() {
    let env = TestEnv::new();
    fs::write(
        &env.config,
        env.policy
            .replace("args = [\"-u\"]", "args = [\"-u\"]\n# edited")
            .replace("default = \"ask\"", "default = \"deny\""),
    )
    .unwrap();
    checked(env.cli().arg("reload"), 0);
    assert_eq!(
        env.request("exec", command("/usr/bin/printf", &["manual"]))["type"],
        "rejected"
    );
    assert_eq!(
        env.request("exec", command("/usr/bin/id", &["-u"]))["code"],
        0
    );
}

#[test]
fn unrelated_policy_changes_preserve_approval_id_and_original_expiry() {
    let env = TestEnv::new();
    let (mut caller, id) = env.pending(command("/usr/bin/printf", &["manual"]));
    let original = env.queue()[0].clone();
    let changed = format!(
        "{}\n# unrelated edit",
        env.policy.replace("timeout_secs = 4", "timeout_secs = 120")
    );
    fs::write(&env.config, changed).unwrap();
    let result = env.request("admin", json!({"method":"reload"}));
    assert_eq!(result["retained_approvals"], 1);
    assert_eq!(result["cancelled_approvals"], 0);
    assert_eq!(env.queue()[0], original);
    assert_eq!(caller.event()["reason"], "approval expired");
    assert_eq!(env.resolve(&id, true)["type"], "error");
}

#[test]
fn newly_allowed_requests_execute_and_newly_denied_requests_explain_rejection() {
    let env = TestEnv::new();
    let (mut allowed, _) = env.pending(command("/usr/bin/printf", &["%s", "new"]));
    let (mut denied, _) = env.pending(command("/usr/bin/printf", &["%s", "other"]));
    let changed = env
        .policy
        .replace("args = [\"%s\", \"hello\"]", "args = [\"%s\", \"new\"]")
        .replace("default = \"ask\"", "default = \"deny\"");
    fs::write(&env.config, changed).unwrap();
    let result = env.request("admin", json!({"method":"reload"}));
    assert_eq!(result["allowed_approvals"], 1);
    assert_eq!(result["cancelled_approvals"], 1);
    assert_eq!(decoded(&allowed.event(), "stdout"), b"new");
    assert_eq!(denied.event()["reason"], "command denied by updated policy");
}

#[test]
fn changed_operation_and_directory_require_fresh_review_without_reconnecting() {
    let env = TestEnv::new();
    let policy = env.policy.replace(
        "arguments = [{name = \"who\", choices = [\"world\", \"λ\"]}]\ndecision = \"allow\"",
        "arguments = [{name = \"who\", choices = [\"world\", \"λ\"]}]\ndecision = \"ask\"",
    );
    fs::write(&env.config, &policy).unwrap();
    checked(env.cli().arg("reload"), 0);
    let mut caller = env.session(
        "ops",
        json!({"method":"invoke","operation":"greet","args":["world"]}),
    );
    let original = caller.event()["request"].clone();
    fs::write(
        &env.config,
        policy
            .replace("hello %s", "updated %s")
            .replace("cwd = \"/tmp\"", "cwd = \"/\"")
            .replace("decision = \"ask\"", "decision = \"allow\""),
    )
    .unwrap();
    let result = env.request("admin", json!({"method":"reload"}));
    assert_eq!(result["refreshed_approvals"], 1);
    let updated = caller.event()["request"].clone();
    assert_eq!(updated["request_id"], original["request_id"]);
    assert_eq!(updated["expires_unix_ms"], original["expires_unix_ms"]);
    assert_eq!(updated["cwd"], "/");
    assert_eq!(updated["command"]["args"], json!(["updated %s", "world"]));
    assert_ne!(updated["approval_id"], original["approval_id"]);
    let current = fs::read_to_string(&env.config).unwrap();
    fs::write(&env.config, format!("{current}\n# another edit")).unwrap();
    let again = env.request("admin", json!({"method":"reload"}));
    assert_eq!(again["retained_approvals"], 1);
    assert_eq!(env.queue()[0]["approval_id"], updated["approval_id"]);
    assert_eq!(
        env.resolve(original["approval_id"].as_str().unwrap(), true)["type"],
        "error"
    );
    assert_eq!(
        env.resolve(updated["approval_id"].as_str().unwrap(), true)["type"],
        "resolved"
    );
    assert_eq!(decoded(&caller.event(), "stdout"), b"updated world");
}

#[test]
fn approval_waiting_for_capacity_cannot_bypass_a_later_denial() {
    let env = TestEnv::new();
    let policy = env.policy.replace("max_running = 2", "max_running = 1");
    fs::write(&env.config, &policy).unwrap();
    checked(env.cli().arg("reload"), 0);
    let mut running = env.session("exec", command("/usr/bin/sleep", &["1"]));
    wait_for(|| env.request("admin", json!({"method":"status"}))["running"] == 1);
    let (mut caller, id) = env.pending(command("/usr/bin/printf", &["manual"]));
    env.resolve(&id, true);
    fs::write(
        &env.config,
        policy.replace("default = \"ask\"", "default = \"deny\""),
    )
    .unwrap();
    checked(env.cli().arg("reload"), 0);
    let mut result = caller.event();
    while result["type"] == "pending" {
        result = caller.event();
    }
    assert_eq!(result["reason"], "command denied by updated policy");
    assert_eq!(running.event()["code"], 0);
}

#[test]
fn newly_allowed_requests_wait_for_capacity_and_use_current_limits() {
    let env = TestEnv::new();
    let policy = env.policy.replace("max_running = 2", "max_running = 1");
    fs::write(&env.config, &policy).unwrap();
    checked(env.cli().arg("reload"), 0);
    let mut running = env.session("exec", command("/usr/bin/sleep", &["1"]));
    wait_for(|| env.request("admin", json!({"method":"status"}))["running"] == 1);
    let (mut caller, _) = env.pending(command("/usr/bin/printf", &["%s", "new"]));
    fs::write(
        &env.config,
        policy
            .replace("args = [\"%s\", \"hello\"]", "args = [\"%s\", \"new\"]")
            .replace("max_output_bytes = 1024", "max_output_bytes = 1"),
    )
    .unwrap();
    let result = env.request("admin", json!({"method":"reload"}));
    assert_eq!(result["allowed_approvals"], 1);
    assert_eq!(running.event()["code"], 0);
    let mut result = caller.event();
    while result["type"] == "pending" {
        result = caller.event();
    }
    assert!(result["message"].as_str().unwrap().contains("output limit"));
}
