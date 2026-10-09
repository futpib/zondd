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
        "policy reloaded; submit the request again"
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
