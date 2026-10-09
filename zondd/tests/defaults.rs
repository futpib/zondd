use libzondtest::{TestEnv, checked, command, serde_json::json, wait_for};
use std::fs;

#[test]
fn missing_policy_starts_with_manual_approval_and_no_automatic_execution() {
    let env = TestEnv::new();
    env.stop_daemon();
    fs::remove_dir_all(env.config.parent().unwrap()).unwrap();
    checked(env.daemon_command().arg("check"), 0);
    env.start(env.daemon_command().arg("serve"), "default-daemon");
    wait_for(|| env.runtime.join("default.sock").exists());
    assert!(!env.config.exists());
    let marker = env.dir.path().join("must-wait");
    let mut caller = env.session(
        "default",
        command("/usr/bin/touch", &[marker.to_str().unwrap()]),
    );
    let event = caller.event();
    assert_eq!(event["type"], "pending");
    assert!(!marker.exists());
    assert_eq!(
        event["request"]["cwd"],
        libzond::paths::home_dir().to_str().unwrap()
    );
    env.resolve(event["request"]["approval_id"].as_str().unwrap(), true);
    assert_eq!(caller.event()["code"], 0);
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    let mut caller = env.session(
        "default",
        command("/usr/bin/touch", &[marker.to_str().unwrap()]),
    );
    let event = caller.event();
    env.resolve(event["request"]["approval_id"].as_str().unwrap(), false);
    assert_eq!(caller.event()["type"], "rejected");
    assert!(!marker.exists());
    fs::write(&env.config, "[approvals]\nenabled = false\n").unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    assert_eq!(
        env.request(
            "default",
            command("/usr/bin/touch", &[marker.to_str().unwrap()])
        )["type"],
        "rejected"
    );
    assert!(!marker.exists());
    fs::write(&env.config, "broken policy").unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "error"
    );
    assert_eq!(
        env.request(
            "default",
            command("/usr/bin/touch", &[marker.to_str().unwrap()])
        )["type"],
        "rejected"
    );
    fs::remove_file(&env.config).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let mut caller = env.session("default", command("/usr/bin/true", &[]));
    assert_eq!(caller.event()["type"], "pending");
}
