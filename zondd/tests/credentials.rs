use libzondtest::{
    TestEnv, decoded,
    serde_json::{Value, json},
    wait_for,
};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn challenge(env: &TestEnv) -> Value {
    let mut found = None;
    wait_for(|| {
        found = env.request("admin", json!({"method":"pending"}))["credentials"]
            .as_array()
            .and_then(|items| items.first())
            .cloned();
        found.is_some()
    });
    found.unwrap()
}

fn privileged_policy(env: &TestEnv, enabled: bool) -> String {
    env.policy.replace(
        "operations = [\"greet\"]",
        "operations = [\"greet\", \"privileged\"]",
    ) + &format!(
        "\n[operations.privileged]\nprogram = {:?}\nfixed_args = [\"askpass\"]\ndecision = \"ask\"\nsudo_password = {enabled}\n",
        env.probe.display()
    )
}

#[test]
fn named_operation_prompts_twice_without_persisting_the_password() {
    let env = TestEnv::new();
    let policy = privileged_policy(&env, true);
    fs::write(&env.config, &policy).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );

    let ordinary = env.approved_probe(&["no_new_privs"]);
    assert_eq!(decoded(&ordinary, "stdout"), b"1\n");

    let mut caller = env.session(
        "ops",
        json!({"method":"invoke","operation":"privileged","args":[]}),
    );
    let pending = caller.event();
    assert_eq!(pending["type"], "pending", "{pending}");
    assert_eq!(pending["request"]["sudo_password"], true);
    let request_id = pending["request"]["request_id"].as_str().unwrap();
    assert_eq!(
        env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true)["type"],
        "resolved"
    );

    let first = challenge(&env);
    assert_eq!(first["request_id"], request_id);
    assert_eq!(first["operation"], "privileged");
    assert_eq!(first["prompt"], "Password for sudo:");
    let first_id = first["challenge_id"].as_str().unwrap();
    let rejected = env.request(
        "ops",
        json!({"method":"credential","challenge_id":first_id,"password":"wrong-endpoint-secret"}),
    );
    assert_eq!(rejected["type"], "rejected");
    assert_eq!(
        env.request(
            "admin",
            json!({"method":"credential","challenge_id":first_id,"password":"test-password-one"})
        )["type"],
        "credential_answered"
    );

    let second = challenge(&env);
    assert_ne!(second["challenge_id"], first["challenge_id"]);
    let second_id = second["challenge_id"].as_str().unwrap();
    let mut control = Command::new(&env.ctl)
        .arg("--runtime-dir")
        .arg(&env.runtime)
        .arg("control")
        .arg("--config")
        .arg(&env.config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(control.stdin.take().unwrap(), "{}", json!({"version":1,"method":"credential","challenge_id":second_id,"password":"test-password-two"})).unwrap();
    let response = control.wait_with_output().unwrap();
    assert!(response.status.success(), "{response:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&response.stdout).unwrap()["result"]["type"],
        "credential_answered"
    );

    let done = caller.event();
    assert_eq!(done["type"], "completed", "{done}");
    assert_eq!(decoded(&done, "stdout"), b"two prompts answered\n");
    assert!(
        env.request("admin", json!({"method":"pending"}))["credentials"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let mut persisted = vec![fs::read(env.dir.path().join("daemon.log")).unwrap()];
    for entry in fs::read_dir(env.config.parent().unwrap()).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("config.history.sqlite3")
        {
            persisted.push(fs::read(entry.path()).unwrap());
        }
    }
    for value in [
        "test-password-one",
        "test-password-two",
        "wrong-endpoint-secret",
    ] {
        for file in &persisted {
            assert!(
                !file
                    .windows(value.len())
                    .any(|bytes| bytes == value.as_bytes())
            );
        }
    }
}

#[test]
fn cancelled_job_discards_its_password_challenge() {
    let env = TestEnv::new();
    fs::write(&env.config, privileged_policy(&env, true)).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let mut caller = env.session(
        "ops",
        json!({"method":"invoke","operation":"privileged","args":[]}),
    );
    let pending = caller.event();
    let request_id = pending["request"]["request_id"].as_str().unwrap();
    env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true);
    let id = challenge(&env)["challenge_id"].as_str().unwrap().to_owned();
    assert_eq!(
        env.request("ops", json!({"method":"cancel","request_id":request_id}))["type"],
        "cancelled"
    );
    wait_for(|| {
        env.request("admin", json!({"method":"pending"}))["credentials"]
            .as_array()
            .unwrap()
            .is_empty()
    });
    assert_eq!(
        env.request(
            "admin",
            json!({"method":"credential","challenge_id":id,"password":"late-secret"})
        )["type"],
        "error"
    );
    assert_eq!(caller.event()["type"], "rejected");
    assert!(
        !fs::read_dir(&env.runtime)
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("askpass-"))
    );
}

#[test]
fn enabling_sudo_password_on_reload_requires_fresh_approval() {
    let env = TestEnv::new();
    fs::write(&env.config, privileged_policy(&env, false)).unwrap();
    env.request("admin", json!({"method":"reload"}));
    let mut caller = env.session(
        "ops",
        json!({"method":"invoke","operation":"privileged","args":[]}),
    );
    let original = caller.event();
    let old_id = original["request"]["approval_id"].as_str().unwrap();
    fs::write(&env.config, privileged_policy(&env, true)).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["refreshed_approvals"],
        1
    );
    let refreshed = caller.event();
    assert_eq!(refreshed["type"], "pending", "{refreshed}");
    assert_ne!(refreshed["request"]["approval_id"], old_id);
    assert_eq!(refreshed["request"]["sudo_password"], true);
    assert_eq!(env.resolve(old_id, true)["type"], "error");
    assert_eq!(
        env.resolve(refreshed["request"]["approval_id"].as_str().unwrap(), false)["type"],
        "resolved"
    );
    assert_eq!(caller.event()["type"], "rejected");
}

#[test]
fn a_later_sudo_prompt_keeps_the_same_backgrounded_job() {
    let env = TestEnv::new();
    let policy = privileged_policy(&env, true).replace(
        "fixed_args = [\"askpass\"]",
        "fixed_args = [\"askpass_slow\"]",
    );
    fs::write(&env.config, policy).unwrap();
    env.request("admin", json!({"method":"reload"}));
    let mut caller = env.session(
        "ops",
        json!({"method":"invoke","operation":"privileged","args":[]}),
    );
    let pending = caller.event();
    let request_id = pending["request"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.resolve(pending["request"]["approval_id"].as_str().unwrap(), true);
    let first = challenge(&env);
    env.request("admin", json!({"method":"credential","challenge_id":first["challenge_id"],"password":"test-password-one"}));
    let submitted = caller.event();
    assert_eq!(submitted["type"], "submitted", "{submitted}");
    assert_eq!(submitted["request_id"], request_id);
    drop(caller);

    let second = challenge(&env);
    assert_ne!(second["challenge_id"], first["challenge_id"]);
    env.request("admin", json!({"method":"credential","challenge_id":second["challenge_id"],"password":"test-password-two"}));
    let mut final_job = Value::Null;
    wait_for(|| {
        final_job = env.request("ops", json!({"method":"job","request_id":request_id}));
        final_job["request"]["status"] == "completed"
    });
    assert_eq!(final_job["request"]["backgrounded"], true);
    assert_eq!(
        decoded(&final_job["request"]["result"], "stdout"),
        b"two prompts answered\n"
    );
}
