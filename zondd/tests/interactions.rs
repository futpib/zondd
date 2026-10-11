use libzondtest::{
    TestEnv, read_json,
    serde_json::{Value, json},
    wait_for,
};
use std::{fs, io::Write, os::unix::net::UnixStream, time::Duration};

fn configure(env: &TestEnv, names: &[&str]) {
    let mut policy = env.policy.clone();
    for name in names {
        policy += &format!(
            "\n[credential_adapters.{name}]\nlabel = 'Trusted {name}'\nprogram = {:?}\nargs = ['adapter', {:?}]\ncwd = '/'\n",
            env.probe,
            env.dir.path().join(format!("{name}.sock"))
        );
    }
    fs::write(&env.config, policy).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
}
fn connect(env: &TestEnv, name: &str) -> UnixStream {
    let path = env.dir.path().join(format!("{name}.sock"));
    let mut connection = None;
    wait_for(|| {
        connection = UnixStream::connect(&path).ok();
        connection.is_some()
    });
    let mut connection = connection.unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(read_json(&mut connection)["type"], "ready");
    connection
}
fn send(stream: &mut UnixStream, value: Value) -> Value {
    writeln!(stream, "{value}").unwrap();
    read_json(stream)
}
fn form() -> Value {
    json!({"method":"challenge","prompt":"untrusted prompt: not a recipient label", "fields":[{"id":"password","label":"Password","kind":"future-field","future":{"encoding":"opaque"}}],"context":{"url":"https://example.test","future":{"property":[1,2,3]}}})
}
fn queue(env: &TestEnv) -> Value {
    env.request("admin", json!({"method":"pending"}))
}
fn actions(env: &TestEnv) -> Value {
    env.request("admin", json!({"method":"actions","limit":100}))
}

#[test]
fn application_answers_are_private_single_use_and_bound_to_configured_recipient() {
    let env = TestEnv::new();
    configure(&env, &["first", "second"]);
    let mut first = connect(&env, "first");
    let mut second = connect(&env, "second");
    let id = send(&mut first, form())["challenge_id"].clone();
    let challenge = &queue(&env)["interactions"][0];
    assert_eq!(challenge["recipient"]["label"], "Trusted first");
    assert_eq!(challenge["recipient"]["origin"], "configured service");
    assert_eq!(
        challenge["recipient"]["command"]["program"],
        env.probe.to_str().unwrap()
    );
    assert_eq!(challenge["context"]["future"]["property"], json!([1, 2, 3]));
    assert_eq!(send(&mut first, form())["type"], "error");
    assert_eq!(
        send(&mut second, json!({"method":"withdraw","challenge_id":id}))["type"],
        "error"
    );
    let response = json!({"method":"answer_interaction","challenge_id":id,"values":{"password":"unique-test-secret"}});
    assert_eq!(env.request("exec", response.clone())["type"], "rejected");
    assert_eq!(env.request("admin", json!({"method":"answer_interaction","challenge_id":id,"values":{"extra":"rejected-secret"}}))["type"], "error");
    assert_eq!(queue(&env)["interactions"].as_array().unwrap().len(), 1);
    assert_eq!(
        env.request("admin", response.clone())["type"],
        "credential_answered"
    );
    let answer = read_json(&mut first);
    assert_eq!(answer["values"]["password"], "unique-test-secret");
    assert_eq!(env.request("admin", response)["type"], "error");
    assert_eq!(
        send(
            &mut second,
            json!({"method":"result","challenge_id":id,"outcome":"succeeded"})
        )["type"],
        "error"
    );
    assert_eq!(
        send(
            &mut first,
            json!({"method":"result","challenge_id":id,"outcome":"succeeded"})
        )["type"],
        "recorded"
    );
    assert_eq!(
        send(&mut first, json!({"method":"status","state":"ready"}))["type"],
        "recorded"
    );
    assert!(queue(&env)["interactions"].as_array().unwrap().is_empty());
    let audit = actions(&env).to_string();
    for secret in ["unique-test-secret", "rejected-secret"] {
        assert!(!audit.contains(secret));
        assert!(
            !fs::read_to_string(env.dir.path().join("daemon.log"))
                .unwrap()
                .contains(secret)
        );
        for suffix in ["history.sqlite3", "history.sqlite3-wal"] {
            let bytes = fs::read(env.config.with_extension(suffix)).unwrap_or_default();
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
    }
    assert!(audit.contains("interaction_requested"));
    assert!(audit.contains("interaction_ended"));
    assert!(audit.contains("succeeded"));
}

#[test]
fn decline_withdraw_expire_and_disconnect_leave_a_trace() {
    let env = TestEnv::new();
    configure(&env, &["first"]);
    let mut adapter = connect(&env, "first");
    let id = send(&mut adapter, form())["challenge_id"].clone();
    env.request(
        "admin",
        json!({"method":"answer_interaction","challenge_id":id,"values":null}),
    );
    assert_eq!(read_json(&mut adapter)["status"], "rejected");
    let id = send(&mut adapter, form())["challenge_id"].clone();
    assert_eq!(
        send(&mut adapter, json!({"method":"withdraw","challenge_id":id}))["type"],
        "recorded"
    );
    assert_eq!(read_json(&mut adapter)["status"], "withdrawn");
    let mut request = form();
    request["timeout_secs"] = json!(1);
    send(&mut adapter, request);
    assert_eq!(read_json(&mut adapter)["status"], "expired");
    let id = send(&mut adapter, form())["challenge_id"].clone();
    drop(adapter);
    wait_for(|| queue(&env)["interactions"].as_array().unwrap().is_empty());
    assert_eq!(env.request("admin", json!({"method":"answer_interaction","challenge_id":id,"values":{"password":"late-secret"}}))["type"], "error");
    let audit = actions(&env).to_string();
    for status in ["rejected", "withdrawn", "expired", "disconnected"] {
        assert!(audit.contains(status), "{audit}");
    }
}

#[test]
fn reload_invalidates_changed_recipients_and_preserves_unrelated_requests() {
    let env = TestEnv::new();
    configure(&env, &["first"]);
    let mut adapter = connect(&env, "first");
    let id = send(&mut adapter, form())["challenge_id"].clone();
    let policy = fs::read_to_string(&env.config).unwrap();
    fs::write(&env.config, format!("{policy}\n# unrelated change\n")).unwrap();
    env.request("admin", json!({"method":"reload"}));
    assert_eq!(queue(&env)["interactions"][0]["challenge_id"], id);
    fs::write(&env.config, policy.replace("Trusted first", "Replacement")).unwrap();
    env.request("admin", json!({"method":"reload"}));
    assert_eq!(env.request("admin", json!({"method":"answer_interaction","challenge_id":id,"values":{"password":"stale-secret"}}))["type"], "error");
    wait_for(|| queue(&env)["interactions"].as_array().unwrap().is_empty());
    assert!(!actions(&env).to_string().contains("stale-secret"));
}

#[test]
fn malformed_adapter_frames_cannot_spoof_a_recipient_or_leak_values() {
    let env = TestEnv::new();
    configure(&env, &["first"]);
    let mut adapter = connect(&env, "first");
    let mut request = form();
    request["recipient"] = json!({"label":"spoofed-secret"});
    writeln!(adapter, "{request}").unwrap();
    wait_for(|| actions(&env).to_string().contains("adapter_stopped"));
    assert!(queue(&env)["interactions"].as_array().unwrap().is_empty());
    assert!(
        !fs::read_to_string(env.dir.path().join("daemon.log"))
            .unwrap()
            .contains("spoofed-secret")
    );
}

#[test]
fn restart_records_interrupted_input_and_undelivered_outcomes() {
    use libzondtest::nix::sys::signal::Signal;
    for answered in [false, true] {
        let env = TestEnv::new();
        configure(&env, &["first"]);
        let mut adapter = connect(&env, "first");
        let id = send(&mut adapter, form())["challenge_id"].clone();
        if answered {
            env.request("admin", json!({"method":"answer_interaction","challenge_id":id,"values":{"password":"crash-secret"}}));
            assert_eq!(read_json(&mut adapter)["status"], "answered");
        }
        env.signal_daemon(Signal::SIGKILL);
        env.stop_daemon();
        fs::write(&env.config, &env.policy).unwrap();
        env.start_daemon();
        let events = actions(&env);
        let expected = if answered {
            "interaction_result"
        } else {
            "interaction_ended"
        };
        let detail = if answered { "outcome" } else { "status" };
        assert!(
            events["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["action"] == expected
                    && a["detail"]["challenge_id"] == id
                    && a["detail"][detail] == "interrupted"),
            "{events}"
        );
        assert!(queue(&env)["interactions"].as_array().unwrap().is_empty());
        assert!(!events.to_string().contains("crash-secret"));
    }
}
