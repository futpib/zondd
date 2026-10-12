use libzondtest::{
    TestEnv, read_json,
    serde_json::{Value, json},
    wait_for,
};
use std::{
    fs,
    io::Write,
    os::unix::net::UnixStream,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn identity(name: &str) -> String {
    libzond::config::revision(name)
}
fn read_event(stream: &mut UnixStream) -> Value {
    read_json(stream)["body"].clone()
}

fn configure(env: &TestEnv, names: &[&str]) {
    let mut policy = env.policy.clone();
    for name in names {
        policy += &format!(
            "\n[credential_recipients.{name}]\nlabel = 'Trusted {name}'\nkey_sha256 = {:?}\nfield_ids = ['password']\norigins = ['https://example.test']\n",
            libzond::config::revision(&identity(name))
        );
    }
    fs::write(&env.config, policy).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
}
fn connect(env: &TestEnv, name: &str) -> UnixStream {
    let mut connection = UnixStream::connect(env.runtime.join("credential.sock")).unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(connection, "{}", json!({"version":1,"id":1,"body":{"method":"authenticate","recipient":name,"key":identity(name)}})).unwrap();
    assert_eq!(read_event(&mut connection)["type"], "ready");
    connection
}
fn send(stream: &mut UnixStream, value: Value) -> Value {
    static ID: AtomicU64 = AtomicU64::new(2);
    writeln!(
        stream,
        "{}",
        json!({"version":1,"id":ID.fetch_add(1,Ordering::Relaxed),"body":value})
    )
    .unwrap();
    read_event(stream)
}
fn form() -> Value {
    json!({"method":"challenge","origin":"https://example.test","prompt":"untrusted prompt: not a recipient label", "fields":[{"id":"password","label":"Password","kind":"future-field","future":{"encoding":"opaque"}}],"context":{"url":"https://example.test","future":{"property":[1,2,3]}}})
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
    assert_eq!(challenge["recipient"]["peer_uid"], env.user.uid.as_raw());
    assert_eq!(challenge["recipient"]["name"], "first");
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
    let answer = read_event(&mut first);
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
    assert_eq!(queue(&env)["recipients"][0]["state"], "idle");
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
    assert_eq!(read_event(&mut adapter)["status"], "rejected");
    let id = send(&mut adapter, form())["challenge_id"].clone();
    assert_eq!(
        send(&mut adapter, json!({"method":"withdraw","challenge_id":id}))["type"],
        "recorded"
    );
    assert_eq!(read_event(&mut adapter)["status"], "withdrawn");
    let mut request = form();
    request["timeout_secs"] = json!(1);
    send(&mut adapter, request);
    assert_eq!(read_event(&mut adapter)["status"], "expired");
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
    writeln!(adapter, "{}", json!({"version":1,"id":2,"body":request})).unwrap();
    wait_for(|| {
        actions(&env)
            .to_string()
            .contains("credential_session_closed")
    });
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
            assert_eq!(read_event(&mut adapter)["status"], "answered");
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

#[test]
fn authentication_field_and_origin_boundaries_have_stable_private_errors() {
    let env = TestEnv::new();
    configure(&env, &["first", "second"]);
    for (name, key) in [
        ("first", identity("second")),
        ("missing", identity("first")),
    ] {
        let mut stream = UnixStream::connect(env.runtime.join("credential.sock")).unwrap();
        writeln!(
            stream,
            "{}",
            json!({"version":1,"id":1,"body":{"method":"authenticate","recipient":name,"key":key}})
        )
        .unwrap();
        assert_eq!(read_event(&mut stream)["code"], "authentication_failed");
    }
    let mut first = connect(&env, "first");
    let mut duplicate = UnixStream::connect(env.runtime.join("credential.sock")).unwrap();
    writeln!(duplicate, "{}", json!({"version":1,"id":1,"body":{"method":"authenticate","recipient":"first","key":identity("first")}})).unwrap();
    assert_eq!(read_event(&mut duplicate)["code"], "busy");
    for origin in [
        "https://example.test.evil",
        "https://example.test/login",
        "http://example.test",
        "https://user@example.test",
    ] {
        let mut request = form();
        request["origin"] = json!(origin);
        assert_eq!(send(&mut first, request)["code"], "origin_not_allowed");
    }
    let mut request = form();
    request["fields"][0]["id"] = json!("unregistered");
    assert_eq!(send(&mut first, request)["code"], "field_not_allowed");
    assert!(queue(&env)["interactions"].as_array().unwrap().is_empty());
    let id = send(&mut first, form())["challenge_id"].clone();
    assert_eq!(send(&mut first, form())["code"], "busy");
    env.request("admin", json!({"method":"answer_interaction","challenge_id":id,"values":{"password":"private-pending-outcome"}}));
    assert_eq!(
        read_event(&mut first)["values"]["password"],
        "private-pending-outcome"
    );
    assert_eq!(send(&mut first, form())["code"], "result_required");
    assert_eq!(
        send(&mut first, json!({"method":"withdraw","challenge_id":id}))["code"],
        "answer_delivered"
    );
    assert_eq!(
        send(
            &mut first,
            json!({"method":"result","challenge_id":id,"outcome":"made-up-secret"})
        )["code"],
        "invalid_outcome"
    );
    assert_eq!(
        send(
            &mut first,
            json!({"method":"result","challenge_id":id,"outcome":"cancelled"})
        )["type"],
        "recorded"
    );
    let audit = actions(&env).to_string();
    for secret in [
        "private-pending-outcome",
        "made-up-secret",
        &identity("first"),
        &identity("second"),
    ] {
        assert!(!audit.contains(secret));
    }
}

#[test]
fn fragmented_frames_survive_expiry_ticks_and_reconnect_cannot_claim_an_old_challenge() {
    let env = TestEnv::new();
    configure(&env, &["first"]);
    let mut stream = connect(&env, "first");
    let frame = json!({"version":1,"id":2,"body":form()}).to_string() + "\n";
    stream.write_all(&frame.as_bytes()[..20]).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    stream.write_all(&frame.as_bytes()[20..]).unwrap();
    let opened = read_json(&mut stream);
    assert_eq!(opened["id"], 2);
    assert_eq!(opened["body"]["type"], "opened");
    let id = opened["body"]["challenge_id"].clone();
    drop(stream);
    wait_for(|| queue(&env)["recipients"].as_array().unwrap().is_empty());
    let mut stream = connect(&env, "first");
    assert_eq!(
        send(&mut stream, json!({"method":"withdraw","challenge_id":id}))["code"],
        "unknown_challenge"
    );
    assert_eq!(env.request("admin", json!({"method":"answer_interaction","challenge_id":id,"values":{"password":"replay-secret"}}))["type"], "error");
    assert_eq!(send(&mut stream, form())["type"], "opened");
}
