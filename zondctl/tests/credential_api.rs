use libzond::{
    SecretString,
    credential::{Event, Request},
};
use libzondctl::credential::{Client, read_key};
use libzondtest::{
    TestEnv, read_json,
    serde_json::{Value, json},
    wait_for,
};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    process::Command,
    time::Duration,
};

fn configure(env: &TestEnv) -> std::path::PathBuf {
    let key = "a".repeat(64);
    let path = env.dir.path().join("service.key");
    fs::write(&path, &key).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&env.config, format!("{}\n[credential_recipients.service]\nlabel = 'Independent service'\nkey_sha256 = {:?}\nfield_ids = ['password']\norigins = ['https://example.test']\n", env.policy, libzond::config::revision(&key))).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    path
}

fn challenge() -> Request {
    Request::Challenge {
        origin: "https://example.test".into(),
        prompt: "Sign in".into(),
        fields: serde_json::from_value(
            json!([{"id":"password","label":"Password","kind":"secret"}]),
        )
        .unwrap(),
        context: Value::Null,
        timeout_secs: 30,
    }
}

#[test]
fn reference_client_discards_answers_when_cancellation_wins_or_loses_the_race() {
    let env = TestEnv::new();
    let key_file = configure(&env);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut client = Client::connect(&env.runtime.join("credential.sock"), "service", read_key(&key_file).unwrap()).await.unwrap();
        for answered in [false, true] {
            let request_id = client.send(challenge()).await.unwrap();
            let reply = client.receive().await.unwrap();
            assert_eq!(reply.id, request_id);
            let Event::Opened { challenge_id } = reply.body else { panic!("expected opened"); };
            if answered {
                assert_eq!(env.request("admin", json!({"method":"answer_interaction","challenge_id":challenge_id,"values":{"password":"cancel-race-secret"}}))["type"], "credential_answered");
            }
            client.withdraw_and_discard(request_id, &challenge_id).await.unwrap();
            let queue = env.request("admin", json!({"method":"pending"}));
            assert!(queue["interactions"].as_array().unwrap().is_empty());
            assert_eq!(queue["recipients"][0]["state"], "idle");
        }
    });
    let audit = env
        .request("admin", json!({"method":"actions","limit":100}))
        .to_string();
    assert!(audit.contains("cancelled"));
    assert!(!audit.contains("cancel-race-secret"));
    assert!(
        !fs::read_to_string(env.dir.path().join("daemon.log"))
            .unwrap()
            .contains("cancel-race-secret")
    );
}

#[test]
fn private_identity_is_required_and_reference_client_disconnect_cancels_pending_input() {
    let env = TestEnv::new();
    let key_file = configure(&env);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        assert!(
            Client::connect(
                &env.runtime.join("credential.sock"),
                "service",
                SecretString("b".repeat(64))
            )
            .await
            .is_err()
        );
        let mut client = Client::connect(
            &env.runtime.join("credential.sock"),
            "service",
            read_key(&key_file).unwrap(),
        )
        .await
        .unwrap();
        client.send(challenge()).await.unwrap();
        assert!(matches!(
            client.receive().await.unwrap().body,
            Event::Opened { .. }
        ));
        drop(client);
    });
    wait_for(|| {
        env.request("admin", json!({"method":"pending"}))["interactions"]
            .as_array()
            .unwrap()
            .is_empty()
    });
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_key(&key_file).is_err());
}

#[test]
fn response_limit_allows_answer_metadata_above_the_admin_request_limit() {
    let env = TestEnv::new();
    let key_file = configure(&env);
    let ids: Vec<_> = (0..16).map(|i| format!("field-{i:02}")).collect();
    let policy = fs::read_to_string(&env.config)
        .unwrap()
        .replace("['password']", &serde_json::to_string(&ids).unwrap());
    fs::write(&env.config, policy).unwrap();
    env.request("admin", json!({"method":"reload"}));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut client = Client::connect(
            &env.runtime.join("credential.sock"),
            "service",
            read_key(&key_file).unwrap(),
        )
        .await
        .unwrap();
        let fields = ids
            .iter()
            .map(|id| json!({"id":id,"label":"Input","kind":"secret"}))
            .collect::<Vec<_>>();
        let request: Request = serde_json::from_value(
            json!({"method":"challenge","origin":"https://example.test","fields":fields}),
        )
        .unwrap();
        client.send(request).await.unwrap();
        let Event::Opened { challenge_id } = client.receive().await.unwrap().body else {
            panic!("expected opened");
        };
        let values: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.clone(), json!("\"".repeat(2000))))
            .collect();
        let mut body =
            json!({"method":"answer_interaction","challenge_id":challenge_id,"values":values});
        let envelope = json!({"version":1,"id":1,"body":body});
        let padding = libzond::MAX_REQUEST_BYTES - 2 - envelope.to_string().len();
        body["values"][&ids[0]] = json!("\"".repeat(2000) + &"x".repeat(padding));
        assert_eq!(env.request("admin", body)["type"], "credential_answered");
        let answer = client.receive().await.unwrap();
        assert!(
            serde_json::to_vec(&answer).unwrap().len() > libzond::credential::MAX_REQUEST_BYTES
        );
        let Event::Answered {
            values: Some(values),
            ..
        } = answer.body
        else {
            panic!("expected answer");
        };
        assert_eq!(values.len(), 16);
    });
}

#[test]
fn legacy_bridge_keeps_its_application_alive_when_broker_is_absent_or_restarted() {
    let env = TestEnv::new();
    let key_file = configure(&env);
    let app_socket = env.dir.path().join("independent.sock");
    env.stop_daemon();
    env.start(
        Command::new(&env.ctl)
            .arg("--runtime-dir")
            .arg(&env.runtime)
            .args(["credential-adapter", "--recipient", "service", "--key-file"])
            .arg(&key_file)
            .args(["--origin", "https://example.test", "--"])
            .arg(&env.probe)
            .arg("adapter")
            .arg(&app_socket),
        "independent-service",
    );
    let mut stream = None;
    wait_for(|| {
        stream = UnixStream::connect(&app_socket).ok();
        stream.is_some()
    });
    let mut stream = stream.unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(read_json(&mut stream)["type"], "ready");
    let form = json!({"method":"challenge","prompt":"Sign in","fields":[{"id":"password","label":"Password","kind":"secret"}]});
    writeln!(stream, "{form}").unwrap();
    assert_eq!(read_json(&mut stream)["type"], "error");
    env.start_daemon();
    for _ in 0..2 {
        writeln!(stream, "{form}").unwrap();
        let opened = read_json(&mut stream);
        assert_eq!(opened["type"], "opened");
        env.stop_daemon();
        let answer = read_json(&mut stream);
        assert_eq!(answer["challenge_id"], opened["challenge_id"]);
        assert_eq!(answer["status"], "interrupted");
        assert!(answer["values"].is_null());
        env.start_daemon();
    }
    // The same live application pipe can still request and use a fresh answer.
    writeln!(stream, "{form}").unwrap();
    let opened = read_json(&mut stream);
    assert_eq!(opened["type"], "opened");
    env.request("admin", json!({"method":"answer_interaction","challenge_id":opened["challenge_id"],"values":{"password":"independent-memory-secret"}}));
    assert_eq!(
        read_json(&mut stream)["values"]["password"],
        "independent-memory-secret"
    );
    writeln!(
        stream,
        "{}",
        json!({"method":"result","challenge_id":opened["challenge_id"],"outcome":"succeeded"})
    )
    .unwrap();
    assert_eq!(read_json(&mut stream)["type"], "recorded");
    env.stop_daemon();
    // Local work and status do not open a broker connection or restart the child.
    writeln!(stream, "{}", json!({"method":"status","state":"ready"})).unwrap();
    assert_eq!(read_json(&mut stream)["type"], "recorded");
}

#[test]
#[ignore = "requires a running systemd user manager"]
fn systemd_owns_the_application_and_provisions_its_connection_identity() {
    use libzondtest::{checked, output};
    struct Unit {
        name: String,
        path: std::path::PathBuf,
    }
    impl Drop for Unit {
        fn drop(&mut self) {
            let _ = output(Command::new("systemctl").args(["--user", "stop", &self.name]));
            let _ = output(Command::new("systemctl").args(["--user", "reset-failed", &self.name]));
            let _ = fs::remove_file(&self.path);
            let _ = output(Command::new("systemctl").args(["--user", "daemon-reload"]));
        }
    }
    let env = TestEnv::new();
    let key_file = configure(&env);
    let name = format!(
        "zondd-credential-{}.service",
        env.dir.path().file_name().unwrap().to_str().unwrap()
    );
    let directory = env.user.dir.join(".config/systemd/user");
    libzond::paths::create_private_dir_all(&directory).unwrap();
    let unit = Unit {
        path: directory.join(&name),
        name,
    };
    let socket = env.dir.path().join("systemd-application.sock");
    fs::write(&unit.path, format!("[Service]\nLoadCredential=identity:{}\nExecStart={} --runtime-dir {} credential-adapter --recipient service --key-file %d/identity --origin https://example.test -- {} adapter {}\nKillMode=control-group\nTimeoutStopSec=5\n", key_file.display(), env.ctl.display(), env.runtime.display(), env.probe.display(), socket.display())).unwrap();
    checked(
        Command::new("systemctl").args(["--user", "daemon-reload"]),
        0,
    );
    checked(
        Command::new("systemctl").args(["--user", "start", &unit.name]),
        0,
    );
    let mut stream = None;
    wait_for(|| {
        stream = UnixStream::connect(&socket).ok();
        stream.is_some()
    });
    let mut stream = stream.unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(read_json(&mut stream)["type"], "ready");
    let pid = || {
        checked(
            Command::new("systemctl").args([
                "--user",
                "show",
                &unit.name,
                "--property=MainPID",
                "--value",
            ]),
            0,
        )
        .stdout
    };
    let original_pid = pid();
    let form = json!({"method":"challenge","fields":[{"id":"password","label":"Password","kind":"secret"}],"prompt":"Sign in"});
    writeln!(stream, "{form}").unwrap();
    let opened = read_json(&mut stream);
    assert_eq!(opened["type"], "opened");
    env.request("admin", json!({"method":"answer_interaction","challenge_id":opened["challenge_id"],"values":{"password":"systemd-provisioned-secret"}}));
    assert_eq!(
        read_json(&mut stream)["values"]["password"],
        "systemd-provisioned-secret"
    );
    writeln!(
        stream,
        "{}",
        json!({"method":"result","challenge_id":opened["challenge_id"],"outcome":"succeeded"})
    )
    .unwrap();
    assert_eq!(read_json(&mut stream)["type"], "recorded");
    for _ in 0..2 {
        env.stop_daemon();
        writeln!(stream, "{}", json!({"method":"status","state":"ready"})).unwrap();
        assert_eq!(read_json(&mut stream)["type"], "recorded");
        assert_eq!(pid(), original_pid);
        env.start_daemon();
        assert_eq!(pid(), original_pid);
    }
    drop(unit);
}
