//! A real Android app, SSH server, Iroh server, and user daemon; no mocked transport.
use libzondtest::{Process, SshEnv, checked, serde_json::json, wait_for};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::Duration,
};

#[test]
#[ignore = "requires Flutter, Android SDK/NDK, a running emulator and OpenSSH"]
fn android_management_over_ssh_and_iroh() {
    let external_public_key = std::env::var("ZONDD_ANDROID_EXTERNAL_PUBLIC_KEY")
        .ok()
        .map(|path| fs::read_to_string(path).expect("read provider OpenSSH public key"));
    let app = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../android-app")
        .canonicalize()
        .unwrap();
    let target = app.join("native/target");
    // Build this server from the app's lockfile so the emulator exercises its
    // pinned protocol, independently of any installed Iroh CLI.
    let mut build = Process::spawn(
        Command::new("cargo")
            .args(["build", "--locked", "--manifest-path"])
            .arg(app.join("native/Cargo.toml"))
            .args(["--example", "test-server", "--target-dir"])
            .arg(&target),
    );
    assert!(build.wait(Duration::from_secs(1200)).success());
    let ssh = SshEnv::new();
    if let Some(key) = &external_public_key {
        use std::io::Write;
        let mut authorized = fs::OpenOptions::new()
            .append(true)
            .open(ssh.env.dir.path().join("authorized_keys"))
            .unwrap();
        writeln!(authorized, "{}", key.trim()).unwrap();
    }
    ssh.env.stop_daemon();
    if let Ok(path) = std::env::var("ZONDD_ANDROID_HISTORY_FIXTURE") {
        fs::copy(path, ssh.env.config.with_extension("history.sqlite3"))
            .expect("copy retained audit history fixture");
    }
    fs::write(
        &ssh.env.config,
        ssh.env
            .policy
            .replace("timeout_secs = 4", "timeout_secs = 120"),
    )
    .unwrap();
    ssh.env.start_daemon();
    let start_iroh = |ssh: &SshEnv, port: u16, name: &str| {
        ssh.env.start(
            Command::new(target.join("debug/examples/test-server")).arg(port.to_string()),
            name,
        );
        let mut endpoint = None;
        wait_for(|| {
            endpoint = fs::read_to_string(ssh.env.dir.path().join(format!("{name}.log")))
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("endpoint=").map(str::to_owned));
            endpoint.is_some()
        });
        endpoint.unwrap()
    };
    let endpoint = start_iroh(&ssh, ssh.port, "iroh");
    ssh.env.start(
        Command::new(std::env::var("PYTHON").unwrap_or_else(|_| "python3".into()))
            .arg(app.join("scripts/test-auth-server.py"))
            .arg(ssh.env.dir.path().join("host"))
            .arg(&ssh.env.ctl)
            .arg("--runtime-dir")
            .arg(&ssh.env.runtime)
            .arg("control")
            .arg("--config")
            .arg(&ssh.env.config),
        "authentication",
    );
    let mut auth_port = None;
    wait_for(|| {
        auth_port = fs::read_to_string(ssh.env.dir.path().join("authentication.log"))
            .unwrap()
            .lines()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|value| value["port"].as_u64().map(|p| p as u16));
        auth_port.is_some()
    });
    let auth_port = auth_port.unwrap();
    let auth_endpoint = start_iroh(&ssh, auth_port, "authentication-iroh");
    let fingerprint = checked(
        Command::new("ssh-keygen")
            .arg("-lf")
            .arg(ssh.env.dir.path().join("host.pub")),
        0,
    );
    let fingerprint = String::from_utf8(fingerprint.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let mut fixture = json!({
        "host":"10.0.2.2", "port":ssh.port, "endpoint":endpoint,
        "authPort":auth_port, "authEndpoint":auth_endpoint,
        "user":ssh.env.user.name, "runtime":ssh.env.runtime, "config":ssh.env.config,
        "executable":ssh.env.ctl, "fingerprint":fingerprint,
        "probe":ssh.env.probe,
        "key":fs::read_to_string(ssh.env.dir.path().join("management-key")).unwrap(),
        "callerKey":fs::read_to_string(ssh.env.dir.path().join("exec-key")).unwrap(),
    });
    let legacy_ssh = std::env::var("ZONDD_ANDROID_TEST")
        .map_or(external_public_key.is_none(), |test| {
            test == "integration_test/legacy_rules_test.dart"
        })
        .then(|| {
            let legacy = SshEnv::new();
            legacy.env.stop_daemon();
            checked(
                Command::new(std::env::var("PYTHON").unwrap_or_else(|_| "python3".into()))
                    .args([
                        "-c",
                        "import sqlite3,sys\nwith sqlite3.connect(sys.argv[1]) as db:\n db.executescript('DELETE FROM actions; DELETE FROM audit_meta; DELETE FROM audit_receipts; DELETE FROM sqlite_sequence WHERE name=\"actions\";')\n db.executemany('INSERT INTO actions(time,request_id,action,detail) VALUES (0,NULL,\"daemon_stopped\",\"{}\")', [()] * 207493)\n",
                    ])
                    .arg(legacy.env.config.with_extension("history.sqlite3")),
                0,
            );
            let history = libzond::history::History::open(&legacy.env.config).unwrap();
            assert_eq!(history.legacy_through_sequence().unwrap(), 207493);
            drop(history);
            fs::write(
                &legacy.env.config,
                legacy.env.policy.replace("timeout_secs = 4", "timeout_secs = 120"),
            )
            .unwrap();
            legacy.env.start_daemon_with_timeout(Duration::from_secs(60));
            let endpoint = start_iroh(&legacy, legacy.port, "legacy-iroh");
            let fingerprint = checked(
                Command::new("ssh-keygen")
                    .arg("-lf")
                    .arg(legacy.env.dir.path().join("host.pub")),
                0,
            );
            let fingerprint = String::from_utf8(fingerprint.stdout).unwrap();
            let fingerprint = fingerprint.split_whitespace().nth(1).unwrap();
            fixture["legacy"] = json!({
                "host":"10.0.2.2", "port":legacy.port, "endpoint":endpoint,
                "user":legacy.env.user.name, "runtime":legacy.env.runtime,
                "config":legacy.env.config, "executable":legacy.env.ctl,
                "fingerprint":fingerprint,
                "key":fs::read_to_string(legacy.env.dir.path().join("management-key")).unwrap(),
                "callerKey":fs::read_to_string(legacy.env.dir.path().join("exec-key")).unwrap(),
            });
            legacy
        });
    if let Ok(path) = std::env::var("ZONDD_ANDROID_EXTRA_FIXTURE") {
        let extra: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&fs::read(path).expect("read external test fixture"))
                .expect("external test fixture must be a JSON object");
        let fixture = fixture.as_object_mut().unwrap();
        for (name, value) in extra {
            assert!(
                !fixture.contains_key(&name),
                "external fixture replaces built-in field {name}"
            );
            fixture.insert(name, value);
        }
    }
    let credential_identity = "b".repeat(64);
    let credential_key_file = ssh.env.dir.path().join("credential-client.key");
    fs::write(&credential_key_file, &credential_identity).unwrap();
    fs::set_permissions(&credential_key_file, fs::Permissions::from_mode(0o600)).unwrap();
    fixture["credentialKeyFile"] = json!(credential_key_file);
    fixture["credentialKeyDigest"] = json!(libzond::config::revision(&credential_identity));
    let forbidden = fixture["forbiddenLogValues"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    fixture["forbiddenLogValues"] = json!(
        forbidden
            .into_iter()
            .chain([
                json!(credential_identity),
                json!("test-user"),
                json!("test-application-password")
            ])
            .collect::<Vec<_>>()
    );
    let definitions = ssh.env.dir.path().join("android-defines.json");
    fs::write(
        &definitions,
        json!({
            "ZONDD_FIXTURE":fixture.to_string(),
            "CAPTURE_PORT":std::env::var("ZONDD_SCREENSHOT_PORT").unwrap_or_default(),
        })
        .to_string(),
    )
    .unwrap();
    fs::set_permissions(&definitions, fs::Permissions::from_mode(0o600)).unwrap();
    // Flutter only recognizes device tests beneath this app's integration_test directory.
    let mut external_test = None;
    let selected_test = std::env::var("ZONDD_ANDROID_TEST").ok().map(|target| {
        let source = app.join(&target).canonicalize().expect("find Android test");
        if source.starts_with(app.join("integration_test")) {
            return target;
        }
        let directory = tempfile::Builder::new()
            .prefix(".external-")
            .tempdir_in(app.join("integration_test"))
            .unwrap();
        let wrapper = directory.path().join("external_test.dart");
        let source = serde_json::to_string(source.to_str().unwrap())
            .unwrap()
            .replace('$', "\\$");
        fs::write(
            &wrapper,
            format!("import {source} as adapterTest;\nvoid main() => adapterTest.main();\n"),
        )
        .unwrap();
        external_test = Some(directory);
        wrapper.to_str().unwrap().to_owned()
    });
    let log = fs::File::create(ssh.env.dir.path().join("android.log")).unwrap();
    let run_exports = std::env::var("ZONDD_ANDROID_TEST")
        .map_or(external_public_key.is_none(), |target| {
            target == "integration_test/audit_test.dart"
        });
    let mut export_driver = run_exports.then(|| {
        Process::spawn(
            Command::new(std::env::var("PYTHON").unwrap_or_else(|_| "python3".into()))
                .arg(app.join("scripts/audit-export-driver.py"))
                .arg(
                    std::env::var("ZONDD_ANDROID_DEVICE")
                        .unwrap_or_else(|_| "emulator-5554".into()),
                )
                .arg(&ssh.env.ctl),
        )
    });
    let mut process = Process::spawn(
        Command::new(std::env::var("FLUTTER").unwrap_or_else(|_| "flutter".into()))
            .current_dir(app)
            .args(["test", "--reporter", "expanded"])
            .args(if let Some(target) = selected_test {
                vec![target]
            } else if external_public_key.is_some() {
                vec!["integration_test/external_key_test.dart".into()]
            } else {
                vec![
                    "integration_test/legacy_rules_test.dart".into(),
                    "integration_test/audit_test.dart".into(),
                    "integration_test/authentication_test.dart".into(),
                    "integration_test/control_test.dart".into(),
                    "integration_test/credential_test.dart".into(),
                    "integration_test/interaction_test.dart".into(),
                    "integration_test/rules_test.dart".into(),
                    "integration_test/search_test.dart".into(),
                    "integration_test/workflow_test.dart".into(),
                ]
            })
            .arg("-d")
            .arg(std::env::var("ZONDD_ANDROID_DEVICE").unwrap_or_else(|_| "emulator-5554".into()))
            .arg("--dart-define-from-file")
            .arg(&definitions)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log),
    );
    let status = process.wait(Duration::from_secs(2700));
    let transcript = fs::read_to_string(ssh.env.dir.path().join("android.log")).unwrap();
    assert!(
        status.success()
            && transcript.contains("All tests passed!")
            && !transcript.contains("EXCEPTION CAUGHT BY FLUTTER TEST FRAMEWORK")
            && !transcript.contains("This test failed after it had already completed"),
        "Android integration failed or reported a late framework exception"
    );
    if let Some(driver) = &mut export_driver {
        assert!(
            driver.wait(Duration::from_secs(60)).success(),
            "Native Android export verification failed"
        );
    }
    assert!(ssh.env.queue().is_empty());
    if let Some(legacy) = &legacy_ssh {
        assert!(legacy.env.queue().is_empty());
    }
    if let Some(secrets) = fixture["forbiddenLogValues"].as_array() {
        let mut logs = vec![ssh.env.dir.path().join("daemon.log")];
        for file in fs::read_dir(ssh.env.config.parent().unwrap()).unwrap() {
            let file = file.unwrap();
            if file
                .file_name()
                .to_string_lossy()
                .starts_with("config.history.sqlite3")
            {
                logs.push(file.path());
            }
        }
        if let Some(extra) = fixture["additionalLogFiles"].as_array() {
            logs.extend(
                extra
                    .iter()
                    .map(|path| std::path::PathBuf::from(path.as_str().unwrap())),
            );
        }
        for path in logs {
            let bytes = fs::read(&path).unwrap();
            for secret in secrets {
                let secret = secret
                    .as_str()
                    .expect("forbidden log value must be text")
                    .as_bytes();
                assert!(!secret.is_empty(), "forbidden log value must not be empty");
                assert!(
                    !bytes.windows(secret.len()).any(|value| value == secret),
                    "credential leaked to {}",
                    path.display()
                );
            }
        }
    }
    drop(external_test);
}
