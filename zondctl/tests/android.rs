//! A real Android app, SSH server, Iroh server, and user daemon; no mocked transport.
use libzondtest::{Process, SshEnv, checked, serde_json::json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::Duration,
};

#[test]
#[ignore = "requires Flutter, Android SDK/NDK, a running emulator, OpenSSH and iroh-ssh"]
fn android_management_over_ssh_and_iroh() {
    let ssh = SshEnv::new();
    ssh.env.stop_daemon();
    fs::write(
        &ssh.env.config,
        ssh.env
            .policy
            .replace("timeout_secs = 4", "timeout_secs = 120"),
    )
    .unwrap();
    ssh.env.start_daemon();
    let endpoint = ssh.start_iroh();
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
    let fixture = json!({
        "host":"10.0.2.2", "port":ssh.port, "endpoint":endpoint,
        "user":ssh.env.user.name, "runtime":ssh.env.runtime, "config":ssh.env.config,
        "executable":ssh.env.ctl, "fingerprint":fingerprint,
        "key":fs::read_to_string(ssh.env.dir.path().join("management-key")).unwrap(),
        "callerKey":fs::read_to_string(ssh.env.dir.path().join("exec-key")).unwrap(),
    });
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
    let app = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../android-app");
    let log = fs::File::create(ssh.env.dir.path().join("android.log")).unwrap();
    let mut process = Process::spawn(
        Command::new(std::env::var("FLUTTER").unwrap_or_else(|_| "flutter".into()))
            .current_dir(app)
            .args([
                "test",
                "integration_test/control_test.dart",
                "integration_test/workflow_test.dart",
                "-d",
            ])
            .arg(std::env::var("ZONDD_ANDROID_DEVICE").unwrap_or_else(|_| "emulator-5554".into()))
            .arg("--dart-define-from-file")
            .arg(&definitions)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log),
    );
    assert!(
        process.wait(Duration::from_secs(1200)).success(),
        "Android integration failed"
    );
    assert!(ssh.env.queue().is_empty());
}
