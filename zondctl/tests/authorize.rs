use libzondtest::{
    Process, SshEnv, TestEnv, checked, nix::pty::openpty, read_until, serde_json::json,
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    time::Duration,
};

fn begin(
    env: &TestEnv,
    key: impl AsRef<OsStr>,
    keys: &Path,
    config: &Path,
    principal: &str,
) -> (Process, File) {
    let pty = openpty(None, None).unwrap();
    let slave = File::from(pty.slave);
    let process = Process::spawn(
        env.cli()
            .arg("authorize-key")
            .arg(key)
            .arg("--zondd")
            .arg(&env.daemon)
            .arg("--authorized-keys")
            .arg(keys)
            .arg("--config")
            .arg(config)
            .arg("--principal")
            .arg(principal)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave),
    );
    (process, File::from(pty.master))
}

#[test]
#[ignore = "requires ssh-keygen"]
fn inline_public_key_is_reviewed_and_installed_without_a_file_argument() {
    let env = TestEnv::new();
    let key = key(&env);
    let public = fs::read_to_string(&key).unwrap();
    let config = env.dir.path().join("missing/config.toml");
    let keys = env.dir.path().join("new-ssh/authorized_keys");
    let (mut process, mut terminal) = begin(&env, public.trim(), &keys, &config, "default");
    let preview = read_until(&mut terminal, b"[y/N] ");
    assert!(String::from_utf8_lossy(&preview).contains(public.trim()));
    assert!(!keys.exists());
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert!(fs::read_to_string(&keys).unwrap().contains(public.trim()));
    let (mut process, mut terminal) = begin(&env, public.trim(), &keys, &config, "default");
    read_until(&mut terminal, b"no changes");
    assert!(process.wait(Duration::from_secs(5)).success());
}

fn key(env: &TestEnv) -> std::path::PathBuf {
    let key = env.dir.path().join("caller");
    checked(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key),
        0,
    );
    key.with_extension("pub")
}

#[test]
#[ignore = "requires ssh-keygen"]
fn diff_precedes_confirmation_and_decline_leaves_configuration_absent() {
    let env = TestEnv::new();
    let key = key(&env);
    let config = env.dir.path().join("missing/config.toml");
    let keys = env.dir.path().join("new-ssh/authorized_keys");
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    let preview = read_until(&mut terminal, b"[y/N] ");
    assert!(String::from_utf8_lossy(&preview).contains("+restrict,command="));
    assert!(!keys.parent().unwrap().exists());
    terminal.write_all(b"n\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert!(!keys.parent().unwrap().exists());
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    read_until(&mut terminal, b"[y/N] ");
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert!(
        fs::read_to_string(&keys)
            .unwrap()
            .starts_with("restrict,command=")
    );
    assert_eq!(
        fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!config.exists());
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    read_until(&mut terminal, b"no changes");
    assert!(process.wait(Duration::from_secs(5)).success());
}

#[test]
#[ignore = "requires ssh-keygen"]
fn concurrent_edits_and_existing_ssh_restrictions_are_preserved() {
    let env = TestEnv::new();
    let key = key(&env);
    let config = env.dir.path().join("missing.toml");
    let keys = env.dir.path().join("authorized_keys");
    fs::write(&keys, "# original\n").unwrap();
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    read_until(&mut terminal, b"[y/N] ");
    fs::write(&keys, "# concurrent edit\n").unwrap();
    terminal.write_all(b"y\n").unwrap();
    assert_eq!(process.wait(Duration::from_secs(5)).code(), Some(125));
    assert_eq!(fs::read_to_string(&keys).unwrap(), "# concurrent edit\n");
    let original = format!("from=\"127.0.0.1\" {}", fs::read_to_string(&key).unwrap());
    fs::write(&keys, &original).unwrap();
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    read_until(&mut terminal, b"merge those restrictions manually");
    assert_eq!(process.wait(Duration::from_secs(5)).code(), Some(125));
    assert_eq!(fs::read_to_string(&keys).unwrap(), original);
    fs::remove_file(&keys).unwrap();
    std::os::unix::fs::symlink(&config, &keys).unwrap();
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    read_until(&mut terminal, b"symlink");
    assert_eq!(process.wait(Duration::from_secs(5)).code(), Some(125));
    assert!(!config.exists());
}

#[test]
#[ignore = "requires OpenSSH client/server"]
fn enrolled_key_runs_the_protocol_and_cannot_run_a_shell_command() {
    let mut ssh = SshEnv::new();
    let quoted = ssh.env.dir.path().join("receiver 'quoted\"$ bin");
    fs::copy(&ssh.env.daemon, &quoted).unwrap();
    ssh.env.daemon = quoted;
    let key = ssh.env.dir.path().join("unknown-key.pub");
    let keys = ssh.env.dir.path().join("authorized_keys");
    let original = fs::read_to_string(&keys).unwrap();
    // Convert an existing normal login key, removing every unrestricted duplicate.
    let public = fs::read_to_string(&key).unwrap();
    fs::write(&keys, format!("{original}{public}{public}")).unwrap();
    let (mut process, mut terminal) = begin(&ssh.env, &key, &keys, &ssh.env.config, "exec");
    let diff = read_until(&mut terminal, b"[y/N] ");
    assert!(String::from_utf8_lossy(&diff).contains("-ssh-ed25519"));
    terminal.write_all(b"yes\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    let actual = fs::read_to_string(&keys).unwrap();
    assert!(actual.starts_with(&original));
    assert_eq!(actual.matches(public.trim()).count(), 1);
    let actions = ssh.env.request("admin", json!({"method":"actions"}));
    assert!(
        actions["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "control.authorize_key" && a["detail"]["principal"] == "exec")
    );
    assert_eq!(
        checked(
            ssh.remote("unknown")
                .args(["exec", "/usr/bin/printf", "%s", "hello"]),
            0
        )
        .stdout,
        b"hello"
    );
    checked(
        Command::new("ssh")
            .arg("-F")
            .arg(&ssh.config)
            .arg("-p")
            .arg(ssh.port.to_string())
            .arg("-i")
            .arg(ssh.env.dir.path().join("unknown-key"))
            .args(["-T", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"])
            .arg(format!("{}@127.0.0.1", ssh.env.user.name))
            .arg("/usr/bin/id"),
        1,
    );
}
