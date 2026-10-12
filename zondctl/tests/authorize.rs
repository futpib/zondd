use libzondtest::{
    Process, SshEnv, TestEnv, checked, nix::pty::openpty, read_until, serde_json::json, wait_for,
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
    begin_with_runtime(env, key, keys, config, principal, None)
}

fn begin_with_runtime(
    env: &TestEnv,
    key: impl AsRef<OsStr>,
    keys: &Path,
    config: &Path,
    principal: &str,
    runtime: Option<&Path>,
) -> (Process, File) {
    let pty = openpty(None, None).unwrap();
    let slave = File::from(pty.slave);
    let mut command = env.cli();
    if let Some(runtime) = runtime {
        command.env("XDG_RUNTIME_DIR", runtime);
    }
    let process = Process::spawn(
        command
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

fn begin_revoke(env: &TestEnv, key: Option<&OsStr>, keys: &Path) -> (Process, File) {
    let pty = openpty(None, None).unwrap();
    let slave = File::from(pty.slave);
    let mut command = env.cli();
    command.arg("revoke-key");
    if let Some(key) = key {
        command.arg(key);
    } else {
        command.arg("--all");
    }
    let process = Process::spawn(
        command
            .arg("--authorized-keys")
            .arg(keys)
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
    let setup = read_until(&mut terminal, b"List saved receivers: zondctl connections");
    assert!(String::from_utf8_lossy(&setup).contains("connections add NAME"));
    assert!(process.wait(Duration::from_secs(5)).success());
    assert!(fs::read_to_string(&keys).unwrap().contains(public.trim()));
    assert!(
        fs::read_to_string(&keys)
            .unwrap()
            .contains(" --runtime-dir ")
    );
    let (mut process, mut terminal) = begin(&env, public.trim(), &keys, &config, "default");
    read_until(&mut terminal, b"no changes");
    assert!(process.wait(Duration::from_secs(5)).success());
}

#[test]
#[ignore = "requires ssh-keygen"]
fn default_runtime_entry_omits_redundant_bridge_arguments() {
    let env = TestEnv::new();
    let key = key(&env);
    let keys = env.dir.path().join("authorized_keys");
    let config = env.dir.path().join("missing.toml");
    let runtime = std::path::PathBuf::from(format!("/run/user/{}", libzond::paths::current_uid()));
    let (mut process, mut terminal) =
        begin_with_runtime(&env, &key, &keys, &config, "default", Some(&runtime));
    let preview = read_until(&mut terminal, b"[y/N] ");
    let public = fs::read_to_string(&key).unwrap();
    let entry = format!(
        "restrict,command=\"{} bridge\" {}",
        env.daemon.display(),
        public
    );
    assert!(String::from_utf8_lossy(&preview).contains(entry.trim()));
    terminal.write_all(b"n\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert!(!keys.exists());
}

#[test]
#[ignore = "requires ssh-keygen"]
fn existing_managed_entry_is_shortened_and_remains_revocable() {
    let env = TestEnv::new();
    let key = key(&env);
    let keys = env.dir.path().join("authorized_keys");
    let config = env.dir.path().join("missing.toml");
    let public = fs::read_to_string(&key).unwrap();
    let previous = format!(
        "restrict,command=\"'{}' bridge --runtime-dir '{}' --principal 'default'\" {}",
        env.daemon.display(),
        env.runtime.display(),
        public
    );
    fs::write(&keys, previous).unwrap();
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    let preview = read_until(&mut terminal, b"[y/N] ");
    assert!(String::from_utf8_lossy(&preview).contains("-restrict,command="));
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    let updated = fs::read_to_string(&keys).unwrap();
    assert_eq!(
        updated,
        format!(
            "restrict,command=\"{} bridge --runtime-dir {}\" {}",
            env.daemon.display(),
            env.runtime.display(),
            public
        )
    );
    let (mut process, mut terminal) = begin_revoke(&env, None, &keys);
    read_until(&mut terminal, b"[y/N] ");
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert!(fs::read_to_string(&keys).unwrap().is_empty());
}

fn key(env: &TestEnv) -> std::path::PathBuf {
    key_named(env, "caller")
}

fn key_named(env: &TestEnv, name: &str) -> std::path::PathBuf {
    let key = env.dir.path().join(name);
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
fn revoke_one_and_all_only_remove_zondd_bridge_entries() {
    let env = TestEnv::new();
    let first = key(&env);
    let second = key_named(&env, "second");
    let first_public = fs::read_to_string(&first).unwrap();
    let second_public = fs::read_to_string(&second).unwrap();
    let keys = env.dir.path().join("authorized_keys");
    let config = env.dir.path().join("missing.toml");
    for key in [&first, &second] {
        let (mut process, mut terminal) = begin(&env, key, &keys, &config, "default");
        read_until(&mut terminal, b"[y/N] ");
        terminal.write_all(b"y\n").unwrap();
        assert!(process.wait(Duration::from_secs(5)).success());
    }
    let managed = fs::read_to_string(&keys).unwrap();
    let unrelated = format!(
        "# keep this comment\n{first_public}from=\"127.0.0.1\" {first_public}restrict,command=\"/usr/bin/id\" {second_public}"
    );
    let legacy = format!(
        "restrict,command=\"/home/old/.cargo/bin/zondd bridge --principal default\" {first_public}"
    );
    let minimal = format!("restrict,command=\"/usr/bin/zondd bridge\" {second_public}");
    fs::write(&keys, format!("{managed}{unrelated}{legacy}{minimal}")).unwrap();
    let original = fs::read_to_string(&keys).unwrap();
    let (mut process, mut terminal) =
        begin_revoke(&env, Some(OsStr::new(first_public.trim())), &keys);
    let preview = read_until(&mut terminal, b"[y/N] ");
    assert!(String::from_utf8_lossy(&preview).contains("-restrict,command="));
    terminal.write_all(b"n\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert_eq!(fs::read_to_string(&keys).unwrap(), original);
    let (mut process, mut terminal) = begin_revoke(&env, Some(first.as_os_str()), &keys);
    read_until(&mut terminal, b"[y/N] ");
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    let remaining = fs::read_to_string(&keys).unwrap();
    assert!(!remaining.contains(&legacy));
    assert!(remaining.contains(&unrelated));
    assert_eq!(remaining.matches("restrict,command=").count(), 3);
    let (mut process, mut terminal) = begin_revoke(&env, Some(first.as_os_str()), &keys);
    read_until(&mut terminal, b"no changes.");
    assert!(process.wait(Duration::from_secs(5)).success());
    assert_eq!(fs::read_to_string(&keys).unwrap(), remaining);
    let (mut process, mut terminal) = begin_revoke(&env, None, &keys);
    read_until(&mut terminal, b"[y/N] ");
    terminal.write_all(b"yes\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert_eq!(fs::read_to_string(&keys).unwrap(), unrelated);
    assert_eq!(
        fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let actions = env.request("admin", json!({"method":"actions"}));
    for action in ["control.revoke_key", "control.revoke_all_keys"] {
        assert!(
            actions["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["action"] == action)
        );
    }
}

#[test]
#[ignore = "requires ssh-keygen"]
fn revoke_rejects_concurrent_edits_and_symlinks() {
    let env = TestEnv::new();
    let key = key(&env);
    let keys = env.dir.path().join("authorized_keys");
    let config = env.dir.path().join("missing.toml");
    let (mut process, mut terminal) = begin(&env, &key, &keys, &config, "default");
    read_until(&mut terminal, b"[y/N] ");
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    let original = fs::read_to_string(&keys).unwrap();
    let (mut process, mut terminal) = begin_revoke(&env, None, &keys);
    read_until(&mut terminal, b"[y/N] ");
    fs::write(&keys, format!("{original}# concurrent edit\n")).unwrap();
    terminal.write_all(b"y\n").unwrap();
    assert_eq!(process.wait(Duration::from_secs(5)).code(), Some(125));
    assert!(
        fs::read_to_string(&keys)
            .unwrap()
            .ends_with("# concurrent edit\n")
    );
    let link = env.dir.path().join("linked_keys");
    std::os::unix::fs::symlink(&keys, &link).unwrap();
    let (mut process, mut terminal) = begin_revoke(&env, None, &link);
    read_until(&mut terminal, b"symlink");
    assert_eq!(process.wait(Duration::from_secs(5)).code(), Some(125));
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
    let (mut process, mut terminal) = begin_revoke(&ssh.env, Some(key.as_os_str()), &keys);
    read_until(&mut terminal, b"[y/N] ");
    terminal.write_all(b"y\n").unwrap();
    assert!(process.wait(Duration::from_secs(5)).success());
    assert_eq!(fs::read_to_string(&keys).unwrap(), original);
    checked(ssh.remote("unknown").arg("permissions"), 125);
}

#[test]
#[ignore = "requires OpenSSH client/server"]
fn bridge_without_principal_uses_the_default_policy() {
    let ssh = SshEnv::new();
    ssh.env.stop_daemon();
    fs::remove_file(&ssh.env.config).unwrap();
    ssh.env
        .start(ssh.env.daemon_command().arg("serve"), "default-daemon");
    wait_for(|| ssh.env.runtime.join("default.sock").exists());
    let public = fs::read_to_string(ssh.env.dir.path().join("unknown-key.pub")).unwrap();
    fs::write(
        ssh.env.dir.path().join("authorized_keys"),
        format!(
            "restrict,command=\"{} bridge --runtime-dir {}\" {public}",
            ssh.env.daemon.display(),
            ssh.env.runtime.display()
        ),
    )
    .unwrap();
    let output = checked(ssh.remote("unknown").args(["--json", "permissions"]), 0);
    let event: libzondtest::serde_json::Value =
        libzondtest::serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(event["permissions"]["principal"], "default");
}
