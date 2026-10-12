use libzondtest::{TestEnv, checked, serde_json::Value};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

fn cli(env: &TestEnv) -> Command {
    let mut cli = env.cli();
    cli.env("XDG_CONFIG_HOME", env.dir.path().join("caller config"));
    cli
}

#[test]
fn saved_connections_resolve_with_openssh_and_preserve_explicit_settings() {
    let env = TestEnv::new();
    let empty = checked(cli(&env).arg("connections"), 0);
    assert!(String::from_utf8_lossy(&empty.stdout).contains("No saved connections"));
    let base = env.dir.path().join("ssh defaults");
    fs::write(&base, "Host *\n User fallback\n Port 9999\n").unwrap();
    let key = env.dir.path().join("caller key");
    let result = checked(
        cli(&env)
            .args([
                "--host",
                "operator@receiver.example",
                "--port",
                "2222",
                "--identity",
            ])
            .arg(&key)
            .arg("--ssh-config")
            .arg(&base)
            .args(["connections", "add", "work"]),
        0,
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("zondctl --host work permissions"));
    let path = env
        .dir
        .path()
        .join("caller config/zondctl/connections/work.conf");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = fs::read(&path).unwrap();
    checked(
        cli(&env).args(["--host", "wrong.example", "connections", "add", "work"]),
        125,
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    let context: Value = serde_json::from_slice(
        &checked(cli(&env).args(["--host", "work", "--json", "context"]), 0).stdout,
    )
    .unwrap();
    assert_eq!(context["destination"], "operator@receiver.example");
    assert_eq!(context["port"], "2222");
    assert_eq!(context["transport"], "SSH");
    assert_eq!(context["identities"][0], key.to_str().unwrap());
    let changed: Value = serde_json::from_slice(
        &checked(
            cli(&env).args(["--host", "work", "--port", "3333", "--json", "context"]),
            0,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(changed["port"], "3333");
    let list: Value =
        serde_json::from_slice(&checked(cli(&env).args(["--json", "connections"]), 0).stdout)
            .unwrap();
    assert_eq!(list[0], context);
    checked(cli(&env).args(["connections", "remove", "work"]), 0);
    assert!(!path.exists());
    assert!(base.exists());
}

#[test]
fn irohs_and_local_sockets_have_explicit_context_without_a_daemon() {
    let env = TestEnv::new();
    let endpoint = "ab".repeat(32);
    checked(
        cli(&env)
            .arg("--host")
            .arg(format!("operator@{endpoint}"))
            .args(["--iroh", "connections", "add", "vm"]),
        0,
    );
    let context: Value = serde_json::from_slice(
        &checked(cli(&env).args(["--host", "vm", "--json", "context"]), 0).stdout,
    )
    .unwrap();
    assert_eq!(context["transport"], "Iroh SSH");
    assert_eq!(context["destination"], format!("operator@{endpoint}"));
    assert!(
        context["proxy"]
            .as_str()
            .unwrap()
            .contains("iroh-ssh proxy")
    );
    let local: Value =
        serde_json::from_slice(&checked(cli(&env).args(["--json", "context"]), 0).stdout).unwrap();
    assert_eq!(local["role"], "admin");
    assert_eq!(local["receiver"], "local");
    let caller: Value = serde_json::from_slice(
        &checked(
            cli(&env).args(["--principal", "exec", "--json", "context"]),
            0,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(caller["role"], "caller");
    env.stop_daemon();
    let failure = checked(cli(&env).arg("status"), 125);
    let stderr = String::from_utf8(failure.stderr).unwrap();
    assert!(
        stderr.contains("local socket")
            && stderr.contains("--host NAME")
            && stderr.contains("zondctl connections"),
        "{stderr}"
    );
}

#[test]
fn connection_storage_rejects_injection_and_symlinks() {
    let env = TestEnv::new();
    for (host, name) in [
        ("example.com", "../escape"),
        ("example.com\nProxyCommand bad", "work"),
    ] {
        checked(
            cli(&env).args(["--host", host, "connections", "add", name]),
            125,
        );
    }
    checked(
        cli(&env).args([
            "--host",
            "example.com",
            "--iroh",
            "connections",
            "add",
            "work",
        ]),
        125,
    );
    let dir = env.dir.path().join("caller config/zondctl/connections");
    fs::create_dir_all(&dir).unwrap();
    let target = env.dir.path().join("untouched");
    fs::write(&target, "Host work\n HostName wrong\n").unwrap();
    symlink(&target, dir.join("work.conf")).unwrap();
    checked(cli(&env).args(["--host", "work", "context"]), 125);
    checked(cli(&env).args(["connections", "remove", "work"]), 125);
    assert!(target.exists());
}
