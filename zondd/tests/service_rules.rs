use libzondtest::{
    Session, TestEnv, checked, output,
    serde_json::{Value, json},
    wait_for,
};
use std::{fs, path::PathBuf, process::Command};

fn approve(env: &TestEnv, unit: &str, command: &str) -> Value {
    let source = format!(
        "rule guarded() {{\n  require user-service-active-or-enabled \"{unit}\"\n  run {command}\n}}"
    );
    let event = env.request("exec", json!({"method":"propose_rule", "source":source}));
    assert_eq!(event["type"], "rule_proposed", "{event}");
    let proposal = &event["proposal"];
    let reviewed = proposal["review"].to_string();
    assert!(reviewed.contains("LoadState=loaded"));
    assert!(reviewed.contains("Manually stopped enabled services still pass"));
    assert!(reviewed.contains("do not inherit"));
    assert_eq!(env.request("admin", json!({"method":"resolve_rule", "proposal_id":proposal["id"], "digest":proposal["digest"], "approve":true}))["type"], "rule_resolved");
    proposal.clone()
}

fn check(env: &TestEnv) -> Value {
    env.request(
        "exec",
        json!({"method":"check", "input":{"method":"invoke", "operation":"guarded", "args":[]}}),
    )["check"]
        .clone()
}

fn invoke(env: &TestEnv) -> Value {
    let event = env.request(
        "exec",
        json!({"method":"invoke", "operation":"guarded", "args":[]}),
    );
    if event["type"] == "submitted" {
        env.request(
            "exec",
            json!({"method":"follow", "request_id":event["request_id"]}),
        )["request"]["result"]
            .clone()
    } else {
        event
    }
}

#[test]
fn unavailable_manager_denies_preview_and_execution_without_running_the_command() {
    let env = TestEnv::new();
    env.stop_daemon();
    env.start(
        env.daemon_command()
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/missing-bus", env.dir.path().display()),
            )
            .arg("serve"),
        "unavailable-manager",
    );
    wait_for(|| env.runtime.join("exec.sock").exists());
    let marker = env.dir.path().join("must-not-exist");
    approve(
        &env,
        "test.service",
        &format!("touch \"{}\"", marker.display()),
    );
    let check = check(&env);
    assert_eq!(check["decision"], "deny", "{check}");
    assert!(
        check["reason"]
            .as_str()
            .unwrap()
            .contains("require user-service-active-or-enabled")
    );
    let result = invoke(&env);
    assert_eq!(result["type"], "error", "{result}");
    assert!(!marker.exists());
}

#[test]
#[ignore = "requires systemctl"]
fn a_stalled_service_query_times_out_without_blocking_admin_requests() {
    use std::{io::Read, os::unix::net::UnixListener, time::Duration};
    let env = TestEnv::new();
    let private = env.runtime.parent().unwrap().join("systemd");
    fs::create_dir(&private).unwrap();
    let listener = UnixListener::bind(private.join("private")).unwrap();
    listener.set_nonblocking(true).unwrap();
    approve(&env, "test.service", "true");
    let socket = env.runtime.join("exec.sock");
    let query = std::thread::spawn(move || {
        Session::new(&socket, json!({"method":"check", "input":{"method":"invoke", "operation":"guarded", "args":[]}})).event()
    });
    let mut peer = None;
    wait_for(|| {
        peer = listener.accept().ok().map(|(stream, _)| stream);
        peer.is_some()
    });
    let mut peer = peer.unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"status"}))["type"],
        "status"
    );
    assert!(
        !query.is_finished(),
        "the query must remain blocked while admin responds"
    );
    let response = query.join().unwrap();
    assert_eq!(response["check"]["decision"], "deny", "{response}");
    assert!(
        response["check"]["reason"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
    // EOF confirms the timed-out systemctl process no longer holds the connection.
    peer.read_to_end(&mut Vec::new()).unwrap();
}

#[test]
#[ignore = "requires systemctl"]
fn cancelling_a_service_query_prevents_the_reviewed_command_from_starting() {
    use std::{io::Read, os::unix::net::UnixListener, time::Duration};
    let env = TestEnv::new();
    let private = env.runtime.parent().unwrap().join("systemd");
    fs::create_dir(&private).unwrap();
    let listener = UnixListener::bind(private.join("private")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let marker = env.dir.path().join("must-not-exist");
    approve(
        &env,
        "test.service",
        &format!("touch \"{}\"", marker.display()),
    );
    let _caller = env.session(
        "exec",
        json!({"method":"invoke", "operation":"guarded", "args":[]}),
    );
    let mut peer = None;
    wait_for(|| {
        peer = listener.accept().ok().map(|(stream, _)| stream);
        peer.is_some()
    });
    let id = env.request("admin", json!({"method":"history"}))["requests"][0]["request_id"].clone();
    let cancelled = env.request("exec", json!({"method":"cancel", "request_id":id}));
    assert_eq!(cancelled["type"], "cancelled", "{cancelled}");
    let mut peer = peer.unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    peer.read_to_end(&mut Vec::new()).unwrap();
    assert_eq!(
        env.request("exec", json!({"method":"job", "request_id":id}))["request"]["status"],
        "cancelled"
    );
    assert!(!marker.exists());
}

struct Service {
    name: String,
    unit: PathBuf,
    runtime: PathBuf,
}

impl Service {
    fn new(env: &TestEnv) -> Self {
        let runtime =
            PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("user manager required"));
        let name = format!(
            "{}-guard.service",
            env.dir
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .trim_start_matches('.')
        );
        let units = runtime.join("systemd/user");
        fs::create_dir_all(&units).unwrap();
        let service = Self {
            unit: units.join(&name),
            name,
            runtime,
        };
        fs::write(&service.unit, "[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=exec\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=default.target\n").unwrap();
        service.ctl(&["daemon-reload"]);
        // Only the runtime socket directory is isolated; talk to the real user manager.
        env.stop_daemon();
        fs::write(
            &env.config,
            format!("runtime_dir = {:?}\n{}", env.runtime, env.policy),
        )
        .unwrap();
        env.start(
            env.daemon_command()
                .env("XDG_RUNTIME_DIR", &service.runtime)
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={}/bus", service.runtime.display()),
                )
                .arg("serve"),
            "service-manager",
        );
        wait_for(|| env.runtime.join("exec.sock").exists());
        service
    }

    fn ctl(&self, args: &[&str]) {
        checked(
            Command::new("/usr/bin/systemctl").arg("--user").args(args),
            0,
        );
    }

    fn property(&self, name: &str) -> String {
        String::from_utf8(
            checked(
                Command::new("/usr/bin/systemctl").args([
                    "--user",
                    "show",
                    "--value",
                    "--property",
                    name,
                    "--",
                    &self.name,
                ]),
                0,
            )
            .stdout,
        )
        .unwrap()
        .trim()
        .into()
    }

    fn fail(&self) {
        self.ctl(&["kill", "--signal=KILL", &self.name]);
        wait_for(|| self.property("ActiveState") == "failed");
    }

    fn denied(&self, env: &TestEnv) {
        let id = self.property("InvocationID");
        let check = check(env);
        assert_eq!(check["decision"], "deny", "{check}");
        assert_eq!(invoke(env)["type"], "error");
        assert_eq!(self.property("InvocationID"), id);
    }

    fn allowed(&self, env: &TestEnv) {
        let id = self.property("InvocationID");
        let check = check(env);
        assert_eq!(check["decision"], "allow", "{check}");
        let result = invoke(env);
        assert_eq!(result["code"], 0, "{result}");
        assert_eq!(self.property("ActiveState"), "active");
        assert_ne!(self.property("InvocationID"), id);
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        for args in [
            vec!["stop", &self.name],
            vec!["disable", "--runtime", &self.name],
            vec!["reset-failed", &self.name],
        ] {
            let _ = output(Command::new("/usr/bin/systemctl").arg("--user").args(args));
        }
        let _ = fs::remove_file(&self.unit);
        let _ = output(Command::new("/usr/bin/systemctl").args(["--user", "daemon-reload"]));
    }
}

#[test]
#[ignore = "requires a running systemd user manager"]
fn real_user_service_can_restart_if_active_or_start_if_enabled() {
    let env = TestEnv::new();
    let service = Service::new(&env);
    let proposal = approve(
        &env,
        &service.name,
        &format!("systemctl --user restart -- \"{}\"", service.name),
    );
    for method in ["rules", "permissions"] {
        let event = env.request("exec", json!({"method":method}));
        let rules = if method == "rules" {
            &event["rules"]
        } else {
            &event["permissions"]["rules"]
        };
        assert_eq!(rules[0]["proposal"], proposal);
    }
    assert_eq!(service.property("UnitFileState"), "disabled");
    service.denied(&env);
    service.ctl(&["start", &service.name]);
    service.allowed(&env);
    service.fail();
    service.denied(&env);
    service.ctl(&["enable", "--runtime", &service.name]);
    assert_eq!(service.property("UnitFileState"), "enabled-runtime");
    service.allowed(&env);
    service.ctl(&["stop", &service.name]);
    service.allowed(&env);

    service.ctl(&["stop", &service.name]);
    assert_eq!(check(&env)["decision"], "allow");
    service.ctl(&["disable", "--runtime", &service.name]);
    // A successful preview is not authorization to use stale enablement at execution.
    assert_eq!(invoke(&env)["type"], "error");
    assert_eq!(service.property("ActiveState"), "inactive");

    fs::write(
        &service.unit,
        "[Service]\nType=exec\nExecStart=/usr/bin/sleep infinity\n",
    )
    .unwrap();
    service.ctl(&["daemon-reload"]);
    assert_eq!(service.property("UnitFileState"), "static");
    service.denied(&env);
    service.ctl(&["start", &service.name]);
    service.allowed(&env);
    service.ctl(&["stop", &service.name]);
    fs::remove_file(&service.unit).unwrap();
    std::os::unix::fs::symlink("/dev/null", &service.unit).unwrap();
    service.ctl(&["daemon-reload"]);
    service.denied(&env);
    fs::remove_file(&service.unit).unwrap();
    service.ctl(&["daemon-reload"]);
    service.denied(&env);
}
