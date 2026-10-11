use libzondtest::{TestEnv, checked, decoded, serde_json::json, wait_for};
use std::{fs, process::Command};

fn run_until_backgrounded(env: &TestEnv, program: &str, args: &[&str]) -> String {
    let mut caller = env.session(
        "exec",
        json!({"method":"run","command":{"program":program,"args":args}}),
    );
    let pending = caller.event();
    assert_eq!(pending["type"], "pending", "{pending}");
    assert_eq!(pending["request"]["detached"], true);
    let id = pending["request"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(env.queue()[0]["request_id"], id);
    assert_eq!(job(env, &id)["request"]["status"], "pending");
    let approval = pending["request"]["approval_id"].as_str().unwrap();
    assert_eq!(env.resolve(approval, true)["type"], "resolved");
    let submitted = caller.event();
    assert_eq!(submitted["type"], "submitted", "{submitted}");
    assert_eq!(submitted["request_id"], id);
    drop(caller);
    id
}

fn job(env: &TestEnv, id: &str) -> serde_json::Value {
    env.request("exec", json!({"method":"job","request_id":id}))
}

#[test]
fn long_running_request_backgrounds_without_restarting_and_streams_output() {
    let env = TestEnv::new();
    let gate = env.dir.path().join("stream-gate");
    libzondtest::nix::unistd::mkfifo(
        &gate,
        libzondtest::nix::sys::stat::Mode::S_IRUSR | libzondtest::nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let id = run_until_backgrounded(
        &env,
        env.probe.to_str().unwrap(),
        &["stream_gate", gate.to_str().unwrap()],
    );
    assert_eq!(
        env.request("ops", json!({"method":"job","request_id":id}))["type"],
        "error"
    );
    let mut follow = env.session("exec", json!({"method":"follow","request_id":id}));
    let first = follow.event();
    assert_eq!(first["type"], "output", "{first}");
    assert_eq!(decoded(&first, "data"), b"early\n");
    assert_eq!(job(&env, &id)["request"]["status"], "running");
    let cursor = first["sequence"].as_u64().unwrap();
    drop(follow);
    let mut follow = env.session(
        "exec",
        json!({"method":"follow","request_id":id,"after":cursor}),
    );
    use std::os::unix::fs::OpenOptionsExt;
    let mut release = None;
    wait_for(|| {
        release = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libzondtest::nix::libc::O_NONBLOCK)
            .open(&gate)
            .ok();
        release.is_some()
    });
    drop(release);
    let second = follow.event();
    assert_eq!(second["type"], "output", "{second}");
    assert_eq!(decoded(&second, "data"), b"late\n");
    assert_eq!(second["stderr"], true);
    let terminal = follow.event();
    assert_eq!(terminal["type"], "job", "{terminal}");
    assert_eq!(terminal["request"]["status"], "completed");
    assert_eq!(terminal["request"]["result"]["code"], 0);
    assert_eq!(terminal["request"]["detached"], true);
    assert_eq!(terminal["request"]["backgrounded"], true);
    assert_eq!(
        decoded(&terminal["request"]["result"], "stdout"),
        b"early\n"
    );
    assert_eq!(decoded(&terminal["request"]["result"], "stderr"), b"late\n");
}

#[test]
fn cancel_terminates_a_detached_process_group_and_preserves_status() {
    let env = TestEnv::new();
    let marker = env.owned_workdir().join("detached.pid");
    let id = run_until_backgrounded(
        &env,
        env.probe.to_str().unwrap(),
        &["sleep", marker.to_str().unwrap()],
    );
    wait_for(|| marker.exists());
    let pid: u32 = fs::read_to_string(marker).unwrap().parse().unwrap();
    assert_eq!(job(&env, &id)["request"]["status"], "running");
    assert_eq!(
        env.request("ops", json!({"method":"cancel","request_id":id}))["type"],
        "error"
    );
    assert_eq!(
        env.request("exec", json!({"method":"cancel","request_id":id}))["type"],
        "cancelled"
    );
    wait_for(|| !std::path::Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(job(&env, &id)["request"]["status"], "cancelled");
    assert_eq!(job(&env, &id)["request"]["reason"], "cancelled by operator");
}

#[test]
fn retained_output_is_bounded_and_follow_reports_lost_prefix() {
    let env = TestEnv::new();
    let id = run_until_backgrounded(&env, env.probe.to_str().unwrap(), &["streamlarge"]);
    wait_for(|| job(&env, &id)["request"]["status"] == "completed");
    let mut follow = env.session("exec", json!({"method":"follow","request_id":id}));
    assert_eq!(follow.event()["type"], "output_truncated");
    let chunk = follow.event();
    assert_eq!(chunk["type"], "output");
    assert_eq!(decoded(&chunk, "data"), vec![b'x'; 1024]);
    let terminal = follow.event();
    assert_eq!(terminal["request"]["status"], "completed");
    assert_eq!(terminal["request"]["output_truncated"], true);
    assert_eq!(
        decoded(&terminal["request"]["result"], "stdout"),
        vec![b'x'; 1024]
    );
}

#[test]
fn daemon_restart_interrupts_a_backgrounded_job_without_replaying_it() {
    let env = TestEnv::new();
    let marker = env.owned_workdir().join("restart.pid");
    let id = run_until_backgrounded(
        &env,
        env.probe.to_str().unwrap(),
        &["sleep", marker.to_str().unwrap()],
    );
    let pid: u32 = fs::read_to_string(marker).unwrap().parse().unwrap();
    env.stop_daemon();
    wait_for(|| !std::path::Path::new(&format!("/proc/{pid}")).exists());
    env.start_daemon();
    assert_eq!(job(&env, &id)["request"]["status"], "interrupted");
}

#[test]
fn cli_starts_and_follows_a_managed_job() {
    let env = TestEnv::new();
    let started = checked(
        env.cli().args([
            "--principal",
            "exec",
            "exec",
            "--detach",
            "/usr/bin/sleep",
            "3",
        ]),
        0,
    );
    let id = String::from_utf8(started.stdout).unwrap();
    let id = id.trim();
    let followed = checked(
        Command::new(&env.ctl)
            .env("XDG_RUNTIME_DIR", env.runtime.parent().unwrap())
            .args(["--principal", "exec", "follow", id]),
        0,
    );
    assert!(String::from_utf8_lossy(&followed.stderr).contains("completed"));
    assert_eq!(job(&env, id)["request"]["status"], "completed");
}

#[test]
fn named_operation_uses_the_same_automatic_backgrounding() {
    let env = TestEnv::new();
    let policy = env.policy.replace(
        "operations = [\"greet\"]",
        "operations = [\"greet\", \"wait\"]",
    ) + "\n[operations.wait]\nprogram = \"/usr/bin/sleep\"\nfixed_args = [\"3\"]\ndecision = \"allow\"\n";
    fs::write(&env.config, policy).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let submitted = env.request(
        "ops",
        json!({"method":"invoke","operation":"wait","args":[]}),
    );
    assert_eq!(submitted["type"], "submitted", "{submitted}");
    let id = submitted["request_id"].as_str().unwrap();
    let mut follow = env.session("ops", json!({"method":"follow","request_id":id}));
    assert_eq!(follow.event()["request"]["status"], "completed");
}
