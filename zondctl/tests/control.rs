use libzondtest::{
    Process, TestEnv, command, read_json,
    serde_json::{Value, json},
};
use std::{io::Write, process::Stdio, time::Duration};

fn control(env: &TestEnv, request: Value) -> Value {
    let mut child = Process::spawn(
        env.cli()
            .arg("control")
            .arg("--config")
            .arg(&env.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let mut stdin = child.child.stdin.take().unwrap();
    writeln!(stdin, "{request}").unwrap();
    let reply = read_json(child.child.stdout.as_mut().unwrap());
    // SSH callers need not close stdin for the helper to exit.
    child.wait(Duration::from_secs(5));
    reply
}

#[test]
fn management_resolves_requests_and_rejects_stale_or_invalid_configuration() {
    let env = TestEnv::new();
    for approve in [true, false] {
        let (mut caller, id) = env.pending(command("/usr/bin/printf", &["%s", "manage"]));
        let queue = control(&env, json!({"version":1,"method":"pending"}));
        assert_eq!(queue["result"]["requests"][0]["approval_id"], id, "{queue}");
        assert_eq!(
            control(
                &env,
                json!({"version":1,"method":"resolve","approval_id":id,"approve":approve})
            )["ok"],
            true
        );
        assert_eq!(
            caller.event()["type"],
            if approve { "completed" } else { "rejected" }
        );
    }
    let original = control(&env, json!({"version":1,"method":"read_config"}));
    let revision = &original["result"]["revision"];
    let changed = format!("{}\n# saved by test\n", env.policy);
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"save_config","content":"invalid","revision":revision})
        )["ok"],
        false
    );
    assert_eq!(std::fs::read_to_string(&env.config).unwrap(), env.policy);
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"save_config","content":changed,"revision":revision})
        )["ok"],
        true
    );
    let stale = control(
        &env,
        json!({"version":1,"method":"save_config","content":env.policy,"revision":revision}),
    );
    assert!(stale["error"].as_str().unwrap().contains("changed"));
    assert_eq!(std::fs::read_to_string(&env.config).unwrap(), changed);
    assert_eq!(
        control(&env, json!({"version":1,"method":"pending","unknown":true}))["ok"],
        false
    );
    assert_eq!(
        control(&env, json!({"version":99,"method":"pending"}))["ok"],
        false
    );
    assert_eq!(
        control(
            &env,
            json!({"version":1,"method":"service","action":"arbitrary-shell-command"})
        )["ok"],
        false
    );
}

#[test]
fn local_principal_runs_the_same_caller_protocol() {
    let env = TestEnv::new();
    assert_eq!(
        libzondtest::checked(
            env.cli()
                .args(["--principal", "ops", "invoke", "greet", "world"]),
            0
        )
        .stdout,
        b"hello world"
    );
    libzondtest::checked(env.cli().args(["--principal", "ops", "pending"]), 126);
    libzondtest::checked(env.cli().args(["--principal", "../admin", "pending"]), 125);
}
