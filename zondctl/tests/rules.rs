use libzondtest::{
    Process, SshEnv, TestEnv, checked,
    nix::sys::signal::Signal,
    read_json, read_until,
    serde_json::{Value, json},
    wait_for,
};
use std::{
    fs,
    io::{Read, Seek, Write},
    process::Stdio,
    time::Duration,
};

const RULE: &str = r#"rule echo-rule(x: repo-name) { run printf "%s" "$x" }"#;

fn parse(output: std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cli_leaves_rule_language_validation_to_the_receiver() {
    let env = TestEnv::new();
    // A newer daemon may know this type; the CLI must forward the source untouched.
    let response = parse(checked(
        env.cli().args([
            "--principal",
            "exec",
            "--json",
            "propose-rule",
            "rule future(x: ticket-id) { run printf '%s' \"$x\" }",
        ]),
        125,
    ));
    assert_eq!(response["type"], "error");
    assert!(
        response["message"]
            .as_str()
            .unwrap()
            .contains("unknown type 'ticket-id'")
    );
}

#[test]
fn cli_forwards_local_definitions_and_invokes_correlated_choices_with_exact_bounds() {
    let env = TestEnv::new();
    let source = r#"type view = choice(resource, market) {
 balances = ("balances", "portfolio")
 positions = ("positions", "usdm")
}
type cursor = uint(0, 18446744073709551615)
rule typed(v: view, n: cursor) {
 run printf "%s:%s:%s" "${v.resource}" "${v.market}" "$n"
}"#;
    let path = env.dir.path().join("typed.zond");
    std::fs::write(&path, source).unwrap();
    let event = parse(checked(
        env.cli()
            .args([
                "--principal",
                "exec",
                "--json",
                "propose-rule",
                "--no-wait",
                "--file",
            ])
            .arg(path),
        0,
    ));
    let proposal = &event["proposal"];
    assert_eq!(proposal["source"], source);
    assert_eq!(
        proposal["bound"]["rule"]["types"][1]["definition"]["max"],
        "18446744073709551615"
    );
    checked(
        env.cli().args([
            "approve-rule",
            proposal["id"].as_str().unwrap(),
            "--digest",
            proposal["digest"].as_str().unwrap(),
            "--permanent",
        ]),
        0,
    );
    let result = checked(
        env.cli().args([
            "--principal",
            "exec",
            "invoke",
            "typed",
            "positions",
            "18446744073709551615",
        ]),
        0,
    );
    assert_eq!(result.stdout, b"positions:usdm:18446744073709551615");
    for args in [
        vec!["positions", "18446744073709551616"],
        vec!["other", "1"],
        vec!["positions", "1", "portfolio"],
    ] {
        checked(
            env.cli()
                .args(["--principal", "exec", "invoke", "typed"])
                .args(args),
            125,
        );
    }
}

#[test]
fn cli_proposes_observes_approves_invokes_and_revokes_rules() {
    let env = TestEnv::new();
    let path = env.dir.path().join("echo.zond");
    fs::write(&path, RULE).unwrap();
    let proposal = parse(checked(
        env.cli()
            .args([
                "--principal",
                "exec",
                "--json",
                "propose-rule",
                "--no-wait",
                "--file",
            ])
            .arg(path),
        0,
    ))["proposal"]
        .clone();
    let id = proposal["id"].as_str().unwrap();
    let digest = proposal["digest"].as_str().unwrap();
    let rules = parse(checked(
        env.cli().args(["--principal", "exec", "--json", "rules"]),
        0,
    ));
    assert_eq!(rules["rules"][0]["status"], "pending");
    checked(env.cli().args(["approve-rule", id, "--digest", digest]), 2);
    let approved = parse(checked(
        env.cli().args([
            "--json",
            "approve-rule",
            id,
            "--digest",
            digest,
            "--for-secs",
            "3600",
        ]),
        0,
    ));
    assert_eq!(approved["rule"]["status"], "active");
    assert_eq!(
        checked(
            env.cli()
                .args(["--principal", "exec", "invoke", "echo-rule", "literal"]),
            0
        )
        .stdout,
        b"literal"
    );
    let check = parse(checked(
        env.cli().args([
            "--principal",
            "exec",
            "--json",
            "check",
            "invoke",
            "echo-rule",
            "literal",
        ]),
        0,
    ));
    assert_eq!(check["check"]["rule"]["grant_id"], id);
    checked(
        env.cli()
            .args(["--principal", "exec", "invoke", "echo-rule", "../escape"]),
        125,
    );
    checked(env.cli().args(["revoke-rule", id]), 0);
    let rules = parse(checked(
        env.cli().args(["--principal", "exec", "--json", "rules"]),
        0,
    ));
    assert_eq!(rules["rules"][0]["status"], "revoked");
    let proposal = parse(checked(
        env.cli().args([
            "--principal",
            "exec",
            "--json",
            "propose-rule",
            "--no-wait",
            RULE,
        ]),
        0,
    ))["proposal"]
        .clone();
    checked(
        env.cli().args([
            "deny-rule",
            proposal["id"].as_str().unwrap(),
            "--digest",
            proposal["digest"].as_str().unwrap(),
        ]),
        0,
    );
    assert_eq!(
        parse(checked(
            env.cli().args(["--principal", "exec", "--json", "rules"]),
            0
        ))["rules"][0]["status"],
        "denied"
    );
}

#[test]
fn interactive_review_distinguishes_reusable_grants_from_one_time_approval() {
    use libzondtest::nix::pty::openpty;
    let env = TestEnv::new();
    env.request("exec", json!({"method":"propose_rule","source":RULE}));
    let pty = openpty(None, None).unwrap();
    let mut master = fs::File::from(pty.master);
    let slave = fs::File::from(pty.slave);
    let mut review = Process::spawn(
        env.cli()
            .arg("review")
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave),
    );
    let text = String::from_utf8(read_until(&mut master, b"quit [q]: ")).unwrap();
    assert!(
        text.contains("repeated invocations")
            && text.contains("repo-name")
            && text.contains("approve until revoked"),
        "{text}"
    );
    master.write_all(b"a\n").unwrap();
    read_until(&mut master, b"rule_resolved");
    let rules = env.request("exec", json!({"method":"rules"}));
    assert_eq!(rules["rules"][0]["status"], "active");
    assert!(rules["rules"][0]["grant_expires_unix_ms"].is_number());
    review.stop();
    review.wait(Duration::from_secs(2));
}

#[test]
fn proposal_waits_by_default_and_json_streams_the_exact_approval() {
    let env = TestEnv::new();
    let path = env.dir.path().join("echo.zond");
    fs::write(&path, RULE).unwrap();
    let mut caller = Process::spawn(
        env.cli()
            .args(["--principal", "exec", "--json", "propose-rule", "--file"])
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let proposed = read_json(caller.child.stdout.as_mut().unwrap());
    assert_eq!(proposed["type"], "rule_proposed");
    let pending = read_json(caller.child.stdout.as_mut().unwrap());
    assert_eq!(pending["type"], "rule_pending");
    assert_eq!(pending["proposal"], proposed["proposal"]);
    assert!(caller.child.try_wait().unwrap().is_none());
    let proposal = &proposed["proposal"];
    assert_eq!(
        env.request(
            "exec",
            json!({"method":"invoke","operation":"echo-rule","args":["early"]})
        )["type"],
        "error"
    );
    assert_eq!(env.request("admin", json!({"method":"resolve_rule","proposal_id":proposal["id"],"digest":proposal["digest"],"approve":true,"expires_in_secs":3600}))["type"], "rule_resolved");
    let resolved = read_json(caller.child.stdout.as_mut().unwrap());
    assert_eq!(resolved["type"], "rule_resolved");
    assert_eq!(resolved["rule"]["status"], "active");
    assert_eq!(resolved["rule"]["proposal"], *proposal);
    assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(0));
    let mut stderr = String::new();
    caller
        .child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(
        checked(
            env.cli()
                .args(["--principal", "exec", "invoke", "echo-rule", "approved"]),
            0
        )
        .stdout,
        b"approved"
    );
}

#[test]
fn rule_wait_notices_and_quiet_mode_preserve_results() {
    for quiet in [false, true] {
        let env = TestEnv::new();
        let mut command = env.cli();
        command.args(["--principal", "exec"]);
        if quiet {
            command.arg("--quiet");
        }
        let mut output = tempfile::tempfile().unwrap();
        let mut caller = Process::spawn(
            command
                .args(["propose-rule", RULE])
                .stdout(output.try_clone().unwrap())
                .stderr(Stdio::piped()),
        );
        let mut proposals = Vec::new();
        wait_for(|| {
            proposals = env.request("admin", json!({"method":"pending"}))["proposals"]
                .as_array()
                .unwrap()
                .clone();
            !proposals.is_empty()
        });
        let proposal = &proposals[0];
        if !quiet {
            let notice = String::from_utf8(read_until(
                caller.child.stderr.as_mut().unwrap(),
                b"Withdraw:",
            ))
            .unwrap();
            assert!(notice.contains("Receiver:"), "{notice}");
            assert!(notice.contains("Waiting for approval in Zond"), "{notice}");
            assert!(notice.contains("Expires in"), "{notice}");
            assert!(
                notice.contains(proposal["id"].as_str().unwrap()),
                "{notice}"
            );
            assert!(
                notice.contains("wait-rule") && notice.contains("rules"),
                "{notice}"
            );
            assert!(notice.contains("leaves the proposal pending"), "{notice}");
        }
        assert!(caller.child.try_wait().unwrap().is_none());
        env.request("admin", json!({"method":"resolve_rule","proposal_id":proposal["id"],"digest":proposal["digest"],"approve":true}));
        assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(0));
        let mut stdout = String::new();
        output.rewind().unwrap();
        output.read_to_string(&mut stdout).unwrap();
        let events: Vec<Value> = serde_json::Deserializer::from_str(&stdout)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["proposal"], *proposal);
        assert_eq!(events[1]["rule"]["status"], "active");
        if quiet {
            let mut stderr = String::new();
            caller
                .child
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(stderr.is_empty(), "{stderr}");
        }
    }
}

#[test]
fn ctrl_c_leaves_rule_pending_and_wait_can_resume_after_restart() {
    let env = TestEnv::new();
    fs::write(
        &env.config,
        env.policy.replace("timeout_secs = 4", "timeout_secs = 60"),
    )
    .unwrap();
    checked(env.cli().arg("reload"), 0);
    let mut caller = Process::spawn(
        env.cli()
            .args(["--principal", "exec", "--json", "propose-rule", RULE])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let proposal = read_json(caller.child.stdout.as_mut().unwrap())["proposal"].clone();
    assert_eq!(
        read_json(caller.child.stdout.as_mut().unwrap())["type"],
        "rule_pending"
    );
    caller.signal(Signal::SIGINT);
    assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(130));
    assert_eq!(
        env.request("exec", json!({"method":"rules"}))["rules"][0]["status"],
        "pending"
    );
    env.stop_daemon();
    env.start_daemon();
    let id = proposal["id"].as_str().unwrap();
    let mut resumed = Process::spawn(
        env.cli()
            .args(["--principal", "exec", "--json", "wait-rule", id])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(
        read_json(resumed.child.stdout.as_mut().unwrap())["proposal"],
        proposal
    );
    env.stop_daemon();
    assert_eq!(resumed.wait(Duration::from_secs(5)).code(), Some(125));
    let mut stderr = String::new();
    resumed
        .child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("resume with") && stderr.contains("wait-rule") && stderr.contains(id),
        "{stderr}"
    );
    env.start_daemon();
    let mut resumed = Process::spawn(
        env.cli()
            .args(["--principal", "exec", "--json", "wait-rule", id])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(
        read_json(resumed.child.stdout.as_mut().unwrap())["proposal"],
        proposal
    );
    env.request("admin", json!({"method":"resolve_rule","proposal_id":id,"digest":proposal["digest"],"approve":true}));
    assert_eq!(
        read_json(resumed.child.stdout.as_mut().unwrap())["rule"]["status"],
        "active"
    );
    assert_eq!(resumed.wait(Duration::from_secs(5)).code(), Some(0));
    assert_eq!(
        parse(checked(
            env.cli()
                .args(["--principal", "exec", "--json", "wait-rule", id]),
            0
        ))["rule"]["proposal"],
        proposal
    );
    checked(env.cli().args(["revoke-rule", id]), 0);
    assert_eq!(
        parse(checked(
            env.cli()
                .args(["--principal", "exec", "--json", "wait-rule", id]),
            126
        ))["rule"]["status"],
        "revoked"
    );
}

#[test]
fn waiting_returns_failure_for_every_unsuccessful_proposal_outcome() {
    for outcome in ["denied", "withdrawn", "invalidated", "expired"] {
        let env = TestEnv::new();
        let mut caller = Process::spawn(
            env.cli()
                .args(["--principal", "exec", "--json", "propose-rule", RULE])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
        let proposal = read_json(caller.child.stdout.as_mut().unwrap())["proposal"].clone();
        assert_eq!(
            read_json(caller.child.stdout.as_mut().unwrap())["type"],
            "rule_pending"
        );
        match outcome {
            "denied" => {
                env.request("admin", json!({"method":"resolve_rule","proposal_id":proposal["id"],"digest":proposal["digest"],"approve":false}));
            }
            "withdrawn" => {
                env.request("exec", json!({"method":"withdraw","id":proposal["id"]}));
            }
            "invalidated" => {
                fs::write(
                    &env.config,
                    env.policy.replace("timeout_secs = 4", "timeout_secs = 5"),
                )
                .unwrap();
                checked(env.cli().arg("reload"), 0);
            }
            "expired" => {}
            _ => unreachable!(),
        }
        let result = read_json(caller.child.stdout.as_mut().unwrap());
        assert_eq!(result["rule"]["status"], outcome);
        assert_eq!(result["rule"]["proposal"], proposal);
        assert_eq!(caller.wait(Duration::from_secs(5)).code(), Some(126));
        assert_eq!(
            parse(checked(
                env.cli().args([
                    "--principal",
                    "exec",
                    "--json",
                    "wait-rule",
                    proposal["id"].as_str().unwrap()
                ]),
                126
            )),
            result
        );
    }
}

fn remote_proposal_wait(mut command: std::process::Command, env: &TestEnv) {
    let mut caller = Process::spawn(
        command
            .args(["--json", "propose-rule", RULE])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let proposal = read_json(caller.child.stdout.as_mut().unwrap())["proposal"].clone();
    assert_eq!(
        read_json(caller.child.stdout.as_mut().unwrap())["proposal"],
        proposal
    );
    assert!(caller.child.try_wait().unwrap().is_none());
    env.request("admin", json!({"method":"resolve_rule","proposal_id":proposal["id"],"digest":proposal["digest"],"approve":true}));
    assert_eq!(
        read_json(caller.child.stdout.as_mut().unwrap())["rule"]["status"],
        "active"
    );
    assert_eq!(caller.wait(Duration::from_secs(10)).code(), Some(0));
}

#[test]
#[ignore = "requires OpenSSH client/server"]
fn ssh_rule_proposal_waits_for_approval() {
    let ssh = SshEnv::new();
    remote_proposal_wait(ssh.remote("exec"), &ssh.env);
}

#[test]
#[ignore = "requires OpenSSH client/server and iroh-ssh"]
fn iroh_rule_proposal_waits_for_approval() {
    let ssh = SshEnv::new();
    fs::write(
        &ssh.env.config,
        ssh.env
            .policy
            .replace("timeout_secs = 4", "timeout_secs = 60"),
    )
    .unwrap();
    checked(ssh.env.cli().arg("reload"), 0);
    let endpoint = ssh.start_iroh();
    let mut command = std::process::Command::new(&ssh.env.ctl);
    command
        .arg("--host")
        .arg(format!("{}@{endpoint}", ssh.env.user.name))
        .arg("--iroh")
        .arg("--identity")
        .arg(ssh.env.dir.path().join("exec-key"))
        .arg("--ssh-config")
        .arg(&ssh.config);
    remote_proposal_wait(command, &ssh.env);
}

#[test]
#[ignore = "requires OpenSSH client/server"]
fn ssh_caller_proposals_and_rule_introspection_use_the_authenticated_principal() {
    let ssh = SshEnv::new();
    let proposal = parse(checked(
        ssh.remote("exec")
            .args(["--json", "propose-rule", "--no-wait", RULE]),
        0,
    ))["proposal"]
        .clone();
    assert_eq!(
        parse(checked(ssh.remote("ops").args(["--json", "rules"]), 0))["rules"],
        json!([])
    );
    checked(
        ssh.remote("exec").args([
            "approve-rule",
            proposal["id"].as_str().unwrap(),
            "--digest",
            proposal["digest"].as_str().unwrap(),
            "--permanent",
        ]),
        126,
    );
    checked(
        ssh.env.cli().args([
            "approve-rule",
            proposal["id"].as_str().unwrap(),
            "--digest",
            proposal["digest"].as_str().unwrap(),
            "--permanent",
        ]),
        0,
    );
    assert_eq!(
        checked(
            ssh.remote("exec").args(["invoke", "echo-rule", "ssh-repo"]),
            0
        )
        .stdout,
        b"ssh-repo"
    );
    let permissions = parse(checked(
        ssh.remote("exec").args(["--json", "permissions"]),
        0,
    ));
    assert_eq!(permissions["permissions"]["rules"][0]["status"], "active");
    checked(
        ssh.remote("ops")
            .args(["withdraw", proposal["id"].as_str().unwrap()]),
        125,
    );
    let withdrawn = parse(checked(
        ssh.remote("exec")
            .args(["--json", "withdraw", proposal["id"].as_str().unwrap()]),
        0,
    ));
    assert_eq!(withdrawn["rule"]["status"], "withdrawn");
    assert_eq!(withdrawn["rule"]["proposal"], proposal);
    checked(
        ssh.remote("exec")
            .args(["invoke", "echo-rule", "after-withdrawal"]),
        125,
    );
}

#[test]
#[ignore = "requires OpenSSH client/server and iroh-ssh"]
fn iroh_caller_can_withdraw_a_pending_proposal_and_submit_its_replacement() {
    let ssh = SshEnv::new();
    fs::write(
        &ssh.env.config,
        ssh.env
            .policy
            .replace("timeout_secs = 4", "timeout_secs = 60"),
    )
    .unwrap();
    checked(ssh.env.cli().arg("reload"), 0);
    let endpoint = ssh.start_iroh();
    let remote = |principal: &str| {
        let mut command = std::process::Command::new(&ssh.env.ctl);
        command
            .arg("--host")
            .arg(format!("{}@{endpoint}", ssh.env.user.name))
            .arg("--iroh")
            .arg("--identity")
            .arg(ssh.env.dir.path().join(format!("{principal}-key")))
            .arg("--ssh-config")
            .arg(&ssh.config)
            .arg("--json");
        command
    };
    let proposal = parse(checked(
        remote("exec").args(["propose-rule", "--no-wait", RULE]),
        0,
    ))["proposal"]
        .clone();
    let id = proposal["id"].as_str().unwrap();
    checked(remote("ops").args(["withdraw", id]), 125);
    let withdrawn = parse(checked(remote("exec").args(["withdraw", id]), 0));
    assert_eq!(withdrawn["rule"]["status"], "withdrawn");
    assert_eq!(withdrawn["rule"]["proposal"], proposal);
    let replacement = parse(checked(
        remote("exec").args(["propose-rule", "--no-wait", RULE]),
        0,
    ))["proposal"]
        .clone();
    assert_ne!(replacement["id"], proposal["id"]);
    checked(
        remote("exec").args(["withdraw", replacement["id"].as_str().unwrap()]),
        0,
    );
    let audit = ssh
        .env
        .request("admin", json!({"method":"actions","limit":100}));
    assert!(
        audit["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "rule_withdrawn" && a["detail"]["proposal"] == proposal)
    );
}
