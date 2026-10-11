use libzondtest::{
    Process, SshEnv, TestEnv, checked, read_until,
    serde_json::{Value, json},
};
use std::{fs, io::Write, time::Duration};

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
fn cli_proposes_observes_approves_invokes_and_revokes_rules() {
    let env = TestEnv::new();
    let path = env.dir.path().join("echo.zond");
    fs::write(&path, RULE).unwrap();
    let proposal = parse(checked(
        env.cli()
            .args(["--principal", "exec", "--json", "propose-rule", "--file"])
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
        env.cli()
            .args(["--principal", "exec", "--json", "propose-rule", RULE]),
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
#[ignore = "requires OpenSSH client/server"]
fn ssh_caller_proposals_and_rule_introspection_use_the_authenticated_principal() {
    let ssh = SshEnv::new();
    let proposal = parse(checked(
        ssh.remote("exec").args(["--json", "propose-rule", RULE]),
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
    let proposal =
        parse(checked(remote("exec").args(["propose-rule", RULE]), 0))["proposal"].clone();
    let id = proposal["id"].as_str().unwrap();
    checked(remote("ops").args(["withdraw", id]), 125);
    let withdrawn = parse(checked(remote("exec").args(["withdraw", id]), 0));
    assert_eq!(withdrawn["rule"]["status"], "withdrawn");
    assert_eq!(withdrawn["rule"]["proposal"], proposal);
    let replacement =
        parse(checked(remote("exec").args(["propose-rule", RULE]), 0))["proposal"].clone();
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
