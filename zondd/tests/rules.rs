use libzondtest::{
    Session, TestEnv, checked, decoded,
    nix::{sys::stat::Mode, unistd::mkfifo},
    serde_json::{Value, json},
    wait_for,
};
use std::{fs, io::Write, os::unix::fs::symlink, path::Path, process::Command};

fn propose(env: &TestEnv, source: &str) -> Value {
    let event = env.request("exec", json!({"method":"propose_rule", "source":source}));
    assert_eq!(event["type"], "rule_proposed", "{event}");
    event["proposal"].clone()
}

fn resolve(env: &TestEnv, proposal: &Value, approve: bool, seconds: Option<u64>) -> Value {
    env.request("admin", json!({"method":"resolve_rule", "proposal_id":proposal["id"], "digest":proposal["digest"], "approve":approve, "expires_in_secs":seconds}))
}

fn approve(env: &TestEnv, source: &str) -> Value {
    let proposal = propose(env, source);
    let event = resolve(env, &proposal, true, None);
    assert_eq!(event["type"], "rule_resolved", "{event}");
    proposal
}

fn invoke(env: &TestEnv, name: &str, args: &[&str]) -> Value {
    env.request(
        "exec",
        json!({"method":"invoke", "operation":name, "args":args}),
    )
}

fn states(env: &TestEnv, principal: &str) -> Vec<Value> {
    env.request(principal, json!({"method":"rules"}))["rules"]
        .as_array()
        .unwrap()
        .clone()
}

fn no_staging(root: &Path) -> bool {
    fs::read_dir(root).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".zondd-new-")
    })
}

#[test]
fn review_is_generated_by_the_receiver_and_included_in_the_approval_digest() {
    let env = TestEnv::new();
    let source = r#"rule reviewed(x: repo-name) {
  require is-dir "$HOME/code"
  require absent "$HOME/code/$x"
  create-new "$HOME/code/$x" as dest {
    run mkdir "$dest" '$x'
  }
}"#;
    assert!(
        serde_json::from_value::<libzond::Request>(json!({
            "method": "propose_rule", "source": source,
            "review": {"version": 1, "title": "Caller-supplied misinformation", "sections": []}
        }))
        .is_err()
    );
    let proposal = &propose(&env, source);
    let review = &proposal["review"];
    assert_eq!(review["version"], 1);
    assert_eq!(review["title"], "reviewed");
    // Bridges preserve unknown review versions and fields for the UI to assess.
    let mut future = json!({"type": "rule_proposed", "proposal": proposal});
    future["proposal"]["review"]["version"] = json!(2);
    future["proposal"]["review"]["new_required_field"] = json!({"unknown": true});
    let forwarded: libzond::Event = serde_json::from_value(future.clone()).unwrap();
    assert_eq!(serde_json::to_value(forwarded).unwrap(), future);
    let field = |title: &str, label: &str| {
        review["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["title"] == title)
            .unwrap()["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == label)
            .unwrap()["value"]
            .as_str()
            .unwrap()
    };
    assert!(
        field("Parameters (positional order)", "x: repo-name")
            .contains("[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
    );
    assert!(field("Checks", "is-dir").contains("without following symlinks"));
    assert!(field("Checks", "absent").contains("no dangling symlink"));
    assert!(field("Effects", "create-new").contains("atomically"));
    assert_eq!(
        field("Effects", "Destination"),
        "${HOME} + \"/code/\" + ${x}"
    );
    assert_eq!(field("Command arguments", "Argument 1"), "${dest}");
    assert_eq!(field("Command arguments", "Argument 2"), "\"$x\"");

    let mut unsigned: libzond::rules::Proposal = serde_json::from_value(proposal.clone()).unwrap();
    let digest = std::mem::take(&mut unsigned.digest);
    let hash = |p: &libzond::rules::Proposal| {
        libzond::config::revision(&serde_json::to_string(p).unwrap())
    };
    assert_eq!(hash(&unsigned), digest);
    unsigned.review.as_mut().unwrap()["sections"][0]["fields"][0]["value"] =
        json!("Different authority");
    let changed_digest = hash(&unsigned);
    assert_ne!(changed_digest, digest);
    let rejected = env.request(
        "admin",
        json!({
            "method":"resolve_rule", "proposal_id":proposal["id"],
            "digest":changed_digest, "approve":true
        }),
    );
    assert_eq!(rejected["type"], "error");
    for method in ["rules", "permissions", "pending"] {
        let response = env.request(
            if method == "pending" { "admin" } else { "exec" },
            json!({"method":method}),
        );
        let observed = match method {
            "rules" => &response["rules"][0]["proposal"],
            "permissions" => &response["permissions"]["rules"][0]["proposal"],
            _ => &response["proposals"][0],
        };
        assert_eq!(observed["review"], *review);
        assert_eq!(observed["digest"], digest);
    }
}

#[test]
fn changed_or_legacy_reviews_require_new_approval_after_restart() {
    let env = TestEnv::new();
    fs::write(
        &env.config,
        env.policy.replace("timeout_secs = 4", "timeout_secs = 120"),
    )
    .unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let mut legacy = approve(&env, "rule legacy() { run true }");
    let mut changed = approve(&env, "rule changed() { run true }");
    let mut pending = propose(&env, "rule pending() { run true }");
    let unchanged = approve(&env, "rule unchanged() { run true }");
    env.stop_daemon();
    legacy.as_object_mut().unwrap().remove("review");
    changed["review"]["sections"][0]["fields"][0]["value"] = json!("Old semantics");
    pending["review"]["version"] = json!(2);
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    for proposal in [&legacy, &changed, &pending] {
        let id = proposal["id"].as_str().unwrap();
        let raw: String = db
            .query_row(
                "SELECT record FROM rule_states WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        let mut state: Value = serde_json::from_str(&raw).unwrap();
        state["proposal"] = proposal.clone();
        db.execute(
            "UPDATE rule_states SET record = ?1 WHERE id = ?2",
            [state.to_string().as_str(), id],
        )
        .unwrap();
    }
    drop(db);
    env.start_daemon();
    let rules = states(&env, "exec");
    for proposal in [&legacy, &changed, &pending] {
        let state = rules
            .iter()
            .find(|s| s["proposal"]["id"] == proposal["id"])
            .unwrap();
        assert_eq!(state["status"], "invalidated");
        assert!(
            state["reason"]
                .as_str()
                .unwrap()
                .contains("rule review changed or is missing")
        );
        assert_eq!(
            invoke(
                &env,
                proposal["bound"]["rule"]["name"].as_str().unwrap(),
                &[]
            )["type"],
            "error"
        );
        assert_eq!(resolve(&env, proposal, true, None)["type"], "error");
    }
    assert_eq!(invoke(&env, "unchanged", &[])["code"], 0);
    assert_eq!(
        rules
            .iter()
            .find(|s| s["proposal"]["id"] == unchanged["id"])
            .unwrap()["proposal"]["digest"],
        unchanged["digest"]
    );
}

#[test]
fn approved_clone_runs_offline_survives_restart_and_is_observable_only_to_its_caller() {
    let env = TestEnv::new();
    let root = env.owned_workdir();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    checked(
        Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(source.join("repo.git")),
        0,
    );
    let source = format!(
        r#"rule clone-local(x: repo-name) {{
  require is-dir "{root}"
  create-new "{root}/$x" as dest {{
    run git clone -- "{root}/source/$x.git" "$dest"
  }}
}}"#,
        root = root.display()
    );
    let proposal = propose(&env, &source);
    let before = env.request("exec", json!({"method":"permissions"}))["permissions"].clone();
    assert_eq!(states(&env, "exec")[0]["status"], "pending");
    assert_eq!(states(&env, "exec")[0]["proposal"]["source"], source);
    assert!(states(&env, "ops").is_empty());
    assert_ne!(invoke(&env, "clone-local", &["repo"])["type"], "completed");
    assert_eq!(
        env.request("admin", json!({"method":"pending"}))["proposals"][0]["digest"],
        proposal["digest"]
    );
    assert_eq!(
        resolve(&env, &proposal, true, None)["rule"]["status"],
        "active"
    );
    let permissions = env.request("exec", json!({"method":"permissions"}));
    assert_ne!(
        permissions["permissions"]["rules_revision"],
        before["rules_revision"]
    );
    assert_eq!(permissions["permissions"]["revision"], before["revision"]);
    assert_eq!(
        permissions["permissions"]["rules_revision"],
        env.request("exec", json!({"method":"rules"}))["revision"]
    );
    assert_eq!(
        permissions["permissions"]["rules"][0]["proposal"]["bound"]["rule"]["parameters"][0]["kind"],
        "repo-name"
    );
    let check = env.request("exec", json!({"method":"check","input":{"method":"invoke","operation":"clone-local","args":["repo"]}}));
    assert_eq!(check["check"]["decision"], "allow", "{check}");
    assert_eq!(
        check["check"]["rule"]["destination"],
        root.join("repo").to_str().unwrap()
    );
    assert!(!root.join("repo").exists());
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(states(&env, "exec")[0]["status"], "active");
    let result = invoke(&env, "clone-local", &["repo"]);
    assert_eq!(result["code"], 0, "{result}");
    assert!(root.join("repo/.git/objects").is_dir());
    assert_eq!(
        checked(
            Command::new("git")
                .arg("-C")
                .arg(root.join("repo"))
                .args(["rev-parse", "--is-inside-work-tree"]),
            0
        )
        .stdout,
        b"true\n"
    );
    assert!(no_staging(&root));
    assert_eq!(invoke(&env, "clone-local", &["repo"])["type"], "error");
    assert_eq!(
        env.request(
            "ops",
            json!({"method":"invoke","operation":"clone-local","args":["repo"]})
        )["type"],
        "error"
    );
    let event = env.request(
        "admin",
        json!({"method":"revoke_rule","grant_id":proposal["id"]}),
    );
    assert_eq!(event["type"], "rule_revoked");
    assert_eq!(states(&env, "exec")[0]["status"], "revoked");
    assert_eq!(invoke(&env, "clone-local", &["repo"])["type"], "error");
}

#[test]
fn raw_protocol_cannot_bypass_types_approval_digest_or_principal_scope() {
    let env = TestEnv::new();
    let source = r#"rule echo-name(x: repo-name) { run printf "%s" "$x" }"#;
    let proposal = propose(&env, source);
    let approval = json!({"method":"resolve_rule","proposal_id":proposal["id"],"digest":proposal["digest"],"approve":true});
    assert_eq!(env.request("exec", approval.clone())["type"], "rejected");
    let mut wrong = approval.clone();
    wrong["digest"] = json!("wrong");
    assert_eq!(env.request("admin", wrong)["type"], "error");
    assert_eq!(states(&env, "exec")[0]["status"], "pending");
    assert_eq!(env.request("admin", approval)["type"], "rule_resolved");
    for value in [
        "../escape",
        "a/b",
        "-c",
        "a;id",
        "$(id)",
        "a b",
        "a\nb",
        "a\0b",
        "λ",
        "a\u{200b}",
        &"a".repeat(101),
    ] {
        let event = invoke(&env, "echo-name", &[value]);
        assert_eq!(event["type"], "error", "{event}");
        assert!(
            event["message"].as_str().unwrap().contains("repo-name"),
            "{event}"
        );
    }
    assert_eq!(
        decoded(&invoke(&env, "echo-name", &["my.repo-1"]), "stdout"),
        b"my.repo-1"
    );
    assert_eq!(
        env.request(
            "exec",
            json!({"method":"revoke_rule","grant_id":proposal["id"]})
        )["type"],
        "rejected"
    );
    assert_eq!(
        env.request("admin", json!({"method":"propose_rule","source":source}))["type"],
        "rejected"
    );
    assert_eq!(
        env.request("exec", json!({"method":"propose_rule","source":source}))["type"],
        "error"
    );
    let source = format!(
        "rule restricted() {{ run {} no_new_privs }}",
        env.probe.display()
    );
    approve(&env, &source);
    assert_eq!(decoded(&invoke(&env, "restricted", &[]), "stdout"), b"1\n");
    approve(
        &env,
        r#"rule literals() { run printf "%s" '$(touch SHOULD_NOT_EXIST) ; *' }"#,
    );
    assert_eq!(
        decoded(&invoke(&env, "literals", &[]), "stdout"),
        b"$(touch SHOULD_NOT_EXIST) ; *"
    );
}

#[test]
fn rejected_expired_and_changed_rules_remain_visible_with_reasons() {
    let env = TestEnv::new();
    let proposal = propose(&env, "rule denied() { run true }");
    assert_eq!(
        resolve(&env, &proposal, false, None)["rule"]["status"],
        "denied"
    );
    let proposal = propose(&env, "rule expiring() { run true }");
    assert_eq!(
        resolve(&env, &proposal, true, Some(1))["rule"]["status"],
        "active"
    );
    wait_for(|| {
        states(&env, "exec")
            .iter()
            .any(|s| s["proposal"]["id"] == proposal["id"] && s["status"] == "expired")
    });
    assert_eq!(invoke(&env, "expiring", &[])["type"], "error");
    let pending = propose(&env, "rule pending() { run true }");
    let active = approve(&env, "rule active() { run true }");
    fs::write(&env.config, format!("{}\n# unrelated change\n", env.policy)).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    assert_eq!(invoke(&env, "active", &[])["code"], 0);
    assert_eq!(resolve(&env, &pending, true, None)["type"], "error");
    fs::write(
        &env.config,
        env.policy
            .replace("default = \"ask\"", "default = \"deny\""),
    )
    .unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let rules = states(&env, "exec");
    assert!(
        rules
            .iter()
            .any(|s| s["proposal"]["id"] == active["id"] && s["status"] == "invalidated")
    );
    assert!(rules.iter().any(|s| s["status"] == "denied"));
    assert_eq!(invoke(&env, "active", &[])["type"], "error");
}

#[test]
fn preconditions_are_checked_at_execution_and_existing_entries_are_never_replaced() {
    let env = TestEnv::new();
    let root = env.owned_workdir();
    let source = format!(
        r#"rule guarded(x: repo-name) {{
  require absent "{root}/blocked"
  create-new "{root}/$x" as dest {{ run mkdir "$dest" }}
}}"#,
        root = root.display()
    );
    approve(&env, &source);
    fs::write(root.join("blocked"), "stop").unwrap();
    assert_eq!(invoke(&env, "guarded", &["new"])["type"], "error");
    assert!(!root.join("new").exists());
    fs::remove_file(root.join("blocked")).unwrap();
    fs::create_dir(root.join("dir")).unwrap();
    fs::write(root.join("file"), "keep").unwrap();
    symlink(root.join("missing"), root.join("link")).unwrap();
    for name in ["dir", "file", "link"] {
        assert_eq!(invoke(&env, "guarded", &[name])["type"], "error");
    }
    assert_eq!(fs::read_to_string(root.join("file")).unwrap(), "keep");
    assert!(
        fs::symlink_metadata(root.join("link"))
            .unwrap()
            .is_symlink()
    );
    assert!(no_staging(&root));
    assert_eq!(invoke(&env, "guarded", &["new"])["code"], 0);
}

fn gate(env: &TestEnv, root: &Path, outcome: &str) -> (Session, std::path::PathBuf) {
    let ready = root.join("ready");
    let gate = root.join("gate");
    mkfifo(&gate, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    let source = format!(
        r#"rule gated() {{ create-new "{root}/target" as dest {{
  run "{probe}" create_new_gate "$dest" "{ready}" "{gate}" "{outcome}"
}} }}"#,
        root = root.display(),
        probe = env.probe.display(),
        ready = ready.display(),
        gate = gate.display()
    );
    approve(env, &source);
    let session = env.session(
        "exec",
        json!({"method":"invoke","operation":"gated","args":[]}),
    );
    wait_for(|| ready.exists());
    assert!(!root.join("target").exists());
    (session, gate)
}

#[test]
fn atomic_publication_loses_a_race_without_touching_the_winner() {
    let env = TestEnv::new();
    let root = env.owned_workdir();
    let (mut session, gate) = gate(&env, &root, "success");
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("target/keep"), "winner").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(gate)
        .unwrap()
        .write_all(b"go")
        .unwrap();
    let event = session.event();
    let event = if event["type"] == "submitted" {
        env.request(
            "exec",
            json!({"method":"follow","request_id":event["request_id"]}),
        )
    } else {
        event
    };
    assert!(
        event["message"]
            .as_str()
            .is_some_and(|m| m.contains("not replaced"))
            || event["request"]["reason"]
                .as_str()
                .is_some_and(|m| m.contains("not replaced")),
        "{event}"
    );
    assert_eq!(
        fs::read_to_string(root.join("target/keep")).unwrap(),
        "winner"
    );
    assert!(!root.join("target/payload").exists());
    wait_for(|| no_staging(&root));
}

#[test]
fn failed_or_cancelled_commands_never_publish_partial_directories() {
    for cancel in [false, true] {
        let env = TestEnv::new();
        let root = env.owned_workdir();
        let (mut session, gate) = gate(&env, &root, "fail");
        if cancel {
            let detached = session.event();
            assert_eq!(detached["type"], "submitted", "{detached}");
            drop(session);
            let record = env.request("admin", json!({"method":"history"}))["requests"][0].clone();
            assert_eq!(
                env.request(
                    "exec",
                    json!({"method":"cancel","request_id":record["request_id"]})
                )["type"],
                "cancelled"
            );
        } else {
            fs::OpenOptions::new()
                .write(true)
                .open(gate)
                .unwrap()
                .write_all(b"go")
                .unwrap();
            let event = session.event();
            assert_eq!(event["code"], 7, "{event}");
        }
        wait_for(|| no_staging(&root));
        assert!(!root.join("target").exists());
    }
}

#[test]
fn an_admitted_background_job_finishes_after_revocation_without_restarting() {
    let env = TestEnv::new();
    let root = env.owned_workdir();
    let (mut session, gate) = gate(&env, &root, "success");
    let detached = session.event();
    assert_eq!(detached["type"], "submitted");
    drop(session);
    let grant = states(&env, "exec")[0]["proposal"]["id"].clone();
    assert_eq!(
        env.request("admin", json!({"method":"revoke_rule","grant_id":grant}))["type"],
        "rule_revoked"
    );
    fs::OpenOptions::new()
        .write(true)
        .open(gate)
        .unwrap()
        .write_all(b"go")
        .unwrap();
    let result = env.request(
        "exec",
        json!({"method":"follow","request_id":detached["request_id"]}),
    );
    assert_eq!(result["request"]["result"]["code"], 0, "{result}");
    assert_eq!(
        fs::read_to_string(root.join("target/payload")).unwrap(),
        "new output"
    );
    assert!(no_staging(&root));
    assert_eq!(invoke(&env, "gated", &[])["type"], "error");
}

#[test]
fn pending_proposals_survive_restart_and_failed_reload_does_not_change_grants() {
    let env = TestEnv::new();
    let proposal = propose(&env, "rule pending() { run true }");
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(
        states(&env, "exec")[0]["proposal"]["digest"],
        proposal["digest"]
    );
    fs::write(&env.config, "malformed TOML").unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "error"
    );
    assert_eq!(
        resolve(&env, &proposal, true, None)["rule"]["status"],
        "active"
    );
    assert_eq!(invoke(&env, "pending", &[])["code"], 0);
    fs::write(&env.config, &env.policy).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    assert_eq!(states(&env, "exec")[0]["status"], "active");
}

#[test]
fn cancellation_racing_publication_reports_the_actual_commit_outcome() {
    for _ in 0..8 {
        let env = TestEnv::new();
        let root = env.owned_workdir();
        let (_session, gate) = gate(&env, &root, "success");
        let id =
            env.request("admin", json!({"method":"history"}))["requests"][0]["request_id"].clone();
        let socket = env.runtime.join("exec.sock");
        let request_id = id.clone();
        let cancellation = std::thread::spawn(move || {
            Session::new(&socket, json!({"method":"cancel","request_id":request_id})).event()
        });
        fs::OpenOptions::new()
            .write(true)
            .open(gate)
            .unwrap()
            .write_all(b"go")
            .unwrap();
        cancellation.join().unwrap();
        wait_for(|| no_staging(&root));
        let result = env.request("exec", json!({"method":"job","request_id":id}));
        match result["request"]["status"].as_str().unwrap() {
            "cancelled" => assert!(!root.join("target").exists()),
            "completed" => assert_eq!(
                fs::read_to_string(root.join("target/payload")).unwrap(),
                "new output"
            ),
            other => panic!("unexpected final status {other}: {result}"),
        }
    }
}
