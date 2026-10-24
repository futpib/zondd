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
fn local_types_are_reviewed_bound_to_the_digest_and_enforced_after_restart() {
    let env = TestEnv::new();
    let source = r#"type view = choice(fields=(resource, market)) {
 balances = (resource="balances", market="portfolio")
 accounts = (resource="accounts", market="portfolio")
 positions = (resource="positions", market="usdm")
}
type selected = view
type count = integer(minimum_inclusive=0, maximum_exclusive=1001)
rule typed(v: selected, n: count) {
 run printf "%s:%s:%s" "${v.resource}" "${v.market}" "$n"
}"#;
    let proposal = propose(&env, source);
    assert_eq!(
        proposal["bound"]["rule"]["language_version"],
        libzond::rules::LANGUAGE_VERSION
    );
    let review = proposal["review"].to_string();
    assert!(
        review.contains("Local type definitions")
            && review.contains("positions")
            && review.contains("usdm")
            && review.contains("No other combinations")
    );
    let mut unsigned: libzond::rules::Proposal = serde_json::from_value(proposal.clone()).unwrap();
    let digest = std::mem::take(&mut unsigned.digest);
    assert_eq!(
        libzond::config::revision(&serde_json::to_string(&unsigned).unwrap()),
        digest
    );
    unsigned.bound.rule.types[0].definition = libzond::rules::TypeKind::Choice {
        fields: vec!["resource".into(), "market".into()],
        cases: std::collections::BTreeMap::from([(
            "positions".into(),
            vec!["positions".into(), "portfolio".into()],
        )]),
    };
    assert_ne!(
        libzond::config::revision(&serde_json::to_string(&unsigned).unwrap()),
        digest
    );
    assert_eq!(
        resolve(&env, &proposal, true, None)["rule"]["status"],
        "active"
    );
    for (selector, market) in [
        ("balances", "portfolio"),
        ("accounts", "portfolio"),
        ("positions", "usdm"),
    ] {
        let result = invoke(&env, "typed", &[selector, "1000"]);
        assert_eq!(result["type"], "completed", "{result}");
        assert_eq!(
            decoded(&result, "stdout"),
            format!("{selector}:{market}:1000").as_bytes()
        );
    }
    for args in [
        vec!["positions", "1001"],
        vec!["positions", "01"],
        vec!["unknown", "1"],
        vec!["positions", "1", "portfolio"],
        vec!["positions,portfolio", "1"],
    ] {
        let result = invoke(&env, "typed", &args);
        assert_eq!(result["type"], "error", "{result}");
        let check = env.request(
            "exec",
            json!({"method":"check","input":{"method":"invoke","operation":"typed","args":args}}),
        );
        assert_ne!(check["check"]["decision"], "allow", "{check}");
    }
    env.stop_daemon();
    env.start_daemon();
    let state = &states(&env, "exec")[0];
    assert_eq!(state["status"], "active", "{state}");
    assert_eq!(state["proposal"], proposal);
    assert_eq!(
        decoded(&invoke(&env, "typed", &["positions", "0"]), "stdout"),
        b"positions:usdm:0"
    );
}

#[test]
fn home_paths_expand_on_the_receiver_and_new_home_spellings_are_rejected() {
    let env = TestEnv::new();
    let before = states(&env, "exec");
    for word in ["$HOME/code", "\"${HOME}/code\""] {
        let result = env.request(
            "exec",
            json!({"method":"propose_rule","source":format!("rule old() {{ run printf {word} }}")}),
        );
        assert_eq!(result["type"], "error");
        assert!(
            result["message"].as_str().unwrap().contains("use ~"),
            "{result}"
        );
    }
    assert_eq!(states(&env, "exec"), before);
    let proposal = approve(&env, "rule home() { run printf '%s' \"~/code\" }");
    let expected = libzond::paths::home_dir().join("code");
    assert_eq!(
        decoded(&invoke(&env, "home", &[]), "stdout"),
        expected.to_str().unwrap().as_bytes()
    );
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(states(&env, "exec")[0]["proposal"], proposal);
}

#[path = "../src/rules/migration/previous.rs"]
mod previous;

// Sign modified fixtures using the serialization that produced the old approval.
fn sign_previous(state: &mut Value) -> String {
    let proposal = &mut state["proposal"];
    proposal["digest"] = "".into();
    let fields = [
        "id",
        "principal",
        "source",
        "bound",
        "review",
        "digest",
        "revision",
        "principal_revision",
        "created_unix_ms",
        "expires_unix_ms",
    ];
    let unsigned = format!(
        "{{{}}}",
        fields
            .iter()
            .filter_map(|name| proposal.get(*name).map(|value| format!(
                "{}:{}",
                serde_json::to_string(name).unwrap(),
                if *name == "bound" {
                    serde_json::to_string(
                        &serde_json::from_value::<previous::Bound>(value.clone()).unwrap(),
                    )
                    .unwrap()
                } else {
                    value.to_string()
                }
            )))
            .collect::<Vec<_>>()
            .join(",")
    );
    proposal["digest"] = libzond::config::revision(&unsigned).into();
    state.to_string()
}

fn previous_fixture(seed: &Value, fixture: &str) -> Value {
    let mut state: Value = serde_json::from_str(fixture).unwrap();
    for key in [
        "id",
        "principal",
        "revision",
        "principal_revision",
        "created_unix_ms",
        "expires_unix_ms",
    ] {
        state["proposal"][key] = seed[key].clone();
    }
    state["proposal"]["expires_unix_ms"] = (libzond::history::now() + 60000).into();
    state["proposal"]["bound"]["home"] = seed["bound"]["home"].clone();
    state["proposal"]["bound"]["cwd"] = seed["bound"]["cwd"].clone();
    for section in state["proposal"]["review"]["sections"]
        .as_array_mut()
        .unwrap()
    {
        if section["title"] == "Execution" {
            for field in section["fields"].as_array_mut().unwrap() {
                if field["label"] == "Server HOME" {
                    field["value"] = seed["bound"]["home"].to_string().into();
                }
                if field["label"] == "Working directory" {
                    field["value"] = seed["bound"]["cwd"].to_string().into();
                }
            }
        }
    }
    state
}

fn store_previous(env: &TestEnv, state: &mut Value) {
    let record = sign_previous(state);
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    db.execute("INSERT OR REPLACE INTO rule_states(id,principal,status,updated,record) VALUES (?1,'exec',?2,?3,?4)", rusqlite::params![state["proposal"]["id"].as_str().unwrap(), state["status"].as_str().unwrap(), libzond::history::now() as i64, record]).unwrap();
}

#[test]
fn upgrading_migrates_home_syntax_and_preserves_literal_tildes() {
    let env = TestEnv::new();
    let proposal = approve(&env, "rule seed() { run true }");
    let mut state = previous_fixture(&proposal, include_str!("fixtures/home-v2.json"));
    state["status"] = "active".into();
    state["proposal"]["bound"]["rule"]
        .as_object_mut()
        .unwrap()
        .remove("language_version");
    state["proposal"]["source"] =
        "rule legacy() { run printf '%s:%s' \"$HOME/code\" \"~\" }".into();
    let normalized = state["proposal"]["review"]["sections"][0]["fields"][0]["value"]
        .as_str()
        .unwrap()
        .replace("\"~/code\"", "\"${HOME}/code\"")
        .replace("\"\\~\"", "\"~\"");
    state["proposal"]["review"]["sections"][0]["fields"][0]["value"] = normalized.into();
    env.stop_daemon();
    store_previous(&env, &mut state);
    env.start_daemon();
    let restored = &states(&env, "exec")[0];
    assert_eq!(restored["status"], "active", "{restored}");
    assert_eq!(
        restored["proposal"]["bound"]["rule"]["language_version"],
        libzond::rules::LANGUAGE_VERSION
    );
    assert_ne!(restored["proposal"]["digest"], state["proposal"]["digest"]);
    let output = format!("{}:~", libzond::paths::home_dir().join("code").display());
    assert_eq!(
        decoded(&invoke(&env, "legacy", &[]), "stdout"),
        output.as_bytes()
    );
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(&states(&env, "exec")[0], restored);
}

#[test]
fn upgrading_migrates_inclusive_bounds_and_all_statuses_once() {
    let env = TestEnv::new();
    let seed = approve(&env, "rule seed() { run true }");
    env.stop_daemon();
    let mut old = Vec::new();
    for status in [
        "active",
        "pending",
        "denied",
        "revoked",
        "expired",
        "withdrawn",
    ] {
        let mut state = previous_fixture(&seed, include_str!("fixtures/integer-v2.json"));
        state["status"] = status.into();
        state["proposal"]["id"] = format!("{}-{status}", seed["id"].as_str().unwrap()).into();
        if status == "active" {
            state["proposal"]["id"] = seed["id"].clone();
        }
        let name = format!("migrated-{status}");
        state["proposal"]["bound"]["rule"]["name"] = name.clone().into();
        state["proposal"]["review"]["title"] = name.clone().into();
        for location in ["source", "normalized"] {
            let text = if location == "source" {
                &mut state["proposal"]["source"]
            } else {
                &mut state["proposal"]["review"]["sections"][0]["fields"][0]["value"]
            };
            *text = text
                .as_str()
                .unwrap()
                .replace("migrated(", &format!("{name}("))
                .into();
        }
        state["grant_expires_unix_ms"] = (libzond::history::now() + 60000).into();
        store_previous(&env, &mut state);
        old.push(state);
    }
    env.start_daemon();
    let migrated = states(&env, "exec");
    for previous in &old {
        let current = migrated
            .iter()
            .find(|s| s["proposal"]["id"] == previous["proposal"]["id"])
            .unwrap();
        assert_eq!(current["status"], previous["status"], "{current}");
        assert_eq!(
            current["grant_expires_unix_ms"],
            previous["grant_expires_unix_ms"]
        );
        assert_eq!(
            current["proposal"]["bound"]["rule"]["types"][0]["definition"]["maximum_exclusive"],
            "18446744073709551616"
        );
        assert_eq!(
            current["proposal"]["bound"]["rule"]["types"][1]["definition"]["maximum_exclusive"],
            "9223372036854775808"
        );
        assert_ne!(
            current["proposal"]["digest"],
            previous["proposal"]["digest"]
        );
        assert!(
            !current["proposal"]["source"]
                .as_str()
                .unwrap()
                .contains("uint(")
        );
    }
    for args in [
        ["0", "-9223372036854775808"],
        ["18446744073709551615", "9223372036854775807"],
    ] {
        let result = invoke(&env, "migrated-active", &args);
        assert_eq!(result["type"], "completed", "{result}");
        assert_eq!(decoded(&result, "stdout"), args.join(":").as_bytes());
    }
    for args in [
        ["18446744073709551616", "0"],
        ["0", "9223372036854775808"],
        ["0", "-9223372036854775809"],
        ["-1", "0"],
    ] {
        assert_eq!(invoke(&env, "migrated-active", &args)["type"], "error");
    }
    let pending = old.iter().find(|s| s["status"] == "pending").unwrap();
    assert_eq!(
        resolve(&env, &pending["proposal"], true, None)["type"],
        "error"
    );
    let actions = env.request("admin", json!({"method":"actions","limit":100}));
    let migrations: Vec<_> = actions["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["action"] == "rule_migrated")
        .collect();
    assert_eq!(migrations.len(), old.len());
    for action in migrations {
        assert!(old.contains(&action["detail"]["previous"]));
    }
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(states(&env, "exec"), migrated);
    let actions = env.request("admin", json!({"method":"actions","limit":100}));
    assert_eq!(
        actions["actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["action"] == "rule_migrated")
            .count(),
        old.len()
    );
}

#[test]
fn home_relative_executables_resolve_once_and_remain_bound_after_restart() {
    let env = TestEnv::new();
    let executable = env.dir.path().join("home-printf");
    fs::copy("/usr/bin/printf", &executable).unwrap();
    let relative = executable
        .strip_prefix(libzond::paths::home_dir())
        .unwrap()
        .to_str()
        .unwrap();
    let source =
        format!("rule home-program() {{ run \"~/{relative}\" '%s' 'home-program-output' }}");
    let proposal = approve(&env, &source);
    assert_eq!(
        proposal["bound"]["rule"]["program"],
        executable.to_str().unwrap()
    );
    assert_eq!(
        decoded(&invoke(&env, "home-program", &[]), "stdout"),
        b"home-program-output"
    );
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(states(&env, "exec")[0]["proposal"], proposal);
    assert_eq!(
        decoded(&invoke(&env, "home-program", &[]), "stdout"),
        b"home-program-output"
    );
}

#[test]
fn rule_wait_is_scoped_and_observes_approval_before_or_after_attachment() {
    let env = TestEnv::new();
    let proposal = propose(&env, "rule waited() { run true }");
    let request = json!({"method":"wait_rule","proposal_id":proposal["id"]});
    let hidden = env.request("ops", request.clone());
    let missing = env.request("ops", json!({"method":"wait_rule","proposal_id":"unknown"}));
    assert_eq!(hidden, missing);
    assert_eq!(hidden["type"], "error");
    let mut waiter = env.session("exec", request.clone());
    let pending = waiter.event();
    assert_eq!(pending["type"], "rule_pending");
    assert_eq!(pending["proposal"], proposal);
    let approved = resolve(&env, &proposal, true, Some(3600));
    assert_eq!(approved["rule"]["status"], "active");
    assert_eq!(waiter.event(), approved);
    assert_eq!(env.request("exec", request.clone()), approved);
    assert_eq!(env.request("admin", request), approved);
}

#[test]
fn disconnecting_a_rule_wait_preserves_the_proposal_and_audit() {
    let env = TestEnv::new();
    let proposal = propose(&env, "rule disconnected() { run true }");
    let mut waiter = env.session(
        "exec",
        json!({"method":"wait_rule","proposal_id":proposal["id"]}),
    );
    assert_eq!(waiter.event()["type"], "rule_pending");
    drop(waiter);
    let state = &states(&env, "exec")[0];
    assert_eq!(state["status"], "pending");
    assert_eq!(state["proposal"], proposal);
    assert_eq!(
        resolve(&env, &proposal, true, None)["rule"]["status"],
        "active"
    );
    let actions = env.request("admin", json!({"method":"actions","limit":100}));
    assert!(
        actions["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "caller_request"
                && a["category"] == "read"
                && a["detail"]["request"]["method"] == "wait_rule"
                && a["detail"]["request"]["proposal_id"] == proposal["id"])
    );
}

#[test]
fn rule_wait_can_retrieve_an_outcome_outside_the_recent_rules_page() {
    let env = TestEnv::new();
    let first = propose(&env, "rule old() { run true }");
    let denied = resolve(&env, &first, false, None);
    for i in 0..256 {
        let proposal = propose(&env, &format!("rule recent{i}() {{ run true }}"));
        assert_eq!(
            resolve(&env, &proposal, false, None)["rule"]["status"],
            "denied"
        );
    }
    assert!(
        !states(&env, "exec")
            .iter()
            .any(|s| s["proposal"]["id"] == first["id"])
    );
    assert_eq!(
        env.request(
            "exec",
            json!({"method":"wait_rule","proposal_id":first["id"]})
        ),
        denied
    );
}

#[test]
fn review_is_generated_by_the_receiver_and_included_in_the_approval_digest() {
    let env = TestEnv::new();
    let source = r#"rule reviewed(x: repository-name) {
  require is-directory "~/code"
  require absent "~/code/$x"
  create-new-directory "~/code/$x" as dest {
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
    assert!(
        serde_json::from_value::<libzond::Request>(json!({
            "method": "propose_rule", "source": "rule benign() { run true }",
            "bound": {"rule": {"program":"/usr/bin/sh", "args":["-c", "unexpected command"]}}
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
        field("Parameters (positional order)", "x: repository-name")
            .contains("[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
    );
    assert!(field("Checks", "is-directory").contains("without following symlinks"));
    assert!(field("Checks", "absent").contains("no dangling symlink"));
    assert!(field("Effects", "create-new-directory").contains("atomically"));
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
        r#"rule clone-local(x: repository-name) {{
  require is-directory "{root}"
  create-new-directory "{root}/$x" as dest {{
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
        "repository-name"
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
fn stored_source_ast_and_digest_must_agree_before_restoring_authority() {
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
    let approved = approve(&env, "rule approved() { run true }");
    let pending = propose(&env, "rule pending() { run true }");
    let corrupt_digest = approve(&env, "rule digest() { run true }");
    let legacy = approve(&env, "rule legacy() { run true }");
    env.stop_daemon();
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    for proposal in [&approved, &pending, &corrupt_digest, &legacy] {
        let id = proposal["id"].as_str().unwrap();
        let text: String = db
            .query_row("SELECT record FROM rule_states WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        let mut state: Value = serde_json::from_str(&text).unwrap();
        if *proposal == legacy {
            state["proposal"]["review"]["sections"]
                .as_array_mut()
                .unwrap()
                .remove(0);
        } else if *proposal == corrupt_digest {
            state["proposal"]["source"] =
                "# changed original text\nrule digest() { run true }".into();
        } else {
            let name = proposal["bound"]["rule"]["name"].as_str().unwrap();
            state["proposal"]["source"] = format!("rule {name}() {{ run false }}").into();
        }
        if *proposal != corrupt_digest {
            let mut unsigned: libzond::rules::Proposal =
                serde_json::from_value(state["proposal"].clone()).unwrap();
            unsigned.digest.clear();
            state["proposal"]["digest"] =
                libzond::config::revision(&serde_json::to_string(&unsigned).unwrap()).into();
        }
        db.execute(
            "UPDATE rule_states SET record=?1 WHERE id=?2",
            [state.to_string().as_str(), id],
        )
        .unwrap();
    }
    drop(db);
    env.start_daemon();
    let records = states(&env, "exec");
    for proposal in [&approved, &pending, &corrupt_digest] {
        let record = records
            .iter()
            .find(|s| s["proposal"]["id"] == proposal["id"])
            .unwrap();
        assert_eq!(record["status"], "invalidated");
        let reason = record["reason"].as_str().unwrap();
        assert!(
            reason.contains(if *proposal == corrupt_digest {
                "digest does not match"
            } else {
                "source and compiled definition disagree"
            }),
            "{reason}"
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
    let legacy_record = records
        .iter()
        .find(|s| s["proposal"]["id"] == legacy["id"])
        .unwrap();
    assert_eq!(legacy_record["status"], "invalidated");
    assert!(
        legacy_record["reason"]
            .as_str()
            .unwrap()
            .contains("review changed or is missing")
    );
    assert_eq!(invoke(&env, "legacy", &[])["type"], "error");
    let audit = env.request("admin", json!({"method":"actions","limit":100}));
    assert_eq!(
        audit["actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["action"] == "rule_invalidated")
            .count(),
        3
    );
}

#[test]
fn raw_protocol_cannot_bypass_types_approval_digest_or_principal_scope() {
    let env = TestEnv::new();
    let source = r#"rule echo-name(x: repository-name) { run printf "%s" "$x" }"#;
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
            event["message"]
                .as_str()
                .unwrap()
                .contains("repository-name"),
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
        r#"rule guarded(x: repository-name) {{
  require absent "{root}/blocked"
  create-new-directory "{root}/$x" as dest {{ run mkdir "$dest" }}
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
        r#"rule gated() {{ create-new-directory "{root}/target" as dest {{
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

#[test]
fn migration_rolls_back_the_batch_if_a_record_cannot_be_converted() {
    let env = TestEnv::new();
    let seed = approve(&env, "rule seed() { run true }");
    env.stop_daemon();
    let mut old = previous_fixture(&seed, include_str!("fixtures/integer-v2.json"));
    old["proposal"]["id"] = "a-old".into();
    store_previous(&env, &mut old);
    let mut future = old.clone();
    future["proposal"]["id"] = "z-future".into();
    future["proposal"]["bound"]["rule"]["language_version"] = 999.into();
    store_previous(&env, &mut future);
    let failure = checked(env.daemon_command().arg("serve"), 1);
    assert!(
        String::from_utf8_lossy(&failure.stderr).contains("unsupported stored rule language 999")
    );
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    let saved: String = db
        .query_row("SELECT record FROM rule_states WHERE id='a-old'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&saved).unwrap(), old);
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM actions WHERE action='rule_migrated'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    db.execute("DELETE FROM rule_states WHERE id='z-future'", [])
        .unwrap();
    drop(db);
    env.start_daemon();
    let migrated = states(&env, "exec");
    assert!(
        migrated
            .iter()
            .any(|s| s["proposal"]["id"] == "a-old" && s["status"] == "pending")
    );
}

#[test]
fn migration_includes_records_outside_the_recent_history_page() {
    let env = TestEnv::new();
    let seed = approve(&env, "rule seed() { run true }");
    env.stop_daemon();
    for index in 0..260 {
        let mut old = previous_fixture(&seed, include_str!("fixtures/integer-v2.json"));
        old["proposal"]["id"] = format!("historical-{index}").into();
        old["status"] = "revoked".into();
        store_previous(&env, &mut old);
    }
    env.start_daemon_with_timeout(std::time::Duration::from_secs(30));
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    let migrated: i64 = db.query_row("SELECT count(*) FROM rule_states WHERE status='revoked' AND json_extract(record,'$.proposal.bound.rule.language_version')=?1", [libzond::rules::LANGUAGE_VERSION], |r| r.get(0)).unwrap();
    assert_eq!(migrated, 260);
}

#[test]
fn version_two_constructor_migration_preserves_grants_and_exact_arguments() {
    for status in ["active", "pending"] {
        let env = TestEnv::new();
        let seed = approve(&env, "rule seed() { run true }");
        let mut previous = previous_fixture(&seed, include_str!("fixtures/types-v2.json"));
        previous["status"] = status.into();
        previous["grant_expires_unix_ms"] = (libzond::history::now() + 60000).into();
        env.stop_daemon();
        store_previous(&env, &mut previous);
        env.start_daemon();
        let migrated = states(&env, "exec")[0].clone();
        assert_eq!(migrated["status"], status, "{migrated}");
        assert_eq!(
            migrated["grant_expires_unix_ms"],
            previous["grant_expires_unix_ms"]
        );
        let proposal = &migrated["proposal"];
        assert_eq!(
            proposal["bound"]["rule"]["language_version"],
            libzond::rules::LANGUAGE_VERSION
        );
        assert!(
            proposal["source"]
                .as_str()
                .unwrap()
                .contains("type enumeration-local-1 = enumeration(values=")
        );
        assert!(
            proposal["source"]
                .as_str()
                .unwrap()
                .contains("type repository-name-local-1 = repository-name")
        );
        assert_eq!(
            proposal["bound"]["rule"]["types"][3]["definition"]["maximum_bytes_exclusive"],
            21
        );
        assert_eq!(proposal["bound"]["rule"]["sudo_password"], true);
        assert!(
            proposal["source"]
                .as_str()
                .unwrap()
                .contains("run --sudo /usr/bin/printf")
        );
        assert_ne!(proposal["digest"], previous["proposal"]["digest"]);
        if status == "pending" {
            assert_eq!(
                resolve(&env, &previous["proposal"], true, None)["type"],
                "error"
            );
            assert_eq!(
                resolve(&env, proposal, true, None)["rule"]["status"],
                "active"
            );
        }
        for symbol in ["AB".to_owned(), "A".repeat(20)] {
            let result = invoke(
                &env,
                "previous-types",
                &[
                    "daily",
                    "kmux",
                    "positions",
                    &symbol,
                    "18446744073709551615",
                ],
            );
            assert_eq!(result["type"], "completed", "{result}");
            assert_eq!(
                decoded(&result, "stdout"),
                format!("daily:kmux:positions:usdm:{symbol}:18446744073709551615").as_bytes()
            );
        }
        for arguments in [
            vec!["daily", "kmux", "positions", "A", "1"],
            vec!["daily", "kmux", "positions", "ABCDEFGHIJKLMNOPQRSTU", "1"],
            vec!["daily", "kmux", "unknown", "AB", "1"],
            vec!["monthly", "kmux", "positions", "AB", "1"],
            vec!["daily", "../kmux", "positions", "AB", "1"],
            vec!["daily", "kmux", "positions", "AB", "18446744073709551616"],
        ] {
            assert_eq!(invoke(&env, "previous-types", &arguments)["type"], "error");
        }
        let before = states(&env, "exec");
        env.stop_daemon();
        env.start_daemon();
        assert_eq!(states(&env, "exec"), before);
        let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
        let migrations: i64 = db
            .query_row(
                "SELECT count(*) FROM actions WHERE action='rule_migrated'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migrations, 1);
    }
}
