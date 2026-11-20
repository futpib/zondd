use libzondtest::{
    TestEnv, decoded,
    serde_json::{Value, json},
};

fn source(rows: &[(&str, &str, &str)]) -> String {
    let rows = rows.iter().map(|(name, repo, branch)| format!(
        "  {name} = (repo=\"futpib/{repo}\", path=\"/home/publisher/code/{repo}\", src=\"refs/heads/{branch}\", dst=\"refs/heads/{branch}\")"
    )).collect::<Vec<_>>().join("\n");
    format!(
        r#"type target = choice(fields=(repo, path, src, dst)) {{
{rows}
}}
rule publish(t: target) {{
  run printf "%s|%s|%s|%s" "${{t.repo}}" "${{t.path}}" "${{t.src}}" "${{t.dst}}"
}}"#
    )
}

const SNAKES: (&str, &str, &str) = ("snakes", "snakes-telegram", "master");
const ZOND: (&str, &str, &str) = ("zond", "zondd", "master");
const EKA: (&str, &str, &str) = ("eka", "EKA2L1", "wasm-port");

fn propose(env: &TestEnv, source: &str) -> Value {
    let event = env.request("exec", json!({"method":"propose_rule", "source":source}));
    assert_eq!(event["type"], "rule_proposed", "{event}");
    event["proposal"].clone()
}

fn resolve(env: &TestEnv, p: &Value, approve: bool) -> Value {
    env.request("admin", json!({"method":"resolve_rule", "proposal_id":p["id"], "digest":p["digest"], "approve":approve}))
}

fn approve(env: &TestEnv, source: &str) -> Value {
    let p = propose(env, source);
    assert_eq!(resolve(env, &p, true)["rule"]["status"], "active");
    p
}

fn invoke(env: &TestEnv, choice: &str) -> Value {
    env.request(
        "exec",
        json!({"method":"invoke", "operation":"publish", "args":[choice]}),
    )
}

fn state(env: &TestEnv, p: &Value) -> Value {
    env.request("exec", json!({"method":"rules"}))["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["proposal"]["id"] == p["id"])
        .unwrap()
        .clone()
}

fn diff(p: &Value) -> &Value {
    let section = &p["review"]["sections"][0];
    assert_eq!(section["title"], "Changes from approved rule");
    section
}

#[test]
fn one_added_repo_branch_is_the_entire_choice_diff_and_replaces_atomically() {
    let env = TestEnv::new();
    let original = approve(&env, &source(&[SNAKES, ZOND]));
    assert!(original.get("replaces").is_none());
    assert_eq!(
        original["review"]["sections"][0]["title"],
        "Normalized rule"
    );
    let proposed_source = source(&[SNAKES, ZOND, EKA]);
    let replacement = propose(&env, &proposed_source);
    assert_eq!(replacement["replaces"]["id"], original["id"]);
    assert_eq!(replacement["replaces"]["digest"], original["digest"]);
    assert_eq!(replacement["source"], proposed_source);
    let changes = diff(&replacement).to_string();
    assert!(
        changes.contains("1 added, 0 removed, 0 changed."),
        "{changes}"
    );
    assert!(
        changes.contains("Added Choice target.eka")
            && changes.contains("futpib/EKA2L1")
            && changes.contains("refs/heads/wasm-port"),
        "{changes}"
    );
    assert!(
        !changes.contains("snakes-telegram") && !changes.contains("futpib/zondd"),
        "{changes}"
    );
    assert!(
        replacement["review"]["sections"][1]
            .to_string()
            .contains("snakes-telegram")
    );
    assert_eq!(invoke(&env, "snakes")["code"], 0);
    assert_eq!(invoke(&env, "eka")["type"], "error");
    assert_eq!(state(&env, &original)["status"], "active");
    let duplicate = env.request(
        "exec",
        json!({"method":"propose_rule", "source":proposed_source}),
    );
    assert_eq!(duplicate["type"], "error");
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(state(&env, &replacement)["proposal"], replacement);
    assert_eq!(
        resolve(&env, &replacement, true)["rule"]["status"],
        "active"
    );
    assert_eq!(state(&env, &original)["status"], "revoked");
    assert!(
        state(&env, &original)["reason"]
            .as_str()
            .unwrap()
            .contains(replacement["id"].as_str().unwrap())
    );
    assert_eq!(
        decoded(&invoke(&env, "eka"), "stdout"),
        b"futpib/EKA2L1|/home/publisher/code/EKA2L1|refs/heads/wasm-port|refs/heads/wasm-port"
    );
    env.stop_daemon();
    env.start_daemon();
    assert_eq!(invoke(&env, "snakes")["code"], 0);
    assert_eq!(state(&env, &replacement)["proposal"], replacement);
    let rules = env.request("exec", json!({"method":"rules"}));
    assert_eq!(
        rules["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["status"] == "active")
            .count(),
        1
    );
}

#[test]
fn removal_and_branch_change_show_only_the_changed_rows_and_enforce_new_scope() {
    let env = TestEnv::new();
    approve(&env, &source(&[SNAKES, ZOND, EKA]));
    let removal = propose(&env, &source(&[SNAKES, EKA]));
    let changes = diff(&removal).to_string();
    assert!(changes.contains("0 added, 1 removed, 0 changed."));
    assert!(changes.contains("Removed Choice target.zond") && changes.contains("futpib/zondd"));
    assert!(!changes.contains("EKA2L1") && !changes.contains("snakes-telegram"));
    assert_eq!(resolve(&env, &removal, true)["rule"]["status"], "active");
    assert_eq!(invoke(&env, "zond")["type"], "error");
    let branch = propose(&env, &source(&[SNAKES, ("eka", "EKA2L1", "release")]));
    let changes = diff(&branch).to_string();
    assert!(changes.contains("0 added, 0 removed, 1 changed."));
    assert!(
        changes.contains("Changed Choice target.eka")
            && changes.contains("Before:")
            && changes.contains("After:")
            && changes.contains("refs/heads/wasm-port")
            && changes.contains("refs/heads/release")
    );
    assert!(!changes.contains("snakes-telegram"));
    assert_eq!(resolve(&env, &branch, true)["rule"]["status"], "active");
    assert!(
        String::from_utf8(decoded(&invoke(&env, "eka"), "stdout"))
            .unwrap()
            .ends_with("refs/heads/release|refs/heads/release")
    );
}

#[test]
fn rejecting_or_withdrawing_replacement_preserves_the_existing_grant() {
    let env = TestEnv::new();
    let original = approve(&env, &source(&[SNAKES, ZOND]));
    let denied = propose(&env, &source(&[SNAKES, ZOND, EKA]));
    assert_eq!(resolve(&env, &denied, false)["rule"]["status"], "denied");
    let withdrawn = propose(&env, &source(&[SNAKES, ZOND, EKA]));
    assert_eq!(
        env.request("exec", json!({"method":"withdraw","id":withdrawn["id"]}))["rule"]["status"],
        "withdrawn"
    );
    assert_eq!(state(&env, &original)["status"], "active");
    assert_eq!(invoke(&env, "snakes")["code"], 0);
    assert_eq!(invoke(&env, "eka")["type"], "error");
}

#[test]
fn revoked_or_withdrawn_baseline_cannot_be_reapproved_through_a_stale_replacement() {
    for withdraw in [false, true] {
        let env = TestEnv::new();
        let original = approve(&env, &source(&[SNAKES, ZOND]));
        let stale = propose(&env, &source(&[SNAKES, ZOND, EKA]));
        if withdraw {
            env.request("exec", json!({"method":"withdraw", "id":original["id"]}));
        } else {
            env.request(
                "admin",
                json!({"method":"revoke_rule", "grant_id":original["id"]}),
            );
        }
        let result = resolve(&env, &stale, true);
        assert_eq!(result["type"], "error");
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("baseline changed"),
            "{result}"
        );
        assert_eq!(state(&env, &stale)["status"], "invalidated");
        let fresh = approve(&env, &source(&[SNAKES]));
        assert!(fresh.get("replaces").is_none());
        assert_eq!(resolve(&env, &stale, true)["type"], "error");
        assert_eq!(state(&env, &fresh)["status"], "active");
        assert_eq!(invoke(&env, "eka")["type"], "error");
    }
}

#[test]
fn diff_and_baseline_are_digest_bound_and_cannot_be_supplied_by_callers() {
    let env = TestEnv::new();
    let original = approve(&env, &source(&[SNAKES]));
    let replacement = propose(&env, &source(&[SNAKES, EKA]));
    for key in ["replaces", "review"] {
        assert!(serde_json::from_value::<libzond::Request>(json!({"method":"propose_rule", "source":source(&[SNAKES, EKA]), key:replacement[key]})).is_err());
    }
    let mut p: libzond::rules::Proposal = serde_json::from_value(replacement.clone()).unwrap();
    let digest = std::mem::take(&mut p.digest);
    assert_eq!(
        libzond::config::revision(&serde_json::to_string(&p).unwrap()),
        digest
    );
    p.replaces.as_mut().unwrap().digest = "different-baseline".into();
    assert_ne!(
        libzond::config::revision(&serde_json::to_string(&p).unwrap()),
        digest
    );
    p.replaces.as_mut().unwrap().digest = original["digest"].as_str().unwrap().into();
    p.review.as_mut().unwrap()["sections"][0]["fields"][0]["value"] = "Nothing changed".into();
    let altered = libzond::config::revision(&serde_json::to_string(&p).unwrap());
    assert_ne!(altered, digest);
    let result = env.request("admin", json!({"method":"resolve_rule", "proposal_id":replacement["id"], "digest":altered, "approve":true}));
    assert_eq!(result["type"], "error");
    assert_eq!(state(&env, &original)["status"], "active");
}

#[test]
fn expiring_baseline_invalidates_the_review_and_other_principals_cannot_replace_it() {
    let env = TestEnv::new();
    let original = propose(&env, &source(&[SNAKES]));
    assert_eq!(env.request("admin", json!({"method":"resolve_rule", "proposal_id":original["id"], "digest":original["digest"], "approve":true, "expires_in_secs":1}))["rule"]["status"], "active");
    let replacement = propose(&env, &source(&[SNAKES, EKA]));
    let other = env.request(
        "ops",
        json!({"method":"propose_rule", "source":source(&[SNAKES, EKA])}),
    );
    assert_eq!(other["type"], "rule_proposed");
    assert!(other["proposal"].get("replaces").is_none());
    let mut waiting = libzondtest::Session::new(
        &env.runtime.join("exec.sock"),
        json!({"method":"wait_rule", "proposal_id":replacement["id"]}),
    );
    assert_eq!(waiting.event()["type"], "rule_pending");
    let outcome = waiting.event();
    assert_eq!(outcome["rule"]["status"], "invalidated", "{outcome}");
    assert_eq!(state(&env, &original)["status"], "expired");
    assert_eq!(resolve(&env, &replacement, true)["type"], "error");
    assert_eq!(state(&env, &replacement)["status"], "invalidated");
}

#[test]
fn failed_replacement_transaction_preserves_both_states_and_audit() {
    let env = TestEnv::new();
    let original = approve(&env, &source(&[SNAKES]));
    let replacement = propose(&env, &source(&[SNAKES, EKA]));
    let db = rusqlite::Connection::open(env.config.with_extension("history.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_replacement BEFORE UPDATE ON rule_states WHEN NEW.status = 'active' BEGIN SELECT RAISE(ABORT, 'test replacement failure'); END;").unwrap();
    let failure = resolve(&env, &replacement, true);
    assert_eq!(failure["type"], "error");
    assert_eq!(state(&env, &original)["status"], "active");
    assert_eq!(state(&env, &replacement)["status"], "pending");
    let audit = env.request("admin", json!({"method":"actions", "limit":100}));
    assert!(
        !audit["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "rule_revoked")
    );
    db.execute_batch("DROP TRIGGER fail_replacement;").unwrap();
    assert_eq!(
        resolve(&env, &replacement, true)["rule"]["status"],
        "active"
    );
    let audit = env.request("admin", json!({"method":"actions", "limit":100}));
    let transitions = audit["actions"].as_array().unwrap();
    assert!(
        transitions
            .iter()
            .any(|a| a["action"] == "rule_revoked"
                && a["detail"]["proposal"]["id"] == original["id"])
    );
    assert!(
        transitions.iter().any(|a| a["action"] == "rule_approved"
            && a["detail"]["proposal"]["id"] == replacement["id"])
    );
}
