use libzondtest::{TestEnv, command, serde_json::json};
use std::fs;

fn check(env: &TestEnv, principal: &str, input: serde_json::Value) -> serde_json::Value {
    let event = env.request(principal, json!({"method":"check","input":input}));
    assert_eq!(event["type"], "checked", "{event}");
    event["check"].clone()
}

#[test]
fn permissions_are_scoped_to_the_authenticated_principal() {
    let env = TestEnv::new();
    let exec = env.request("exec", json!({"method":"permissions"}));
    let p = &exec["permissions"];
    assert_eq!(p["principal"], "exec");
    assert_eq!(p["policy"]["allow_exec"], true);
    assert_eq!(p["policy"]["default"], "ask");
    assert_eq!(p["policy"]["rules"][0]["args"], json!(["%s", "hello"]));
    assert_eq!(p["policy"]["rules"][2]["args"], json!(null));
    assert_eq!(p["approvals"]["enabled"], true);
    assert_eq!(p["limits"]["command_timeout_secs"], 2);
    assert_eq!(p["operations"], json!({}));
    assert!(!exec.to_string().contains("greet"));
    let ops = env.request("ops", json!({"method":"permissions"}));
    let p = &ops["permissions"];
    assert_eq!(p["principal"], "ops");
    assert_eq!(p["policy"]["allow_exec"], false);
    assert_eq!(p["policy"]["rules"], json!([]));
    assert_eq!(p["operations"]["greet"]["decision"], "allow");
    assert_eq!(
        p["operations"]["greet"]["arguments"][0]["choices"],
        json!(["world", "λ"])
    );
    assert_eq!(p["revision"], exec["permissions"]["revision"]);
    assert_eq!(
        env.request("admin", json!({"method":"permissions"}))["type"],
        "rejected"
    );
    assert!(
        serde_json::from_value::<libzond::Request>(
            json!({"method":"permissions","principal":"ops"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<libzond::Request>(
            json!({"method":"check","input":{"method":"pending"}})
        )
        .is_err()
    );
    for method in ["pending", "history", "actions", "reload"] {
        assert_eq!(
            env.request("exec", json!({"method":method}))["type"],
            "rejected"
        );
    }
}

#[test]
fn checks_follow_execution_rules_without_execution_or_approval() {
    let env = TestEnv::new();
    for (input, expected) in [
        (command("/usr/bin/printf", &["%s", "hello"]), "allow"),
        (command("/usr/bin/printf", &["%s", "other"]), "ask"),
        (command("/usr/bin/false", &["any-args"]), "deny"),
        (command("/usr/bin/id", &["-u"]), "allow"),
        (command("/usr/bin/id", &[]), "ask"),
        (command("relative-path", &[]), "deny"),
        (command("/usr/bin/printf", &["\0"]), "deny"),
    ] {
        assert_eq!(check(&env, "exec", input)["decision"], expected);
    }
    assert_eq!(
        check(&env, "ops", command("/usr/bin/id", &["-u"]))["decision"],
        "deny"
    );
    let invoke = json!({"method":"invoke","operation":"greet","args":["λ"]});
    let result = check(&env, "ops", invoke.clone());
    assert_eq!(result["decision"], "allow");
    assert_eq!(result["command"]["args"], json!(["hello %s", "λ"]));
    assert_eq!(check(&env, "exec", invoke)["decision"], "deny");
    for args in [json!([]), json!(["--help"]), json!(["world", "extra"])] {
        assert_eq!(
            check(
                &env,
                "ops",
                json!({"method":"invoke","operation":"greet","args":args})
            )["decision"],
            "deny"
        );
    }
    let marker = env.dir.path().join("must-not-execute");
    let input = command("/usr/bin/touch", &[marker.to_str().unwrap()]);
    assert_eq!(check(&env, "exec", input.clone())["decision"], "ask");
    let policy = format!(
        "{}\n[[principals.exec.rules]]\nprogram = \"/usr/bin/touch\"\ndecision = \"allow\"\n",
        fs::read_to_string(&env.config).unwrap()
    );
    fs::write(&env.config, policy).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    assert_eq!(check(&env, "exec", input)["decision"], "allow");
    assert!(!marker.exists());
    assert!(env.queue().is_empty());
    assert_eq!(
        env.request("admin", json!({"method":"history"}))["requests"],
        json!([])
    );
}

#[test]
fn introspection_uses_live_policy_and_effective_approval_settings() {
    let env = TestEnv::new();
    let input = command("/usr/bin/printf", &["unmatched"]);
    let initial = check(&env, "exec", input.clone());
    assert_eq!(initial["decision"], "ask");
    let policy = fs::read_to_string(&env.config)
        .unwrap()
        .replace("enabled = true", "enabled = false");
    fs::write(&env.config, &policy).unwrap();
    let reload = env.request("admin", json!({"method":"reload"}));
    let disabled = check(&env, "exec", input.clone());
    assert_eq!(disabled["decision"], "deny");
    assert_eq!(disabled["policy_decision"], "ask");
    assert_ne!(disabled["revision"], initial["revision"]);
    assert_eq!(disabled["revision"], reload["revision"]);
    assert_eq!(env.request("exec", input)["type"], "rejected");
    assert_eq!(
        check(&env, "exec", command("/usr/bin/id", &["-u"]))["decision"],
        "allow"
    );
    let permissions = env.request("exec", json!({"method":"permissions"}));
    assert_eq!(permissions["permissions"]["approvals"]["enabled"], false);
    assert_eq!(permissions["permissions"]["revision"], reload["revision"]);

    // Exact rules precede later wildcard rules for the same executable.
    fs::write(
        &env.config,
        format!(
            "{policy}\n[[principals.exec.rules]]\nprogram = \"/usr/bin/id\"\ndecision = \"deny\"\n"
        ),
    )
    .unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    assert_eq!(
        check(&env, "exec", command("/usr/bin/id", &["-u"]))["decision"],
        "allow"
    );
    assert_eq!(
        check(&env, "exec", command("/usr/bin/id", &[]))["decision"],
        "deny"
    );

    fs::remove_file(&env.config).unwrap();
    assert_eq!(
        env.request("admin", json!({"method":"reload"}))["type"],
        "reloaded"
    );
    let defaults = env.request("default", json!({"method":"permissions"}));
    assert_eq!(defaults["permissions"]["policy"]["default"], "ask");
    assert_eq!(defaults["permissions"]["approvals"]["enabled"], true);
    assert_eq!(
        check(&env, "default", command("/usr/bin/id", &["-u"]))["decision"],
        "ask"
    );
}

#[test]
fn operation_checks_report_approval_and_denial_independently_of_exec_rules() {
    let env = TestEnv::new();
    let (principals, operation) = env.policy.split_once("[operations.greet]").unwrap();
    let input = json!({"method":"invoke","operation":"greet","args":["world"]});
    for (enabled, policy_decision, effective) in [
        (true, "ask", "ask"),
        (false, "ask", "deny"),
        (true, "deny", "deny"),
    ] {
        let policy = format!(
            "{}[operations.greet]{}",
            principals.replace("enabled = true", &format!("enabled = {enabled}")),
            operation.replace(
                "decision = \"allow\"",
                &format!("decision = \"{policy_decision}\"")
            )
        );
        fs::write(&env.config, policy).unwrap();
        assert_eq!(
            env.request("admin", json!({"method":"reload"}))["type"],
            "reloaded"
        );
        let result = check(&env, "ops", input.clone());
        assert_eq!(result["policy_decision"], policy_decision);
        assert_eq!(result["decision"], effective);
        assert!(env.queue().is_empty());
    }
    let actions = env.request("admin", json!({"method":"actions"}));
    assert!(actions["actions"].as_array().unwrap().iter().any(|action| {
        action["action"] == "caller_request"
            && action["detail"]["principal"] == "ops"
            && action["detail"]["request"]["method"] == "check"
    }));
}
