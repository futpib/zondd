use libzond::rules::{BoundRule, parse, valid_repo_name, valid_service_unit};

const SOURCE: &str = r#"rule clone-futpib(x: repo-name) {
  require is-dir "~/code"
  create-new-dir "~/code/$x" as dest {
    run git clone -- "https://github.com/futpib/${x}.git" "$dest"
  }
}"#;

#[test]
fn sudo_is_an_explicit_run_capability_and_preserves_ordinary_rule_digests() {
    let ordinary = parse("rule test() { run paru --sudo }").unwrap();
    assert!(!ordinary.sudo_password);
    let serialized = serde_json::to_value(&ordinary).unwrap();
    assert!(serialized.get("sudo_password").is_none());
    assert_eq!(
        serde_json::from_value::<libzond::rules::Rule>(serialized).unwrap(),
        ordinary
    );
    let privileged = parse("rule test() { run --sudo paru -Syu }").unwrap();
    assert!(privileged.sudo_password);
    assert_eq!(privileged.program, "paru");
    assert_eq!(
        serde_json::to_value(&privileged).unwrap()["sudo_password"],
        true
    );
    for source in [
        "rule test() { run --sudo }",
        "rule test() { run --sudo --sudo paru }",
        "rule test(x: repo-name) { run $x paru }",
        "rule test(x: repo-name) { run --sudo $x }",
    ] {
        assert!(parse(source).is_err(), "{source}");
    }
}

#[test]
fn directory_effect_keeps_the_old_spelling_as_an_alias() {
    assert_eq!(
        parse(SOURCE).unwrap(),
        parse(&SOURCE.replace("create-new-dir", "create-new")).unwrap()
    );
}

#[test]
fn names_are_full_ascii_components_with_no_normalization() {
    for valid in ["zondd", "ibkr-tws-http", "my.repo", "X_1", &"a".repeat(100)] {
        assert!(valid_repo_name(valid), "{valid:?}");
    }
    for invalid in [
        "",
        ".",
        "..",
        "../foo",
        "foo/bar",
        "--config",
        "$(whoami)",
        "a b",
        "a\nb",
        "a\r",
        "a\0",
        "a\u{200b}",
        "λ",
        "é",
        "a;id",
        "a\\b",
        &"a".repeat(101),
    ] {
        assert!(!valid_repo_name(invalid), "{invalid:?}");
    }
    for byte in 0..=127u8 {
        let name = format!("a{}z", byte as char);
        assert_eq!(
            valid_repo_name(&name),
            byte.is_ascii_alphanumeric() || b"._-".contains(&byte)
        );
    }
}

#[test]
fn one_binding_builds_the_url_and_destination_without_shell_expansion() {
    let mut rule = parse(SOURCE).unwrap();
    rule.program = "/usr/bin/git".into();
    let bound = BoundRule {
        rule,
        home: "/home/test user".into(),
        cwd: "/tmp".into(),
    };
    let call = bound
        .instantiate("grant", &["my.repo".into()], None)
        .unwrap();
    assert_eq!(
        call.command.args,
        [
            "clone",
            "--",
            "https://github.com/futpib/my.repo.git",
            "/home/test user/code/my.repo"
        ]
    );
    assert_eq!(
        call.requirements[0].path.to_str().unwrap(),
        "/home/test user/code"
    );
    assert_eq!(
        call.destination.unwrap().to_str().unwrap(),
        "/home/test user/code/my.repo"
    );
    let staged = bound
        .instantiate("grant", &["my.repo".into()], Some("/private/output"))
        .unwrap();
    assert_eq!(staged.command.args.last().unwrap(), "/private/output");
    assert!(
        bound
            .instantiate("grant", &["../escape".into()], None)
            .is_err()
    );
    assert!(bound.instantiate("grant", &[], None).is_err());
    assert!(
        bound
            .instantiate("grant", &["x".into(), "y".into()], None)
            .is_err()
    );
}

#[test]
fn reject_shell_code_unknown_variables_types_and_ambiguous_bindings() {
    for source in [
        SOURCE.replace("repo-name", "string"),
        SOURCE.replace("x: repo-name", "HOME: repo-name"),
        SOURCE.replace("x: repo-name", "x: repo-name, x: repo-name"),
        SOURCE.replace("as dest", "as x"),
        SOURCE.replace("$dest", "$unknown"),
        SOURCE.replace("run git", "run $x"),
        SOURCE.replace("run git", "run $(id)"),
        SOURCE.replace("git clone", "git `id` clone"),
        SOURCE.replace("git clone", "git clone | sh"),
        SOURCE.replace("git clone", "git clone; id"),
        SOURCE.replace("git clone", "git clone *"),
        SOURCE.replace("${x}", "${x:-evil}"),
        SOURCE.replace("\"$dest\"", "\"${dest\""),
        SOURCE.replace("\"$dest\"", "\"unterminated"),
        SOURCE.replace("~/code", "$dest/code"),
        format!("{SOURCE}\nrun sh"),
        format!("{SOURCE}\0"),
        "#".repeat(16 * 1024 + 1),
    ] {
        assert!(parse(&source).is_err(), "accepted {source}");
    }
}

#[test]
fn quotes_and_escapes_preserve_literal_arguments() {
    let rule = parse(
        r#"rule literal(x: repo-name) {
  run /usr/bin/printf "%s" '$x $(id) ; | *' "\$x" "" "a b" "$x"
}"#,
    )
    .unwrap();
    let call = BoundRule {
        rule,
        home: "/home/test".into(),
        cwd: "/tmp".into(),
    }
    .instantiate("grant", &["repo".into()], None)
    .unwrap();
    assert_eq!(
        call.command.args,
        ["%s", "$x $(id) ; | *", "$x", "", "a b", "repo"]
    );
}

#[test]
fn service_checks_expand_one_explicit_unit_and_keep_the_wire_shape() {
    let bound = BoundRule {
        rule: parse(
            r#"rule restart-app(x: repo-name) {
  require user-service-active-or-enabled "app-$x.service"
  run /usr/bin/systemctl --user restart -- "app-$x.service"
}"#,
        )
        .unwrap(),
        home: "/home/test".into(),
        cwd: "/tmp".into(),
    };
    let call = bound
        .instantiate("grant", &["worker".into()], None)
        .unwrap();
    assert_eq!(
        call.requirements[0].path.to_str().unwrap(),
        "app-worker.service"
    );
    assert_eq!(
        call.command.args,
        ["--user", "restart", "--", "app-worker.service"]
    );
    let wire = serde_json::to_value(&call.requirements[0]).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"kind":"user-service-active-or-enabled", "path":"app-worker.service"})
    );
    for target in [
        "app",
        "/tmp/app.service",
        "app*.service",
        "--user.service",
        "app@.service",
    ] {
        let mut invalid = bound.clone();
        invalid.rule.requirements[0].path =
            libzond::rules::Word(vec![libzond::rules::Part::Literal(target.into())]);
        assert!(
            invalid
                .instantiate("grant", &["worker".into()], None)
                .is_err(),
            "{target}"
        );
    }
}

#[test]
fn service_names_cannot_select_patterns_paths_options_or_templates() {
    for valid in [
        "app.service",
        "app-1.2_worker.service",
        "app@one.service",
        &format!("{}.service", "a".repeat(247)),
    ] {
        assert!(valid_service_unit(valid), "{valid:?}");
    }
    for invalid in [
        "",
        ".service",
        "app",
        "app.timer",
        "../app.service",
        "app/foo.service",
        "*.service",
        "app?.service",
        "app[12].service",
        "app@.service",
        "app@one@two.service",
        "--all.service",
        "a b.service",
        "a\nb.service",
        "a\0.service",
        "λ.service",
        r"app\x2dworker.service",
        &format!("{}.service", "a".repeat(248)),
    ] {
        assert!(!valid_service_unit(invalid), "{invalid:?}");
    }
}
