use libzond::rules::{BoundRule, parse, valid_repo_name};

const SOURCE: &str = r#"rule clone-futpib(x: repo-name) {
  require is-dir "$HOME/code"
  create-new-dir "$HOME/code/$x" as dest {
    run git clone -- "https://github.com/futpib/${x}.git" "$dest"
  }
}"#;

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
        SOURCE.replace("$HOME/code", "$dest/code"),
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
