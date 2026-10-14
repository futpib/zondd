use libzond::rules::{BoundRule, TypeKind, parse, parse_stored};

const CHOICES: &str = r#"type view = choice(resource, market) {
  balances = ("balances", "portfolio")
  accounts = ("accounts", "portfolio")
  positions = ("positions", "usdm")
}
type selected = view
type count = uint(0, 1000)
rule query(v: selected, n: count) {
  run /usr/bin/printf "%s" "${v.resource}" "${v.market}" "$n"
}"#;

fn bound(source: &str) -> BoundRule {
    BoundRule {
        rule: parse(source).unwrap(),
        home: "/home/a b".into(),
        cwd: "/tmp".into(),
    }
}

fn expand(source: &str, args: &[&str]) -> anyhow::Result<Vec<String>> {
    Ok(bound(source)
        .instantiate(
            "grant",
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            None,
        )?
        .command
        .args)
}

#[test]
fn correlated_rows_supply_exact_pairs_and_aliases_keep_their_fields() {
    for (selector, resource, market) in [
        ("balances", "balances", "portfolio"),
        ("accounts", "accounts", "portfolio"),
        ("positions", "positions", "usdm"),
    ] {
        assert_eq!(
            expand(CHOICES, &[selector, "1000"]).unwrap(),
            ["%s", resource, market, "1000"]
        );
    }
    for args in [
        vec!["positions", "1001"],
        vec!["positions", "portfolio"],
        vec!["positions,portfolio", "1"],
        vec!["positions", "1", "portfolio"],
        vec!["balances"],
        vec!["unknown", "1"],
    ] {
        assert!(expand(CHOICES, &args).is_err(), "{args:?}");
    }
    let rule = parse(CHOICES).unwrap();
    assert!(matches!(
        rule.type_kind("selected").unwrap(),
        Some(TypeKind::Choice { .. })
    ));
    let text = rule.type_description("selected").unwrap();
    assert!(
        text.contains("positions")
            && text.contains("usdm")
            && text.contains("No other combinations")
    );
}

#[test]
fn integer_ranges_are_canonical_and_do_not_overflow() {
    let unsigned = "type n = uint(0, 18446744073709551615)\nrule integer(x: n) { run /usr/bin/printf '%s' \"$x\" }";
    let serialized = serde_json::to_value(parse(unsigned).unwrap()).unwrap();
    assert_eq!(
        serialized["types"][0]["definition"]["max"],
        "18446744073709551615"
    );
    assert_eq!(
        serde_json::from_value::<libzond::rules::Rule>(serialized).unwrap(),
        parse(unsigned).unwrap()
    );
    for value in ["0", "1", "18446744073709551615"] {
        assert_eq!(expand(unsigned, &[value]).unwrap()[1], value);
    }
    for value in [
        "",
        "-1",
        "+1",
        "01",
        "00",
        " 1",
        "1 ",
        "1.0",
        "1e3",
        "abc",
        "18446744073709551616",
        "١",
    ] {
        assert!(expand(unsigned, &[value]).is_err(), "{value}");
    }
    let signed = "type n = int(-9223372036854775808, 9223372036854775807)\nrule integer(x: n) { run /usr/bin/printf '%s' \"$x\" }";
    for value in ["-9223372036854775808", "-1", "0", "9223372036854775807"] {
        assert!(expand(signed, &[value]).is_ok());
    }
    for value in [
        "-0",
        "-01",
        "+1",
        "9223372036854775808",
        "-9223372036854775809",
    ] {
        assert!(expand(signed, &[value]).is_err());
    }
    let bounded = unsigned.replace("0, 18446744073709551615", "10, 12");
    for value in ["10", "11", "12"] {
        assert!(expand(&bounded, &[value]).is_ok());
    }
    for value in ["0", "9", "13"] {
        assert!(expand(&bounded, &[value]).is_err());
    }
}

#[test]
fn enums_and_patterns_validate_literal_values_without_recursive_expansion() {
    let source = r#"type connection = enum { binance, ibkr }
type symbol = text('[A-Z0-9]+', 2, 20)
rule read(c: connection, s: symbol) { run /usr/bin/printf "%s" "$c" "$s" }"#;
    assert_eq!(
        expand(source, &["binance", "ETHUSDT"]).unwrap(),
        ["%s", "binance", "ETHUSDT"]
    );
    for args in [
        ["unknown", "ETHUSDT"],
        ["Binance", "ETHUSDT"],
        ["binance", "xETHUSDT"],
        ["binance", "A"],
        ["binance", "A\nB"],
    ] {
        assert!(expand(source, &args).is_err(), "{args:?}");
    }
    let literal = r#"type value = enum { '$HOME', '~/path', '$(id)', '`id`', 'a b', '' }
rule literal(x: value) { run /usr/bin/printf "%s" "$x" }"#;
    for value in ["$HOME", "~/path", "$(id)", "`id`", "a b", ""] {
        assert_eq!(expand(literal, &[value]).unwrap()[1], value);
    }
    let anchored = source
        .replace("'[A-Z0-9]+'", "'(?m:A|B)'")
        .replace("2, 20", "1, 20");
    assert!(expand(&anchored, &["ibkr", "A"]).is_ok());
    assert!(expand(&anchored, &["ibkr", "AB"]).is_err());
}

#[test]
fn malformed_or_ambiguous_definitions_and_bindings_are_rejected() {
    for definition in [
        "type a = b\ntype b = a",
        "type a = missing",
        "type repo-name = enum { x }",
        "type a = enum { x }\ntype a = enum { y }",
        "type a = enum {}",
        "type a = enum { x, x }",
        "type a = uint(3, 2)",
        "type a = uint(-1, 2)",
        "type a = uint(0, 18446744073709551616)",
        "type a = int(0, 9223372036854775808)",
        "type a = text('[', 0, 10)",
        "type a = text('.*', 0, 4097)",
        "type a = text('(a{1000000}){1000000}', 0, 10)",
        "type a = choice(x, x) { row = (a, b) }",
        "type a = choice(x) {}",
        "type a = choice(x, y) { row = (a) }",
        "type a = choice(x) {\n row = (a)\n row = (b)\n}",
        "type a = choice(HOME.field) { row = (a) }",
        "type a = enum { \"$x\" }",
        "type a = enum { ~/x }",
    ] {
        assert!(
            parse(&format!(
                "{definition}\nrule test() {{ run /usr/bin/true }}"
            ))
            .is_err(),
            "{definition}"
        );
    }
    for source in [
        CHOICES.replace("${v.resource}", "${v.missing}"),
        CHOICES.replace("${v.resource}", "${n.resource}"),
        CHOICES.replace("run /usr/bin/printf", "run ${v.resource}"),
        CHOICES.replace("run /usr/bin/printf", "run ~/bin/$v"),
        CHOICES.replace("v: selected", "v: missing"),
        format!("{CHOICES}\ntype later = repo-name"),
    ] {
        assert!(parse(&source).is_err(), "{source}");
    }
    let many = (0..33)
        .map(|i| format!("type t{i} = repo-name\n"))
        .collect::<String>();
    assert!(parse(&format!("{many}rule test() {{ run true }}")).is_err());
}

#[test]
fn home_expansion_is_frozen_and_home_variable_paths_need_the_new_spelling() {
    let source = r#"rule home(x: repo-name) { run /usr/bin/printf "%s" ~ ~/code "$HOME-suffix" "~/code/$x" '~' "\~" "file~old" }"#;
    assert_eq!(
        expand(source, &["repo"]).unwrap(),
        [
            "%s",
            "/home/a b",
            "/home/a b/code",
            "/home/a b-suffix",
            "/home/a b/code/repo",
            "~",
            "~",
            "file~old"
        ]
    );
    for value in ["$HOME", "$HOME/code", "${HOME}", "${HOME}/code"] {
        for quote in ["", "\""] {
            let source = format!("rule old() {{ run printf {quote}{value}{quote} }}");
            assert!(
                parse(&source).unwrap_err().to_string().contains("use ~"),
                "{source}"
            );
            assert!(parse_stored(&source).is_ok());
        }
    }
    for value in ["~root/path", "~$x"] {
        assert!(parse(&format!("rule bad(x: repo-name) {{ run printf {value} }}")).is_err());
    }
    for word in [
        "$HOME'/code'",
        "$HOME\"/code\"",
        "\"$HOME\"/code",
        "\"${HOME}\"/code",
    ] {
        assert!(
            parse(&format!("rule old() {{ run printf {word} }}"))
                .unwrap_err()
                .to_string()
                .contains("use ~")
        );
    }
    assert_eq!(
        parse("rule exe() { run ~/bin/tool }").unwrap().program,
        "~/bin/tool"
    );
    let old = parse_stored(r#"rule old() { run /usr/bin/printf "%s" "$HOME/code" "~" }"#).unwrap();
    assert_eq!(old.language_version, 1);
    assert!(
        serde_json::to_value(&old)
            .unwrap()
            .get("language_version")
            .is_none()
    );
    let call = BoundRule {
        rule: old,
        home: "/home/old".into(),
        cwd: "/tmp".into(),
    }
    .instantiate("grant", &[], None)
    .unwrap();
    assert_eq!(call.command.args, ["%s", "/home/old/code", "~"]);
}

#[test]
fn local_definitions_round_trip_and_do_not_leak_between_rules() {
    let rule = parse(CHOICES).unwrap();
    let definitions = rule
        .types
        .iter()
        .map(|ty| ty.source())
        .collect::<Vec<_>>()
        .join("\n");
    let reparsed = parse(&format!(
        "{definitions}\nrule query(v: selected, n: count) {{ run true }}"
    ))
    .unwrap();
    assert_eq!(rule.types, reparsed.types);
    assert!(parse("rule other(v: view) { run true }").is_err());
    let alias =
        "type repository = repo-name\nrule repo(x: repository) { run /usr/bin/printf '%s' \"$x\" }";
    assert!(expand(alias, &["folio"]).is_ok());
    assert!(expand(alias, &["../folio"]).is_err());
}

#[test]
fn merged_live_example_has_exactly_the_three_previously_separate_commands() {
    let mut combined = bound(include_str!("../../examples/rules/binance-live.zond"));
    combined.rule.program = "/usr/bin/uv".into();
    for (view, market) in [
        ("balances", "portfolio"),
        ("accounts", "portfolio"),
        ("positions", "usdm"),
    ] {
        let old = format!(
            "rule old() {{ run /usr/bin/uv run --no-sync --frozen --directory \"$HOME/code/folio\" folio read binance {view} --live --market {market} --account-mode portfolio --verbose }}"
        );
        let old = BoundRule {
            rule: parse_stored(&old).unwrap(),
            home: combined.home.clone(),
            cwd: combined.cwd.clone(),
        };
        assert_eq!(
            combined
                .instantiate("grant", &[view.into()], None)
                .unwrap()
                .command,
            old.instantiate("grant", &[], None).unwrap().command
        );
    }
    assert!(
        combined
            .instantiate("grant", &["trades".into()], None)
            .is_err()
    );
    assert!(
        combined
            .instantiate("grant", &["positions".into(), "portfolio".into()], None)
            .is_err()
    );
    for source in [
        include_str!("../../examples/rules/binance-history.zond"),
        include_str!("../../examples/rules/read-github-failure.zond"),
    ] {
        parse(source).unwrap();
    }
}
