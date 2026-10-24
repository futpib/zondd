use libzond::rules::{BoundRule, TypeKind, parse};

const CHOICES: &str = r#"type view = choice(fields=(resource, market)) {
  balances = (resource="balances", market="portfolio")
  accounts = (resource="accounts", market="portfolio")
  positions = (resource="positions", market="usdm")
}
type selected = view
type count = integer(minimum_inclusive=0, maximum_exclusive=1001)
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
    let unsigned = "type n = integer(minimum_inclusive=0, maximum_exclusive=2**64)\nrule integer(x: n) { run /usr/bin/printf '%s' \"$x\" }";
    let serialized = serde_json::to_value(parse(unsigned).unwrap()).unwrap();
    assert_eq!(
        serialized["types"][0]["definition"]["maximum_exclusive"],
        "18446744073709551616"
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
    let signed = "type n = integer(minimum_inclusive=-2**63, maximum_exclusive=2**63)\nrule integer(x: n) { run /usr/bin/printf '%s' \"$x\" }";
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
    let bounded = unsigned.replace(
        "minimum_inclusive=0, maximum_exclusive=2**64",
        "minimum_inclusive=10, maximum_exclusive=13",
    );
    for value in ["10", "11", "12"] {
        assert!(expand(&bounded, &[value]).is_ok());
    }
    for value in ["0", "9", "13"] {
        assert!(expand(&bounded, &[value]).is_err());
    }
}

#[test]
fn enums_and_patterns_validate_literal_values_without_recursive_expansion() {
    let source = r#"type connection = enumeration(values=(binance, ibkr))
type symbol = text(pattern='[A-Z0-9]+', minimum_bytes_inclusive=2, maximum_bytes_exclusive=21)
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
    let literal = r#"type value = enumeration(values=('$HOME', '~/path', '$(id)', '`id`', 'a b', ''))
rule literal(x: value) { run /usr/bin/printf "%s" "$x" }"#;
    for value in ["$HOME", "~/path", "$(id)", "`id`", "a b", ""] {
        assert_eq!(expand(literal, &[value]).unwrap()[1], value);
    }
    let anchored = source
        .replace("'[A-Z0-9]+'", "'(?m:A|B)'")
        .replace("minimum_bytes_inclusive=2", "minimum_bytes_inclusive=1");
    assert!(expand(&anchored, &["ibkr", "A"]).is_ok());
    assert!(expand(&anchored, &["ibkr", "AB"]).is_err());
}

#[test]
fn malformed_or_ambiguous_definitions_and_bindings_are_rejected() {
    for definition in [
        "type a = b\ntype b = a",
        "type a = missing",
        "type repository-name = enumeration(values=(x))",
        "type a = enumeration(values=(x))\ntype a = enumeration(values=(y))",
        "type a = enumeration(values=())",
        "type a = enumeration(values=(x, x))",
        "type a = uint(3, 2)",
        "type a = uint(-1, 2)",
        "type a = uint(0, 18446744073709551616)",
        "type a = int(0, 9223372036854775808)",
        "type a = text(pattern='[', minimum_bytes_inclusive=0, maximum_bytes_exclusive=11)",
        "type a = text(pattern='.*', minimum_bytes_inclusive=0, maximum_bytes_exclusive=4098)",
        "type a = text(pattern='(a{1000000}){1000000}', minimum_bytes_inclusive=0, maximum_bytes_exclusive=11)",
        "type a = choice(fields=(x, x)) { row = (x=a, x=b) }",
        "type a = choice(fields=(x)) {}",
        "type a = choice(fields=(x, y)) { row = (x=a) }",
        "type a = choice(fields=(x)) {\n row = (x=a)\n row = (x=b)\n}",
        "type a = choice(fields=(HOME.field)) { row = (HOME.field=a) }",
        "type a = enumeration(values=(\"$x\"))",
        "type a = enumeration(values=(~/x))",
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
        format!("{CHOICES}\ntype later = repository-name"),
    ] {
        assert!(parse(&source).is_err(), "{source}");
    }
    let many = (0..33)
        .map(|i| format!("type t{i} = repository-name\n"))
        .collect::<String>();
    assert!(parse(&format!("{many}rule test() {{ run true }}")).is_err());
}

#[test]
fn home_expansion_is_frozen_and_home_variable_paths_need_the_new_spelling() {
    let source = r#"rule home(x: repository-name) { run /usr/bin/printf "%s" ~ ~/code "$HOME-suffix" "~/code/$x" '~' "\~" "file~old" }"#;
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
            assert!(libzond::rules::migration::source(&source, 1).is_ok());
        }
    }
    for value in ["~root/path", "~$x"] {
        assert!(
            parse(&format!(
                "rule bad(x: repository-name) {{ run printf {value} }}"
            ))
            .is_err()
        );
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
    let old = libzond::rules::migration::source(
        r#"rule old() { run /usr/bin/printf "%s" "$HOME/code" "~" }"#,
        1,
    )
    .unwrap();
    assert_eq!(old.language_version, 4);
    assert!(
        serde_json::to_value(&old)
            .unwrap()
            .get("language_version")
            .is_some()
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
    let alias = "type repository = repository-name\nrule repo(x: repository) { run /usr/bin/printf '%s' \"$x\" }";
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
            rule: libzond::rules::migration::source(&old, 1).unwrap(),
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

#[test]
fn arbitrary_integers_keyword_bounds_and_expression_precedence() {
    for (expression, expected) in [
        ("2**128", "340282366920938463463374607431768211456"),
        ("-2**127", "-170141183460469231731687303715884105728"),
        ("2**3**2", "512"),
        ("(-2)**4", "16"),
        ("2 + 3 * 4", "14"),
        ("(2 + 3) * 4", "20"),
        ("-7//3", "-3"),
        ("-7%3", "2"),
        ("7%-3", "-2"),
        ("12/3", "4"),
        ("20-5-3", "12"),
        ("0**0", "1"),
        ("(-1)**(2**100)", "1"),
    ] {
        let source = format!(
            "type n = integer(maximum_exclusive=({expression}) + 1, minimum_inclusive={expression})\nrule value(x: n) {{ run /usr/bin/printf '%s' \"$x\" }}"
        );
        assert_eq!(
            expand(&source, &[expected]).unwrap()[1],
            expected,
            "{source}"
        );
        let rule = parse(&source).unwrap();
        let definition = &rule.types[0];
        assert!(
            definition
                .source()
                .contains(&format!("minimum_inclusive={expected}"))
        );
        let round_trip = parse(&format!(
            "{}\nrule value(x: n) {{ run /usr/bin/printf '%s' \"$x\" }}",
            definition.source()
        ))
        .unwrap();
        assert_eq!(rule, round_trip);
    }
    for ty in ["integer", "integer()"] {
        let source = format!(
            "type n = {ty}\nrule big(x: n, y: integer) {{ run /usr/bin/printf '%s' \"$x\" \"$y\" }}"
        );
        let huge = format!("-{}", "9".repeat(300));
        assert!(expand(&source, &[&huge, &huge]).is_ok());
        assert!(expand(&source, &[&"1".repeat(4097), "0"]).is_err());
        for invalid in ["-0", "+1", "00", "-01", "1_000", "2**32", " 1", "1\n"] {
            assert!(expand(&source, &[invalid, "0"]).is_err(), "{invalid}");
        }
    }
    let named = "type uint = integer(minimum_inclusive=0, maximum_exclusive=2**32)\nrule n(x: uint) { run /usr/bin/printf '%s' \"$x\" }";
    assert!(expand(named, &["4294967295"]).is_ok());
    assert!(expand(named, &["4294967296"]).is_err());
    let lower =
        "type n = integer(minimum_inclusive=0)\nrule n(x: n) { run /usr/bin/printf '%s' \"$x\" }";
    assert!(expand(lower, &["0"]).is_ok());
    assert!(expand(lower, &["-1"]).is_err());
    let upper = lower.replace("minimum_inclusive=0", "maximum_exclusive=0");
    assert!(expand(&upper, &["-1"]).is_ok());
    assert!(expand(&upper, &["0"]).is_err());
}

#[test]
fn integer_expression_errors_and_budgets_fail_closed() {
    for bounds in [
        "0, 10",
        "min=0",
        "max=10",
        "minimum_inclusive=0, minimum_inclusive=1",
        "minimum_inclusive=1, maximum_exclusive=1",
        "minimum_inclusive=2, maximum_exclusive=1",
        "maximum_exclusive=2**-1",
        "maximum_exclusive=1/0",
        "maximum_exclusive=1//0",
        "maximum_exclusive=1%0",
        "maximum_exclusive=3/2",
        "maximum_exclusive=2**(2**32)",
        "maximum_exclusive=2**65536",
        "maximum_exclusive=",
        "maximum_exclusive=1 2",
        "maximum_exclusive=1+",
        "maximum_exclusive=1,",
        "maximum_exclusive=foo()",
        "maximum_exclusive=$HOME",
        "maximum_exclusive=$(id)",
        "maximum_exclusive=2;id",
        "maximum_exclusive=2|id",
        "maximum_exclusive=0x100",
    ] {
        let source = format!(
            "type n = integer({bounds})\nrule n(x: n) {{ run /usr/bin/printf '%s' \"$x\" }}"
        );
        assert!(parse(&source).is_err(), "{source}");
    }
    for expression in [
        format!("{}1{}", "(".repeat(80), ")".repeat(80)),
        format!("{}1", "-".repeat(80)),
        "1+".repeat(1100) + "1",
    ] {
        assert!(
            parse(&format!(
                "type n = integer(maximum_exclusive={expression})\nrule n() {{ run true }}"
            ))
            .is_err()
        );
    }
    for source in [
        "rule n(x: int) { run true }",
        "rule n(x: uint) { run true }",
        "rule n() { run /usr/bin/printf 2**32 }",
        "rule n() { run /usr/bin/printf * }",
    ] {
        assert!(parse(source).is_err(), "{source}");
    }
}

#[test]
fn constructor_keywords_are_required_distinct_and_order_independent() {
    let arguments = [
        "pattern='[A-Z]+'",
        "minimum_bytes_inclusive=2",
        "maximum_bytes_exclusive=4",
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let arguments = order.map(|i| arguments[i]).join(",\n  ");
        let source = format!(
            "type value = text(\n  {arguments}\n)\nrule text(x: value) {{ run /usr/bin/printf '%s' \"$x\" }}"
        );
        for value in ["AB", "ABC"] {
            assert!(expand(&source, &[value]).is_ok());
        }
        for value in ["A", "ABCD", "ab"] {
            assert!(expand(&source, &[value]).is_err());
        }
    }
    for definition in [
        "text('[A-Z]+', 2, 3)",
        "text(pattern='.*', minimum_bytes_inclusive=0)",
        "text(pattern='.*', maximum_bytes_exclusive=10)",
        "text(minimum_bytes_inclusive=0, maximum_bytes_exclusive=10)",
        "text(pattern='.*', pattern='[A-Z]+', maximum_bytes_exclusive=10)",
        "text(pattern='.*', min=0, max=10)",
        "text(pattern='.*', minimum_bytes_inclusive=0, maximum_bytes_exclusive=0)",
        "integer(min_inclusive=0, max_exclusive=10)",
        "enumeration((a, b))",
        "enumeration(values=(a), values=(b))",
        "enumeration()",
        "enum { a, b }",
        "choice(x) { a = (x='a') }",
        "choice(fields=(x, y)) { a = (x='a') }",
        "choice(fields=(x)) { a = (x='a', x='b') }",
        "choice(fields=(x)) { a = (unknown='a') }",
        "choice(fields=(x)) { a = ('a') }",
    ] {
        assert!(
            parse(&format!(
                "type value = {definition}\nrule bad(x: value) {{ run true }}"
            ))
            .is_err(),
            "{definition}"
        );
    }
    let choice = r#"type value = choice(fields=(first, second)) {
 row = (second='b=c', first='a')
}
rule row(x: value) { run /usr/bin/printf '%s' "${x.first}" "${x.second}" "--argument=$x" }"#;
    assert_eq!(
        expand(choice, &["row"]).unwrap(),
        ["%s", "a", "b=c", "--argument=row"]
    );
    let enumeration = "type value=enumeration(values=('a=b', 'type', 'rule'))\nrule words(x: value) { run /usr/bin/printf '%s' \"$x\" }";
    for value in ["a=b", "type", "rule"] {
        assert_eq!(expand(enumeration, &[value]).unwrap()[1], value);
    }
}

#[test]
fn text_half_open_bounds_include_empty_and_maximum_sized_values() {
    let source = "type value=text(pattern='.*', minimum_bytes_inclusive=0, maximum_bytes_exclusive=1)\nrule text(x: value) { run /usr/bin/printf '%s' \"$x\" }";
    assert!(expand(source, &[""]).is_ok());
    assert!(expand(source, &["a"]).is_err());
    let source = source.replace("maximum_bytes_exclusive=1", "maximum_bytes_exclusive=4097");
    assert!(expand(&source, &[&"a".repeat(4096)]).is_ok());
    assert!(expand(&source, &[&"a".repeat(4097)]).is_err());
}
