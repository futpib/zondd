use anyhow::{Result, bail};
use libzond::rules::{BoundRule, Part, Review, ReviewField, ReviewSection, Word};

fn field(label: impl Into<String>, value: impl Into<String>) -> ReviewField {
    ReviewField {
        label: label.into(),
        value: value.into(),
    }
}

fn section(title: &str, fields: Vec<ReviewField>) -> ReviewSection {
    ReviewSection {
        title: title.into(),
        fields,
    }
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("serialize string")
}

// Quoted literal pieces and ${bindings} stay distinguishable even for a literal dollar sign.
fn word(word: &Word) -> String {
    if word.0.is_empty() {
        return quoted("");
    }
    word.0
        .iter()
        .map(|part| match part {
            Part::Literal(value) => quoted(value),
            Part::Variable(name) => format!("${{{name}}}"),
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

fn source_word_mode(word: &Word, home: bool) -> String {
    if let [Part::Literal(value)] = word.0.as_slice()
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./@%+=-".contains(&b))
    {
        return value.clone();
    }
    let mut value = String::from("\"");
    for (index, part) in word.0.iter().enumerate() {
        match part {
            Part::Variable(name)
                if home
                    && index == 0
                    && name == "HOME"
                    && (word.0.len() == 1
                        || matches!(word.0.get(1), Some(Part::Literal(value)) if value.starts_with('/'))) =>
            {
                value.push('~')
            }
            Part::Variable(name) => value.push_str(&format!("${{{name}}}")),
            Part::Literal(text) => {
                for c in text.chars() {
                    if matches!(c, '\\' | '"' | '$') || (home && matches!(c, '~' | '`')) {
                        value.push('\\');
                    }
                    value.push(c);
                }
            }
        }
    }
    value.push('"');
    value
}

pub(super) fn normalized_source(bound: &BoundRule) -> String {
    normalized_source_mode(bound, true)
}

pub(super) fn normalized_source_mode(bound: &BoundRule, home: bool) -> String {
    let rule = &bound.rule;
    let home = home && rule.language_version >= 2;
    let parameters = rule
        .parameters
        .iter()
        .map(|p| format!("{}: {}", p.name, p.kind))
        .collect::<Vec<_>>()
        .join(", ");
    let mut source = rule
        .types
        .iter()
        .map(|ty| format!("{}\n", ty.source()))
        .collect::<String>();
    source.push_str(&format!("rule {}({parameters}) {{\n", rule.name));
    for requirement in &rule.requirements {
        source.push_str(&format!(
            "  require {} {}\n",
            requirement.kind,
            source_word_mode(&requirement.path, home)
        ));
    }
    let indent = if let Some(new) = &rule.create_new {
        source.push_str(&format!(
            "  create-new-directory {} as {} {{\n",
            source_word_mode(&new.path, home),
            new.variable
        ));
        "    "
    } else {
        "  "
    };
    source.push_str(&format!(
        "{indent}run {}{}",
        if rule.sudo_password {
            "--allow-privilege-escalation "
        } else {
            ""
        },
        source_word_mode(&Word(vec![Part::Literal(rule.program.clone())]), home)
    ));
    for arg in &rule.args {
        source.push(' ');
        source.push_str(&source_word_mode(arg, home));
    }
    source.push('\n');
    if rule.create_new.is_some() {
        source.push_str("  }\n");
    }
    source.push('}');
    source
}

pub(super) fn is_current(bound: &BoundRule, review: Option<&serde_json::Value>) -> bool {
    describe(bound).is_ok_and(|current| review == Some(&current))
}

pub(super) fn describe(bound: &BoundRule) -> Result<serde_json::Value> {
    let rule = &bound.rule;
    let checks_service = rule
        .requirements
        .iter()
        .any(|r| r.kind == "user-service-active-or-enabled");
    let mut sections = vec![
        section(
            "Normalized rule",
            vec![field("Definition", normalized_source(bound))],
        ),
        section(
            "Authority",
            vec![
                field(
                    "Grant",
                    "Approval permits repeated invocations by this principal (including every assigned key) without another prompt.",
                ),
                field(
                    "Privileges",
                    if rule.sudo_password {
                        "Commands run as the daemon's Unix user with permission to gain privileges through sudo or other setuid helpers (no_new_privs is disabled). This grant permits repeated privileged invocations without another command approval. Sudo still enforces sudoers and can request passwords through zond; passwords are not stored. Review the executable, its configuration and its child processes, including package build scripts."
                    } else {
                        "Commands run as the daemon's Unix user without gaining new privileges. This does not isolate access to that user's files or program configuration."
                    },
                ),
            ],
        ),
        section(
            "Execution",
            vec![
                field("Executable", quoted(&rule.program)),
                field("Working directory", quoted(&bound.cwd.to_string_lossy())),
                field("Server HOME", quoted(&bound.home)),
                field(
                    "Expansion",
                    "Quoted pieces are literal text; ${name} is a binding. Pieces joined with + form one argument. No shell, word splitting, globbing or recursive expansion.",
                ),
            ],
        ),
    ];
    if checks_service {
        sections[0].fields.push(field(
            "Service manager",
            "The check uses the daemon user's systemd manager. Services started through that manager use their own unit settings; they do not inherit the command's no_new_privs restriction. Review which service names and command arguments this grant permits.",
        ));
    }
    if !rule.parameters.is_empty() {
        let mut fields = Vec::new();
        for parameter in &rule.parameters {
            let description = rule.type_description(&parameter.kind)?;
            fields.push(field(
                format!("{}: {}", parameter.name, parameter.kind),
                description,
            ));
        }
        sections.push(section("Parameters (positional order)", fields));
    }
    if !rule.types.is_empty() {
        sections.push(section(
            "Local type definitions",
            rule.types
                .iter()
                .map(|ty| {
                    Ok(field(
                        &ty.name,
                        format!("{}\n{}", ty.source(), rule.type_description(&ty.name)?),
                    ))
                })
                .collect::<Result<_>>()?,
        ));
    }
    if !rule.requirements.is_empty() {
        let mut fields = vec![field(
            "Timing",
            if checks_service {
                "Checked during check invoke and immediately before execution, after waiting for capacity. Service and filesystem state can change after the check; it does not reserve state or make check-and-execute atomic. Query failures or a 5-second check timeout prevent execution."
            } else {
                "Checked immediately before execution. These observations do not reserve paths or prevent subsequent filesystem changes."
            },
        )];
        for requirement in &rule.requirements {
            let description = match requirement.kind.as_str() {
                "is-directory" => {
                    "Must be an existing trusted directory, reached without following symlinks."
                }
                "absent" => {
                    "Must have no directory entry, including no dangling symlink; its parent must be a trusted directory reached without following symlinks."
                }
                "user-service-active-or-enabled" => {
                    "Requires LoadState=loaded and either ActiveState=active or UnitFileState=enabled/enabled-runtime in the daemon user's systemd manager. Inactive or failed disabled services do not pass. Static, indirect, generated or transient alone do not count as enabled. Manually stopped enabled services still pass. Uses /usr/bin/systemctl with the daemon's session environment. The target must be one explicit .service name (at most 255 ASCII letters, digits, dots, underscores, hyphens and one optional nonempty @instance; starts with a letter or digit), without paths, patterns or options."
                }
                _ => bail!("missing review description for rule check"),
            };
            fields.push(field(
                &requirement.kind,
                format!("{}\n{description}", word(&requirement.path)),
            ));
        }
        sections.push(section("Checks", fields));
    }
    if let Some(new) = &rule.create_new {
        sections.push(section("Effects", vec![
            field("create-new-directory", "Publishes a directory only after exit status zero, atomically and only if the destination is still absent. Never replaces an existing file, directory or symlink. Failure or cancellation discards staging; other command side effects are not rolled back."),
            field("Destination", word(&new.path)),
            field("Output binding", format!("${{{}}} is a private staging path on the destination filesystem, not the final destination.", new.variable)),
            field("Parent directory", "Must already exist, be trusted and contain no symlinks. Publication fails if the filesystem cannot guarantee no replacement."),
        ]));
    }
    if !rule.args.is_empty() {
        sections.push(section(
            "Command arguments",
            rule.args
                .iter()
                .enumerate()
                .map(|(index, arg)| field(format!("Argument {}", index + 1), word(arg)))
                .collect(),
        ));
    }
    Ok(serde_json::to_value(Review {
        version: 1,
        title: rule.name.clone(),
        sections,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_rule_round_trips_literal_text_variables_and_effects() {
        for source in [
            include_str!("../../../examples/rules/binance-live.zond"),
            include_str!("../../../examples/rules/binance-history.zond"),
            include_str!("../../../examples/rules/read-github-failure.zond"),
            "type literal = enumeration(values=('$HOME', '~/path', '`id`', ''))\nrule typed(x: literal) { run printf '`id`' \"$x\" }",
            "# caller says this is harmless\nrule clone(x: repository-name) {\n require is-directory \"~/code\"\n create-new-directory \"~/code/$x\" as dest {\n run /usr/bin/git clone -- \"git@github.com:futpib/$x.git\" \"$dest\"\n }\n}",
            r##"rule literals(x: repository-name) { run printf "" '$x' '${x}' '$(whoami)' "a\"b" "a\\b" "$x.txt" "a'x" "# comment" }"##,
            "rule whitespace() { run printf \"a\tb\" }",
            "rule privileged() { run --allow-privilege-escalation /usr/bin/paru -Syu --noconfirm }",
            "rule service(name: repository-name) {\n require user-service-active-or-enabled \"$name.service\"\n run /usr/bin/systemctl --user restart -- \"$name.service\"\n}",
        ] {
            let rule = libzond::rules::parse(source).unwrap();
            let bound = BoundRule {
                rule: rule.clone(),
                home: "/home/test".into(),
                cwd: "/tmp".into(),
            };
            let normalized = normalized_source(&bound);
            assert_eq!(
                libzond::rules::parse(&normalized).unwrap(),
                rule,
                "{normalized}"
            );
            assert!(!normalized.contains("caller says"));
            assert_eq!(
                describe(&bound).unwrap()["sections"][0]["fields"][0]["value"],
                normalized
            );
        }
    }

    #[test]
    fn current_reviews_require_the_exact_normalized_rule() {
        let bound = BoundRule {
            rule: libzond::rules::parse("rule old() { run /usr/bin/true }").unwrap(),
            home: "/home/test".into(),
            cwd: "/tmp".into(),
        };
        let mut current = describe(&bound).unwrap();
        let mut old = current.clone();
        old["sections"].as_array_mut().unwrap().remove(0);
        assert!(!is_current(&bound, Some(&old)));
        current["sections"][0]["fields"][0]["value"] = "rule old() { run /usr/bin/false }".into();
        assert!(!is_current(&bound, Some(&current)));
    }

    #[test]
    fn sudo_authority_cannot_reuse_an_unprivileged_review() {
        let mut bound = BoundRule {
            rule: libzond::rules::parse("rule upgrade() { run paru -Syu }").unwrap(),
            home: "/home/test".into(),
            cwd: "/tmp".into(),
        };
        let ordinary = describe(&bound).unwrap();
        bound.rule.sudo_password = true;
        let privileged = describe(&bound).unwrap();
        assert!(!is_current(&bound, Some(&ordinary)));
        assert!(is_current(&bound, Some(&privileged)));
        bound.rule.sudo_password = false;
        assert!(!is_current(&bound, Some(&privileged)));
    }

    #[test]
    fn current_reviews_require_the_current_directory_effect() {
        let bound = BoundRule {
            rule: libzond::rules::parse(
                r#"rule directory(x: repository-name) {
  create-new-directory "~/$x" as dest { run mkdir "$dest" }
}"#,
            )
            .unwrap(),
            home: "/home/test".into(),
            cwd: "/tmp".into(),
        };
        let current = describe(&bound).unwrap();
        assert!(is_current(&bound, Some(&current)));
        assert!(!is_current(&bound, None));
        let mut legacy = current;
        let effects = legacy["sections"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|s| s["title"] == "Effects")
            .unwrap();
        effects["fields"][0]["label"] = "create-new".into();
        assert!(!is_current(&bound, Some(&legacy)));
        legacy["sections"][0]["fields"][0]["value"] = "Changed authority".into();
        assert!(!is_current(&bound, Some(&legacy)));
    }
}
