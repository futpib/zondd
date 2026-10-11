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

pub(super) fn is_current(bound: &BoundRule, review: Option<&serde_json::Value>) -> bool {
    let Ok(mut current) = describe(bound) else {
        return false;
    };
    if review == Some(&current) {
        return true;
    }
    // The directory effect's spelling changed, but previously reviewed semantics did not.
    if bound.rule.create_new.is_some() {
        for section in current["sections"].as_array_mut().unwrap() {
            if section["title"] == "Effects" {
                section["fields"][0]["label"] = "create-new".into();
            }
        }
    }
    review == Some(&current)
}

pub(super) fn describe(bound: &BoundRule) -> Result<serde_json::Value> {
    let rule = &bound.rule;
    let mut sections = vec![
        section(
            "Authority",
            vec![
                field(
                    "Grant",
                    "Approval permits repeated invocations by this principal (including every assigned key) without another prompt.",
                ),
                field(
                    "Privileges",
                    "Commands run as the daemon's Unix user without gaining new privileges. This does not isolate access to that user's files or program configuration.",
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
    if !rule.parameters.is_empty() {
        let mut fields = Vec::new();
        for parameter in &rule.parameters {
            let description = match parameter.kind.as_str() {
                "repo-name" => {
                    "1–100 ASCII letters, digits, dots, underscores or hyphens; starts with a letter or digit. Full match: [A-Za-z0-9][A-Za-z0-9._-]{0,99}. Validated on every invocation; does not check repository existence."
                }
                _ => bail!("missing review description for parameter type"),
            };
            fields.push(field(
                format!("{}: {}", parameter.name, parameter.kind),
                description,
            ));
        }
        sections.push(section("Parameters (positional order)", fields));
    }
    if !rule.requirements.is_empty() {
        let mut fields = vec![field(
            "Timing",
            "Checked immediately before execution. These observations do not reserve paths or prevent subsequent filesystem changes.",
        )];
        for requirement in &rule.requirements {
            let description = match requirement.kind.as_str() {
                "is-dir" => {
                    "Must be an existing trusted directory, reached without following symlinks."
                }
                "absent" => {
                    "Must have no directory entry, including no dangling symlink; its parent must be a trusted directory reached without following symlinks."
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
            field("create-new-dir", "Publishes a directory only after exit status zero, atomically and only if the destination is still absent. Never replaces an existing file, directory or symlink. Failure or cancellation discards staging; other command side effects are not rolled back."),
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
    fn legacy_directory_label_preserves_grants_but_changed_semantics_do_not() {
        let bound = BoundRule {
            rule: libzond::rules::parse(
                r#"rule directory(x: repo-name) {
  create-new-dir "$HOME/$x" as dest { run mkdir "$dest" }
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
        assert!(is_current(&bound, Some(&legacy)));
        legacy["sections"][0]["fields"][0]["value"] = "Changed authority".into();
        assert!(!is_current(&bound, Some(&legacy)));
    }
}
