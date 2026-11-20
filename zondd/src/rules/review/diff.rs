use super::{field, quoted, section, source_word_mode};
use libzond::rules::{BoundRule, ReviewSection, Rule, TypeKind};
use std::collections::{BTreeMap, BTreeSet};

// Compare resolved authority, not source formatting. Choice rows are separate
// entries so adding one target never repeats the unchanged allowlist.
fn entries(bound: &BoundRule) -> BTreeMap<String, String> {
    let Rule {
        name,
        language_version,
        types,
        parameters,
        requirements,
        create_new,
        program,
        args,
        sudo_password,
    } = &bound.rule;
    let mut entries = BTreeMap::from([
        ("Rule name".into(), quoted(name)),
        ("Language version".into(), language_version.to_string()),
        ("Executable".into(), quoted(program)),
        (
            "Working directory".into(),
            quoted(&bound.cwd.to_string_lossy()),
        ),
        ("Server HOME".into(), quoted(&bound.home)),
        (
            "Privilege escalation".into(),
            if *sudo_password {
                "Permitted (run --sudo)"
            } else {
                "Disabled (no_new_privs)"
            }
            .into(),
        ),
    ]);
    for (index, parameter) in parameters.iter().enumerate() {
        entries.insert(
            format!("Parameter {}", index + 1),
            format!("{}: {}", parameter.name, parameter.kind),
        );
    }
    for ty in types {
        match &ty.definition {
            TypeKind::Choice { fields, cases } => {
                entries.insert(format!("Choice {} fields", ty.name), fields.join(", "));
                for (name, values) in cases {
                    entries.insert(
                        format!("Choice {}.{name}", ty.name),
                        fields
                            .iter()
                            .zip(values)
                            .map(|(field, value)| format!("{field}={}", quoted(value)))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
            }
            _ => {
                entries.insert(format!("Type {}", ty.name), ty.source());
            }
        }
    }
    for (index, requirement) in requirements.iter().enumerate() {
        entries.insert(
            format!("Check {}", index + 1),
            format!(
                "require {} {}",
                requirement.kind,
                source_word_mode(&requirement.path, true)
            ),
        );
    }
    if let Some(new) = create_new {
        entries.insert(
            "Directory publication".into(),
            format!(
                "create-new-directory {} as {}",
                source_word_mode(&new.path, true),
                new.variable
            ),
        );
    }
    for (index, arg) in args.iter().enumerate() {
        entries.insert(
            format!("Argument {}", index + 1),
            source_word_mode(arg, true),
        );
    }
    entries
}

pub(super) fn describe(before: &BoundRule, after: &BoundRule) -> ReviewSection {
    let before = entries(before);
    let after = entries(after);
    let mut fields = Vec::new();
    let (mut added, mut removed, mut changed) = (0, 0, 0);
    for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        match (before.get(key), after.get(key)) {
            (None, Some(value)) => {
                added += 1;
                fields.push(field(format!("Added {key}"), value));
            }
            (Some(value), None) => {
                removed += 1;
                fields.push(field(format!("Removed {key}"), value));
            }
            (Some(old), Some(new)) if old != new => {
                changed += 1;
                fields.push(field(
                    format!("Changed {key}"),
                    format!("Before:\n{old}\nAfter:\n{new}"),
                ));
            }
            _ => {}
        }
    }
    fields.insert(0, field("Summary", if fields.is_empty() {
        "No authorization changes in the resolved definition.".into()
    } else {
        format!("{added} added, {removed} removed, {changed} changed. Unchanged entries are omitted.")
    }));
    section("Changes from approved rule", fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(source: &str) -> BoundRule {
        BoundRule {
            rule: libzond::rules::parse(source).unwrap(),
            home: "/home/test".into(),
            cwd: "/tmp".into(),
        }
    }

    #[test]
    fn reports_command_types_privileges_checks_effects_and_execution_bindings() {
        let before = bound(
            "type count = integer(minimum_inclusive=1, maximum_exclusive=5)\nrule task(n: count) {\n require is-directory /tmp\n run printf \"$n\"\n}",
        );
        let mut after = bound(
            "type count = integer(minimum_inclusive=0, maximum_exclusive=20)\nrule task(n: count) {\n create-new-directory /tmp/new as dest {\n run --sudo mkdir \"$dest\"\n }\n}",
        );
        after.home = "/home/other".into();
        after.cwd = "/var/tmp".into();
        let diff = describe(&before, &after);
        let labels = diff
            .fields
            .iter()
            .map(|f| f.label.as_str())
            .collect::<Vec<_>>();
        for label in [
            "Changed Executable",
            "Changed Argument 1",
            "Changed Type count",
            "Changed Privilege escalation",
            "Removed Check 1",
            "Added Directory publication",
            "Changed Server HOME",
            "Changed Working directory",
        ] {
            assert!(labels.contains(&label), "missing {label}: {labels:?}");
        }
        assert!(!labels.contains(&"Changed Parameter 1"));
    }

    #[test]
    fn formatting_only_changes_do_not_claim_authorization_changes() {
        let before = bound("rule task() { run printf '%s' hello }");
        let after = bound("# a comment\nrule task() {\n run printf \"%s\" \"hello\"\n}");
        let diff = describe(&before, &after);
        assert_eq!(diff.fields.len(), 1);
        assert_eq!(
            diff.fields[0].value,
            "No authorization changes in the resolved definition."
        );
    }
}
