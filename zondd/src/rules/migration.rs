use super::{check_stored, resolve_program, review};
use anyhow::{Context, Result, ensure};
use libzond::{
    config::revision,
    rules::{BoundRule, LANGUAGE_VERSION, RuleState, migration},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod previous;

// Reproduce the original schema when checking a pre-migration digest.
// Audit records are immutable; only current rule state receives the new format.
#[derive(Deserialize, Serialize)]
struct PreviousProposal {
    id: String,
    principal: String,
    source: String,
    bound: previous::Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    review: Option<Value>,
    digest: String,
    revision: String,
    principal_revision: String,
    created_unix_ms: u64,
    expires_unix_ms: u64,
}

fn previous_description(rule: &Value, mut name: String) -> Option<String> {
    let types = rule.get("types")?.as_array()?;
    for _ in 0..=types.len() {
        let definition = &types.iter().find(|t| t["name"] == name)?["definition"];
        let min = definition["min"].as_str().unwrap_or_default();
        let max = definition["max"].as_str().unwrap_or_default();
        match definition["kind"].as_str()? {
            "alias" => name = definition["target"].as_str()?.into(),
            "uint" => {
                return Some(format!(
                    "Unsigned decimal integer from {min} through {max}, inclusive. Canonical digits only: no sign, leading zeros (except 0), whitespace or overflow."
                ));
            }
            "int" => {
                return Some(format!(
                    "Signed decimal integer from {min} through {max}, inclusive. Canonical digits with optional minus: no plus, leading zeros, negative zero, whitespace or overflow."
                ));
            }
            "text" => {
                return Some(format!(
                    "Printable ASCII text, {}–{} bytes, matching the entire regular expression {}. Validated on every invocation; values are never expanded again.",
                    definition["min"], definition["max"], definition["pattern"]
                ));
            }
            _ => return None,
        }
    }
    None
}

fn previous_literal(value: &str) -> String {
    let mut text = String::from("\"");
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '$' | '~' | '`') {
            text.push('\\');
        }
        text.push(c);
    }
    text.push('"');
    text
}

fn previous_type_source(ty: &Value, current: &libzond::rules::TypeDefinition) -> String {
    let definition = &ty["definition"];
    let name = ty["name"].as_str().unwrap();
    let value = match definition["kind"].as_str() {
        Some(kind @ ("uint" | "int")) => format!(
            "{kind}({}, {})",
            definition["min"].as_str().unwrap(),
            definition["max"].as_str().unwrap()
        ),
        Some("alias") => definition["target"].as_str().unwrap().into(),
        Some("enum") => format!(
            "enum {{ {} }}",
            definition["values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| previous_literal(v.as_str().unwrap()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Some("integer") => {
            let mut bounds = Vec::new();
            for key in ["min_inclusive", "max_exclusive"] {
                if let Some(value) = definition[key].as_str() {
                    bounds.push(format!("{key}={value}"));
                }
            }
            if bounds.is_empty() {
                "integer".into()
            } else {
                format!("integer({})", bounds.join(", "))
            }
        }
        Some("text") => format!(
            "text({}, {}, {})",
            previous_literal(definition["pattern"].as_str().unwrap()),
            definition["min"],
            definition["max"]
        ),
        Some("choice") => format!(
            "choice({}) {{\n{}\n}}",
            definition["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(", "),
            definition["cases"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, row)| format!(
                    "  {name} = ({})",
                    row.as_array()
                        .unwrap()
                        .iter()
                        .map(|v| previous_literal(v.as_str().unwrap()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
                .collect::<Vec<_>>()
                .join("\n")
        ),
        _ => return current.source(),
    };
    format!("type {name} = {value}")
}

fn previous_body(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            let indent = &line[..line.len() - line.trim_start().len()];
            let text = line.trim_start();
            for (current, previous) in [
                ("require is-directory ", "require is-dir "),
                ("create-new-directory ", "create-new-dir "),
            ] {
                if let Some(rest) = text.strip_prefix(current) {
                    return format!("{indent}{previous}{rest}");
                }
            }
            line.into()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn previous_review_matches(
    bound: &BoundRule,
    old_rule: &Value,
    saved: Option<&Value>,
    version: u32,
) -> Result<bool> {
    let mut old_bound = bound.clone();
    old_bound.rule.language_version = version;
    let mut current = review::describe(&old_bound)?;
    let source = review::normalized_source(&old_bound);
    if version == 4 {
        let source = source
            .lines()
            .map(|line| {
                let text = line.trim_start();
                if let Some(command) = text.strip_prefix("run --sudo ") {
                    format!(
                        "{}run --allow-privilege-escalation {command}",
                        &line[..line.len() - text.len()]
                    )
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        current["sections"][0]["fields"][0]["value"] = source.into();
        return Ok(saved == Some(&current));
    }
    let prefix = bound
        .rule
        .types
        .iter()
        .map(|ty| format!("{}\n", ty.source()))
        .collect::<String>();
    let old_types = old_rule["types"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let old_prefix = bound
        .rule
        .types
        .iter()
        .zip(old_types)
        .map(|(ty, previous)| format!("{}\n", previous_type_source(previous, ty)))
        .collect::<String>();
    let parameters = &bound.rule.parameters;
    let old_parameters: Vec<libzond::rules::Parameter> =
        serde_json::from_value(old_rule["parameters"].clone())?;
    let header = |parameters: &[libzond::rules::Parameter]| {
        format!(
            "rule {}({})",
            bound.rule.name,
            parameters
                .iter()
                .map(|p| format!("{}: {}", p.name, p.kind))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let body = source.strip_prefix(&prefix).unwrap().replacen(
        &header(parameters),
        &header(&old_parameters),
        1,
    );
    current["sections"][0]["fields"][0]["value"] =
        format!("{old_prefix}{}", previous_body(&body)).into();
    for section in current["sections"].as_array_mut().unwrap() {
        if section["title"] == "Parameters (positional order)" {
            for (field, parameter) in section["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .zip(&old_parameters)
            {
                field["label"] = format!("{}: {}", parameter.name, parameter.kind).into();
                if let Some(description) = previous_description(old_rule, parameter.kind.clone()) {
                    field["value"] = description.into();
                }
            }
        } else if section["title"] == "Checks" {
            for field in section["fields"].as_array_mut().unwrap() {
                if field["label"] == "is-directory" {
                    field["label"] = "is-dir".into();
                }
            }
        } else if section["title"] == "Effects" {
            section["fields"][0]["label"] = "create-new-dir".into();
        } else if section["title"] == "Local type definitions" {
            for ((field, ty), previous) in section["fields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .zip(&bound.rule.types)
                .zip(old_types)
            {
                let name = previous["name"].as_str().unwrap();
                field["label"] = name.into();
                let description = previous_description(old_rule, name.into())
                    .unwrap_or(bound.rule.type_description(&ty.name)?);
                field["value"] =
                    format!("{}\n{description}", previous_type_source(previous, ty)).into();
            }
        }
    }
    for old_home in [false, true] {
        let mut candidate = current.clone();
        if old_home {
            if !bound.rule.types.is_empty() {
                continue;
            }
            candidate["sections"][0]["fields"][0]["value"] =
                previous_body(&review::normalized_source_mode(&old_bound, false)).into();
        }
        if !saved.is_some_and(|r| {
            r["sections"]
                .as_array()
                .is_some_and(|sections| sections.iter().any(|s| s["title"] == "Normalized rule"))
        }) {
            candidate["sections"].as_array_mut().unwrap().remove(0);
        }
        if saved == Some(&candidate) {
            return Ok(true);
        }
        if bound.rule.create_new.is_some() {
            for section in candidate["sections"].as_array_mut().unwrap() {
                if section["title"] == "Effects" {
                    section["fields"][0]["label"] = "create-new".into();
                }
            }
        }
        if saved == Some(&candidate) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn migrate(record: &str) -> Result<Option<RuleState>> {
    let mut value: Value = serde_json::from_str(record)?;
    let version = value["proposal"]["bound"]["rule"]
        .get("language_version")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    if version == u64::from(LANGUAGE_VERSION) {
        return Ok(None);
    }
    ensure!(
        matches!(version, 1..=4),
        "unsupported stored rule language {version}"
    );
    let mut previous: PreviousProposal = serde_json::from_value(value["proposal"].clone())?;
    let old_rule = value["proposal"]["bound"]["rule"].clone();
    let migrated_rule = migration::compiled(old_rule.clone())?;
    value["proposal"]["bound"]["rule"] = serde_json::to_value(&migrated_rule)?;
    let mut state: RuleState = serde_json::from_value(value)?;
    let valid = (|| -> Result<()> {
        let digest = std::mem::take(&mut previous.digest);
        ensure!(
            revision(&serde_json::to_string(&previous)?) == digest,
            "previous proposal digest does not match its contents"
        );
        ensure!(
            resolve_program(migration::source(&previous.source, version as u32)?)? == migrated_rule,
            "previous rule source and compiled definition disagree"
        );
        ensure!(
            previous_review_matches(
                &state.proposal.bound,
                &old_rule,
                previous.review.as_ref(),
                version as u32
            )?,
            "previous proposal review is missing or changed"
        );
        Ok(())
    })();
    state.proposal.source = review::normalized_source(&state.proposal.bound);
    state.proposal.review = Some(review::describe(&state.proposal.bound)?);
    state.proposal.digest.clear();
    state.proposal.digest = revision(&serde_json::to_string(&state.proposal)?);
    let valid = valid.and_then(|()| check_stored(&state.proposal).context("check migrated rule"));
    if let Err(error) = valid {
        if matches!(state.status.as_str(), "active" | "pending") {
            state.status = "invalidated".into();
        }
        state.reason =
            format!("rule migration failed consistency checks: {error:#}; submit a new proposal");
    }
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PreviousProposal {
        let state: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/integer-v2.json")).unwrap();
        let mut proposal: PreviousProposal =
            serde_json::from_value(state["proposal"].clone()).unwrap();
        let digest = std::mem::take(&mut proposal.digest);
        assert_eq!(
            revision(&serde_json::to_string(&proposal).unwrap()),
            digest,
            "fixture captured from installed zondd 1d1abd38a774 must retain its original digest"
        );
        let mut bound = serde_json::to_value(&proposal.bound).unwrap();
        bound["home"] = libzond::paths::home_dir()
            .to_string_lossy()
            .into_owned()
            .into();
        for section in proposal.review.as_mut().unwrap()["sections"]
            .as_array_mut()
            .unwrap()
        {
            if section["title"] == "Execution" {
                for field in section["fields"].as_array_mut().unwrap() {
                    if field["label"] == "Server HOME" {
                        field["value"] = bound["home"].to_string().into();
                    }
                }
            }
        }
        proposal.bound = serde_json::from_value(bound).unwrap();
        proposal
    }

    fn record(mut proposal: PreviousProposal) -> String {
        proposal.digest.clear();
        proposal.digest = revision(&serde_json::to_string(&proposal).unwrap());
        format!(
            r#"{{"proposal":{},"status":"active","reason":"approved","grant_expires_unix_ms":null}}"#,
            serde_json::to_string(&proposal).unwrap()
        )
    }

    #[test]
    fn captured_v4_digest_is_verified_using_its_original_serialization() {
        let state: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/sudo-v4.json")).unwrap();
        let mut previous: PreviousProposal =
            serde_json::from_value(state["proposal"].clone()).unwrap();
        let digest = std::mem::take(&mut previous.digest);
        assert_eq!(revision(&serde_json::to_string(&previous).unwrap()), digest);
    }

    #[test]
    fn captured_v3_fixture_retains_its_original_digest_and_review() {
        let record = include_str!("../../tests/fixtures/types-v3.json");
        let value: Value = serde_json::from_str(record).unwrap();
        let mut previous: PreviousProposal =
            serde_json::from_value(value["proposal"].clone()).unwrap();
        let digest = std::mem::take(&mut previous.digest);
        assert_eq!(revision(&serde_json::to_string(&previous).unwrap()), digest);
        let migrated = migrate(record).unwrap().unwrap();
        assert_eq!(migrated.status, "pending", "{}", migrated.reason);
        assert_eq!(
            migrated.proposal.bound.rule.language_version,
            LANGUAGE_VERSION
        );
        check_stored(&migrated.proposal).unwrap();
    }

    #[test]
    fn installed_v2_fixture_migrates_with_exact_scope_and_an_idempotent_digest() {
        let old = record(fixture());
        // Stored JSON formatting and object key order do not change the approved digest.
        let old =
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(&old).unwrap()).unwrap();
        let new = migrate(&old).unwrap().unwrap();
        assert_eq!(new.status, "active", "{}", new.reason);
        assert_eq!(new.proposal.bound.rule.language_version, LANGUAGE_VERSION);
        for (a, b) in [
            ("0", "-9223372036854775808"),
            ("18446744073709551615", "9223372036854775807"),
        ] {
            let invocation = new
                .proposal
                .bound
                .instantiate("grant", &[a.into(), b.into()], None)
                .unwrap();
            assert_eq!(invocation.command.args, ["%s:%s", a, b]);
        }
        assert!(
            migrate(&serde_json::to_string(&new).unwrap())
                .unwrap()
                .is_none()
        );
        check_stored(&new.proposal).unwrap();
    }

    #[test]
    fn migration_does_not_restore_tampered_authority() {
        for tamper in ["source", "review", "digest"] {
            let mut proposal = fixture();
            if tamper == "source" {
                proposal.source = proposal.source.replace("run printf", "run false");
            }
            if tamper == "review" {
                proposal.review.as_mut().unwrap()["sections"][1]["fields"][0]["value"] =
                    "anything goes".into();
            }
            let mut old = record(proposal);
            if tamper == "digest" {
                old = old.replace("\"digest\":\"", "\"digest\":\"bad-");
            }
            let new = migrate(&old).unwrap().unwrap();
            assert_eq!(new.status, "invalidated", "{tamper}: {}", new.reason);
            assert!(new.reason.contains("consistency checks"));
        }
    }

    #[test]
    fn migration_renames_a_previous_local_integer_type_and_its_aliases() {
        let previous = serde_json::to_string(&fixture())
            .unwrap()
            .replace("count", "integer");
        let old = record(serde_json::from_str(&previous).unwrap());
        let new = migrate(&old).unwrap().unwrap();
        assert_eq!(new.status, "active", "{}", new.reason);
        assert_eq!(new.proposal.bound.rule.types[0].name, "integer-local-1");
        assert!(
            new.proposal
                .source
                .contains("type selected = integer-local-1")
        );
        assert!(
            new.proposal
                .bound
                .instantiate("grant", &["18446744073709551616".into(), "0".into()], None)
                .is_err()
        );
    }

    #[test]
    fn old_reviews_without_normalized_source_are_migrated_to_complete_reviews() {
        let mut proposal = fixture();
        proposal.review.as_mut().unwrap()["sections"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        let new = migrate(&record(proposal)).unwrap().unwrap();
        assert_eq!(new.status, "active", "{}", new.reason);
        assert!(review::is_current(
            &new.proposal.bound,
            new.proposal.review.as_ref()
        ));
    }
}
