//! One-time conversion of persisted v1–v3 rules; never used for new proposals.
use super::{LANGUAGE_VERSION, Part, Rule, Token, Word, lex, validate_rule};
use anyhow::{Context, Result, ensure};
use num_bigint::BigInt;
use serde_json::Value;
use std::collections::BTreeMap;

mod previous_parser;

fn upper(kind: &str, min: &str, max: &str) -> Result<BigInt> {
    if kind == "uint" {
        ensure!(
            min.parse::<u64>()? <= max.parse::<u64>()?,
            "invalid previous uint bounds"
        );
    } else {
        ensure!(
            min.parse::<i64>()? <= max.parse::<i64>()?,
            "invalid previous int bounds"
        );
    }
    Ok(max.parse::<BigInt>()? + 1)
}

pub fn source(source: &str, version: u32) -> Result<Rule> {
    ensure!(
        matches!(version, 1..=3),
        "unsupported previous rule language"
    );
    let mut tokens = lex(source, version)?;
    let (starts, header) = definitions(&tokens);
    let names: Vec<_> = starts
        .iter()
        .filter_map(|start| match tokens.get(start + 1) {
            Some(Token::Word(w)) => w.literal(),
            _ => None,
        })
        .collect();
    let renames = renamed_types(&names, version);
    let mut position = header;
    while position + 1 < tokens.len() && tokens[position] != Token::Symbol('{') {
        if tokens[position] == Token::Symbol(':') {
            rename_token(&mut tokens[position + 1], &renames);
        }
        position += 1;
    }
    for start in starts.into_iter().rev() {
        rename_token(
            tokens
                .get_mut(start + 1)
                .context("missing previous type name")?,
            &renames,
        );
        rename_token(
            tokens
                .get_mut(start + 3)
                .context("missing previous type definition")?,
            &renames,
        );
        let kind = match tokens.get(start + 3) {
            Some(Token::Word(w)) => w.literal().unwrap_or_default().to_owned(),
            _ => String::new(),
        };
        if version < 3 && matches!(kind.as_str(), "uint" | "int") {
            let literal = |index| match tokens.get(index) {
                Some(Token::Word(w)) => w.literal().context("expected previous integer bound"),
                _ => anyhow::bail!("expected previous integer bound"),
            };
            ensure!(
                tokens.get(start + 4) == Some(&Token::Symbol('('))
                    && tokens.get(start + 6) == Some(&Token::Symbol(','))
                    && tokens.get(start + 8) == Some(&Token::Symbol(')')),
                "invalid previous integer bounds"
            );
            let min = literal(start + 5)?;
            let max = upper(&kind, min, literal(start + 7)?)?;
            let expression = format!("minimum_inclusive={min}, maximum_exclusive={max}");
            tokens.splice(
                start + 3..start + 9,
                [
                    Token::Word(Word(vec![Part::Literal("integer".into())])),
                    Token::IntegerBounds(expression),
                ],
            );
        }
    }
    let mut rule = previous_parser::parse(&tokens)?;
    for ty in &mut rule.types {
        if let super::TypeKind::Text { max, .. } = &mut ty.definition {
            ensure!(*max <= 4096, "invalid previous text maximum");
            *max += 1;
        }
    }
    for requirement in &mut rule.requirements {
        if requirement.kind == "is-dir" {
            requirement.kind = "is-directory".into();
        }
    }
    validate_rule(rule)
}

fn renamed_types(names: &[&str], version: u32) -> BTreeMap<String, String> {
    let mut renames = BTreeMap::new();
    for old in ["integer", "enumeration", "repository-name"] {
        if (old == "integer" && version >= 3) || !names.contains(&old) {
            continue;
        }
        for suffix in 1.. {
            let name = format!("{old}-local-{suffix}");
            if !names.contains(&name.as_str()) && !renames.values().any(|v| v == &name) {
                renames.insert(old.into(), name);
                break;
            }
        }
    }
    renames.insert("repo-name".into(), "repository-name".into());
    renames
}

fn rename_token(token: &mut Token, renames: &BTreeMap<String, String>) {
    if let Token::Word(word) = token
        && let Some(name) = word.literal().and_then(|name| renames.get(name))
    {
        *word = Word(vec![Part::Literal(name.clone())]);
    }
}

fn definitions(tokens: &[Token]) -> (Vec<usize>, usize) {
    let mut starts = Vec::new();
    let mut position = 0;
    while tokens.get(position) == Some(&Token::Newline) {
        position += 1;
    }
    while matches!(tokens.get(position), Some(Token::Word(w)) if w.literal() == Some("type")) {
        starts.push(position);
        let mut depth = 0;
        loop {
            match tokens.get(position) {
                Some(Token::Symbol('(' | '{')) => depth += 1,
                Some(Token::Symbol(')' | '}')) => depth -= 1,
                Some(Token::Newline) if depth == 0 => {
                    position += 1;
                    break;
                }
                None => break,
                _ => {}
            }
            position += 1;
        }
        while tokens.get(position) == Some(&Token::Newline) {
            position += 1;
        }
    }
    (starts, position)
}

pub fn compiled(mut rule: Value) -> Result<Rule> {
    let version = rule
        .get("language_version")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    ensure!(
        matches!(version, 1..=3),
        "unsupported previous rule language"
    );
    let names: Vec<_> = rule["types"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|ty| ty["name"].as_str())
        .collect();
    let renames = renamed_types(&names, version as u32);
    for parameter in rule["parameters"]
        .as_array_mut()
        .context("invalid previous parameters")?
    {
        if let Some(name) = parameter["kind"]
            .as_str()
            .and_then(|name| renames.get(name))
        {
            parameter["kind"] = name.clone().into();
        }
    }
    if let Some(types) = rule.get_mut("types") {
        for ty in types.as_array_mut().context("invalid previous types")? {
            if let Some(name) = ty["name"].as_str().and_then(|name| renames.get(name)) {
                ty["name"] = name.clone().into();
            }
            let definition = &mut ty["definition"];
            match definition["kind"].as_str() {
                Some("alias") => {
                    if let Some(name) = definition["target"]
                        .as_str()
                        .and_then(|name| renames.get(name))
                    {
                        definition["target"] = name.clone().into();
                    }
                }
                Some(kind @ ("uint" | "int")) if version < 3 => {
                    let min = definition["min"]
                        .as_str()
                        .context("invalid previous minimum")?;
                    let max = upper(
                        kind,
                        min,
                        definition["max"]
                            .as_str()
                            .context("invalid previous maximum")?,
                    )?;
                    *definition = serde_json::json!({"kind":"integer", "minimum_inclusive":min, "maximum_exclusive":max.to_string()});
                }
                Some("integer") if version == 3 => {
                    let object = definition.as_object_mut().unwrap();
                    for (old, new) in [
                        ("min_inclusive", "minimum_inclusive"),
                        ("max_exclusive", "maximum_exclusive"),
                    ] {
                        if let Some(value) = object.remove(old) {
                            object.insert(new.into(), value);
                        }
                    }
                }
                Some("enum") => {
                    definition["kind"] = "enumeration".into();
                }
                Some("text") => {
                    let min = definition["min"]
                        .as_u64()
                        .context("invalid previous text minimum")?;
                    let max = definition["max"]
                        .as_u64()
                        .context("invalid previous text maximum")?;
                    ensure!(min <= max && max <= 4096, "invalid previous text range");
                    *definition = serde_json::json!({"kind":"text", "pattern":definition["pattern"], "minimum_bytes_inclusive":min, "maximum_bytes_exclusive":max + 1});
                }
                _ => {}
            }
        }
    }
    for requirement in rule["requirements"]
        .as_array_mut()
        .context("invalid previous requirements")?
    {
        if requirement["kind"] == "is-dir" {
            requirement["kind"] = "is-directory".into();
        }
    }
    rule["language_version"] = LANGUAGE_VERSION.into();
    validate_rule(serde_json::from_value(rule)?)
}
