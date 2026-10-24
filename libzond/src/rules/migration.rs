//! One-time conversion of persisted v1/v2 rules; never used for new proposals.
use super::{LANGUAGE_VERSION, Part, Rule, Token, Word, lex, parse_tokens};
use anyhow::{Context, Result, ensure};
use num_bigint::BigInt;
use serde_json::Value;

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
        matches!(version, 1 | 2),
        "unsupported previous rule language"
    );
    let mut tokens = lex(source, version == 1)?;
    let (starts, header) = definitions(&tokens);
    let names: Vec<_> = starts
        .iter()
        .filter_map(|start| match tokens.get(start + 1) {
            Some(Token::Word(w)) => w.literal(),
            _ => None,
        })
        .collect();
    let rename = renamed_integer(&names);
    if let Some(name) = &rename {
        let mut position = header;
        while position + 1 < tokens.len() && tokens[position] != Token::Symbol('{') {
            if tokens[position] == Token::Symbol(':') {
                rename_token(&mut tokens[position + 1], name);
            }
            position += 1;
        }
    }
    for start in starts.into_iter().rev() {
        if let Some(name) = &rename {
            rename_token(
                tokens
                    .get_mut(start + 1)
                    .context("missing previous type name")?,
                name,
            );
            rename_token(
                tokens
                    .get_mut(start + 3)
                    .context("missing previous type definition")?,
                name,
            );
        }
        let kind = match tokens.get(start + 3) {
            Some(Token::Word(w)) => w.literal().unwrap_or_default().to_owned(),
            _ => String::new(),
        };
        if matches!(kind.as_str(), "uint" | "int") {
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
            let expression = format!("min_inclusive={min}, max_exclusive={max}");
            tokens.splice(
                start + 3..start + 9,
                [
                    Token::Word(Word(vec![Part::Literal("integer".into())])),
                    Token::IntegerBounds(expression),
                ],
            );
        }
    }
    parse_tokens(tokens)
}

fn renamed_integer(names: &[&str]) -> Option<String> {
    if !names.contains(&"integer") {
        return None;
    }
    for suffix in 1.. {
        let name = format!("integer-local-{suffix}");
        if !names.contains(&name.as_str()) {
            return Some(name);
        }
    }
    unreachable!()
}

fn rename_token(token: &mut Token, name: &str) {
    if matches!(token, Token::Word(w) if w.literal() == Some("integer")) {
        *token = Token::Word(Word(vec![Part::Literal(name.into())]));
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
        matches!(version, 1 | 2),
        "unsupported previous rule language"
    );
    let names: Vec<_> = rule["types"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|ty| ty["name"].as_str())
        .collect();
    let rename = renamed_integer(&names);
    if let Some(name) = &rename {
        for parameter in rule["parameters"]
            .as_array_mut()
            .context("invalid previous parameters")?
        {
            if parameter["kind"] == "integer" {
                parameter["kind"] = name.clone().into();
            }
        }
    }
    if let Some(types) = rule.get_mut("types") {
        for ty in types.as_array_mut().context("invalid previous types")? {
            if let Some(name) = &rename {
                if ty["name"] == "integer" {
                    ty["name"] = name.clone().into();
                }
                if ty["definition"]["kind"] == "alias" && ty["definition"]["target"] == "integer" {
                    ty["definition"]["target"] = name.clone().into();
                }
            }
            let definition = &mut ty["definition"];
            if matches!(definition["kind"].as_str(), Some("uint" | "int")) {
                let kind = definition["kind"].as_str().unwrap();
                let min = definition["min"]
                    .as_str()
                    .context("invalid previous minimum")?;
                let max = definition["max"]
                    .as_str()
                    .context("invalid previous maximum")?;
                let upper = upper(kind, min, max)?;
                definition.clone_from(&serde_json::json!({"kind":"integer", "min_inclusive":min, "max_exclusive":upper.to_string()}));
            }
        }
    }
    rule["language_version"] = LANGUAGE_VERSION.into();
    Ok(serde_json::from_value(rule)?)
}
