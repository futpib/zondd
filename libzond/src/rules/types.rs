use super::{Rule, identifier, valid_repo_name};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_TYPES: usize = 32;
pub const MAX_CHOICES: usize = 64;
pub const MAX_FIELDS: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TypeDefinition {
    pub name: String,
    pub definition: TypeKind,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeKind {
    Alias {
        target: String,
    },
    Enum {
        values: Vec<String>,
    },
    Uint {
        #[serde(with = "decimal")]
        min: u64,
        #[serde(with = "decimal")]
        max: u64,
    },
    Int {
        #[serde(with = "decimal")]
        min: i64,
        #[serde(with = "decimal")]
        max: i64,
    },
    Text {
        pattern: String,
        min: usize,
        max: usize,
    },
    Choice {
        fields: Vec<String>,
        cases: BTreeMap<String, Vec<String>>,
    },
}

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    // Decimal strings preserve exact 64-bit bounds in Android JSON and audit exports.
    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, T: FromStr + Display, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        T::Err: Display,
    {
        let text = String::deserialize(deserializer)?;
        let value = text.parse::<T>().map_err(D::Error::custom)?;
        if value.to_string() != text {
            return Err(D::Error::custom("noncanonical decimal bound"));
        }
        Ok(value)
    }
}

fn literal(value: &str) -> bool {
    value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

fn regex(pattern: &str) -> Result<regex::Regex> {
    ensure!(
        literal(pattern) && pattern.len() <= 1024,
        "type pattern must be bounded printable ASCII"
    );
    regex::RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
        .size_limit(256 * 1024)
        .dfa_size_limit(256 * 1024)
        .nest_limit(32)
        .build()
        .context("invalid or oversized type pattern")
}

fn quoted(value: &str) -> String {
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

impl TypeDefinition {
    pub fn source(&self) -> String {
        let value = match &self.definition {
            TypeKind::Alias { target } => target.clone(),
            TypeKind::Enum { values } => format!(
                "enum {{ {} }}",
                values
                    .iter()
                    .map(|v| quoted(v))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            TypeKind::Uint { min, max } => format!("uint({min}, {max})"),
            TypeKind::Int { min, max } => format!("int({min}, {max})"),
            TypeKind::Text { pattern, min, max } => {
                format!("text({}, {min}, {max})", quoted(pattern))
            }
            TypeKind::Choice { fields, cases } => format!(
                "choice({}) {{\n{}\n}}",
                fields.join(", "),
                cases
                    .iter()
                    .map(|(name, values)| format!(
                        "  {name} = ({})",
                        values
                            .iter()
                            .map(|v| quoted(v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        };
        format!("type {} = {value}", self.name)
    }
}

impl Rule {
    pub fn type_kind(&self, name: &str) -> Result<Option<&TypeKind>> {
        let mut name = name;
        for _ in 0..=MAX_TYPES {
            if name == "repo-name" {
                return Ok(None);
            }
            let definition = &self
                .types
                .iter()
                .find(|t| t.name == name)
                .with_context(|| {
                    format!(
                        "unknown type '{name}'; supported type: repo-name or a local definition"
                    )
                })?
                .definition;
            match definition {
                TypeKind::Alias { target } => name = target,
                _ => return Ok(Some(definition)),
            }
        }
        bail!("cyclic local type alias")
    }

    pub(super) fn validate_types(&self) -> Result<()> {
        ensure!(self.types.len() <= MAX_TYPES, "too many local types");
        let mut names = BTreeSet::new();
        for ty in &self.types {
            ensure!(
                crate::config::valid_name(&ty.name)
                    && !matches!(
                        ty.name.as_str(),
                        "repo-name" | "enum" | "uint" | "int" | "text" | "choice"
                    )
                    && names.insert(&ty.name),
                "invalid, reserved or duplicate local type"
            );
            self.type_kind(&ty.name)?;
            match &ty.definition {
                TypeKind::Alias { .. } => {}
                TypeKind::Enum { values } => {
                    ensure!(
                        !values.is_empty()
                            && values.len() <= MAX_CHOICES
                            && values.iter().all(|v| literal(v))
                            && values.iter().collect::<BTreeSet<_>>().len() == values.len(),
                        "enum needs 1–64 distinct bounded ASCII literals"
                    );
                }
                TypeKind::Uint { min, max } => {
                    ensure!(min <= max, "invalid unsigned integer range")
                }
                TypeKind::Int { min, max } => ensure!(min <= max, "invalid integer range"),
                TypeKind::Text { pattern, min, max } => {
                    ensure!(
                        min <= max && *max <= 4096,
                        "text length range must be within 0–4096 bytes"
                    );
                    regex(pattern)?;
                }
                TypeKind::Choice { fields, cases } => {
                    ensure!(
                        !fields.is_empty()
                            && fields.len() <= MAX_FIELDS
                            && fields.iter().all(|f| identifier(f))
                            && fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
                        "choice needs 1–16 distinct field names"
                    );
                    ensure!(
                        !cases.is_empty()
                            && cases.len() <= MAX_CHOICES
                            && cases
                                .iter()
                                .all(|(name, row)| crate::config::valid_name(name)
                                    && row.len() == fields.len()
                                    && row.iter().all(|v| literal(v))),
                        "choice needs 1–64 named rows matching its fields"
                    );
                }
            }
        }
        for parameter in &self.parameters {
            self.type_kind(&parameter.kind)?;
        }
        Ok(())
    }

    pub(super) fn validate_argument<'a>(
        &'a self,
        kind: &str,
        value: &str,
    ) -> Result<Vec<(&'a str, &'a str)>> {
        let valid = match self.type_kind(kind)? {
            None => valid_repo_name(value),
            Some(TypeKind::Enum { values }) => values.iter().any(|v| v == value),
            Some(TypeKind::Uint { min, max }) => value
                .parse::<u64>()
                .is_ok_and(|n| n >= *min && n <= *max && n.to_string() == value),
            Some(TypeKind::Int { min, max }) => value
                .parse::<i64>()
                .is_ok_and(|n| n >= *min && n <= *max && n.to_string() == value),
            Some(TypeKind::Text { pattern, min, max }) => {
                literal(value)
                    && (*min..=*max).contains(&value.len())
                    && regex(pattern)?.is_match(value)
            }
            Some(TypeKind::Choice { fields, cases }) => {
                let row = cases.get(value).context("unknown correlated choice")?;
                return Ok(fields
                    .iter()
                    .zip(row)
                    .map(|(f, v)| (f.as_str(), v.as_str()))
                    .collect());
            }
            Some(TypeKind::Alias { .. }) => unreachable!(),
        };
        ensure!(valid, "value does not satisfy type '{kind}'");
        Ok(Vec::new())
    }

    pub(super) fn known_binding(&self, name: &str) -> bool {
        if name == "HOME" || self.parameters.iter().any(|p| p.name == name) {
            return true;
        }
        let Some((parameter, field)) = name.split_once('.') else {
            return false;
        };
        self.parameters.iter().find(|p| p.name == parameter)
            .and_then(|p| self.type_kind(&p.kind).ok().flatten())
            .is_some_and(|ty| matches!(ty, TypeKind::Choice { fields, .. } if fields.iter().any(|f| f == field)))
    }

    pub fn type_description(&self, kind: &str) -> Result<String> {
        Ok(match self.type_kind(kind)? {
            None => "1–100 ASCII letters, digits, dots, underscores or hyphens; starts with a letter or digit. Full match: [A-Za-z0-9][A-Za-z0-9._-]{0,99}. Validated on every invocation; does not check repository existence.".into(),
            Some(TypeKind::Enum { values }) => format!("Exactly one of {}. Case-sensitive literal values; validated on every invocation.", serde_json::to_string(values)?),
            Some(TypeKind::Uint { min, max }) => format!("Unsigned decimal integer from {min} through {max}, inclusive. Canonical digits only: no sign, leading zeros (except 0), whitespace or overflow."),
            Some(TypeKind::Int { min, max }) => format!("Signed decimal integer from {min} through {max}, inclusive. Canonical digits with optional minus: no plus, leading zeros, negative zero, whitespace or overflow."),
            Some(TypeKind::Text { pattern, min, max }) => format!("Printable ASCII text, {min}–{max} bytes, matching the entire regular expression {}. Validated on every invocation; values are never expanded again.", serde_json::to_string(pattern)?),
            Some(TypeKind::Choice { fields, cases }) => {
                let rows = cases.iter().map(|(name, row)| {
                    format!("{} -> {}", serde_json::to_string(name).unwrap(), fields.iter().zip(row)
                        .map(|(f, v)| format!("{f}={}", serde_json::to_string(v).unwrap()))
                        .collect::<Vec<_>>().join(", "))
                }).collect::<Vec<_>>().join("\n");
                format!("Choose one named row; its fields are supplied together. No other combinations are permitted. Validated on every invocation.\n{rows}")
            }
            Some(TypeKind::Alias { .. }) => unreachable!(),
        })
    }
}
