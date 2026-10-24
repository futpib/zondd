//! Bounded declarative rules. Shell-like words expand once into individual argv entries.
use crate::{Command, config::validate_cwd};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

pub const MAX_SOURCE_BYTES: usize = 16 * 1024;

mod integer;
pub mod migration;
mod parser;
mod types;
pub const LANGUAGE_VERSION: u32 = 3;
pub use types::{TypeDefinition, TypeKind};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub kind: String,
}

pub fn valid_repo_name(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn valid_service_unit(value: &str) -> bool {
    let Some(name) = value.strip_suffix(".service") else {
        return false;
    };
    !name.is_empty()
        && value.len() <= 255
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
        && name.bytes().filter(|b| *b == b'@').count() <= 1
        && !name.ends_with('@')
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Part {
    Literal(String),
    Variable(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Word(pub Vec<Part>);
impl Word {
    fn literal(&self) -> Option<&str> {
        match self.0.as_slice() {
            [Part::Literal(value)] => Some(value),
            _ => None,
        }
    }
    fn variables(&self) -> impl Iterator<Item = &str> {
        self.0.iter().filter_map(|part| match part {
            Part::Variable(name) => Some(name.as_str()),
            _ => None,
        })
    }
    fn expand(&self, bindings: &BTreeMap<String, &str>) -> Result<String> {
        let mut value = String::new();
        for part in &self.0 {
            match part {
                Part::Literal(text) => value.push_str(text),
                Part::Variable(name) => {
                    value.push_str(bindings.get(name.as_str()).context("unbound variable")?)
                }
            }
        }
        ensure!(
            value.len() <= 4096 && !value.contains('\0'),
            "expanded argument too long or contains NUL"
        );
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Requirement {
    pub kind: String,
    // The wire name predates non-filesystem checks; service checks store a unit name here.
    pub path: Word,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateNew {
    pub path: Word,
    pub variable: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub language_version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<TypeDefinition>,
    pub parameters: Vec<Parameter>,
    pub requirements: Vec<Requirement>,
    pub create_new: Option<CreateNew>,
    pub program: String,
    pub args: Vec<Word>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sudo_password: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundRule {
    pub rule: Rule,
    pub home: String,
    pub cwd: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedRequirement {
    pub kind: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invocation {
    pub grant_id: String,
    pub command: Command,
    pub destination: Option<PathBuf>,
    pub requirements: Vec<ResolvedRequirement>,
    pub bound: BoundRule,
    pub args: Vec<String>,
}

impl BoundRule {
    pub fn validate_template(&self) -> Result<()> {
        let mut bindings = BTreeMap::from([("HOME".into(), self.home.as_str())]);
        for word in self
            .rule
            .requirements
            .iter()
            .map(|r| &r.path)
            .chain(self.rule.create_new.iter().map(|n| &n.path))
        {
            for variable in word.variables() {
                bindings.entry(variable.into()).or_insert("example");
            }
        }
        for (word, service, destination) in self
            .rule
            .requirements
            .iter()
            .map(|r| (&r.path, r.kind == "user-service-active-or-enabled", false))
            .chain(self.rule.create_new.iter().map(|n| (&n.path, false, true)))
        {
            // A caller value may supply an absolute path or complete service name.
            // Every instantiated value is checked again before it can be used.
            if matches!(word.0.first(), Some(Part::Variable(name)) if name != "HOME") {
                continue;
            }
            let target = word.expand(&bindings)?;
            if service {
                ensure!(
                    valid_service_unit(&target),
                    "invalid service name in rule template"
                );
            } else {
                let path = PathBuf::from(target);
                validate_cwd(&path)?;
                ensure!(
                    !destination || path.file_name().is_some(),
                    "create-new-directory needs a child path"
                );
            }
        }
        Ok(())
    }

    pub fn instantiate(
        &self,
        grant_id: &str,
        args: &[String],
        staging: Option<&str>,
    ) -> Result<Invocation> {
        ensure!(
            args.len() == self.rule.parameters.len(),
            "wrong argument count"
        );
        let mut bindings = BTreeMap::from([("HOME".into(), self.home.as_str())]);
        for (parameter, value) in self.rule.parameters.iter().zip(args) {
            let fields = self
                .rule
                .validate_argument(&parameter.kind, value)
                .with_context(|| {
                    format!(
                        "invalid parameter '{}': expected {}",
                        parameter.name, parameter.kind
                    )
                })?;
            bindings.insert(parameter.name.clone(), value.as_str());
            for (field, value) in fields {
                bindings.insert(format!("{}.{field}", parameter.name), value);
            }
        }
        let requirements = self
            .rule
            .requirements
            .iter()
            .map(|r| {
                let target = r.path.expand(&bindings)?;
                let path = PathBuf::from(&target);
                if r.kind == "user-service-active-or-enabled" {
                    ensure!(
                        valid_service_unit(&target),
                        "expected a literal .service name (at most 255 ASCII letters, digits, dots, underscores, hyphens and one optional nonempty @instance; starts with a letter or digit)"
                    );
                } else {
                    validate_cwd(&path)?;
                }
                Ok(ResolvedRequirement {
                    kind: r.kind.clone(),
                    path,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let destination = self
            .rule
            .create_new
            .as_ref()
            .map(|new| {
                let path = PathBuf::from(new.path.expand(&bindings)?);
                validate_cwd(&path)?;
                ensure!(
                    path.file_name().is_some(),
                    "create-new-directory needs a child path"
                );
                Ok(path)
            })
            .transpose()?;
        if let Some(new) = &self.rule.create_new {
            bindings.insert(
                new.variable.clone(),
                staging.unwrap_or(
                    destination
                        .as_ref()
                        .unwrap()
                        .to_str()
                        .context("non-UTF8 destination")?,
                ),
            );
        }
        let command = Command {
            program: self.rule.program.clone(),
            args: self
                .rule
                .args
                .iter()
                .map(|w| w.expand(&bindings))
                .collect::<Result<_>>()?,
        };
        crate::config::validate_command(&command)?;
        Ok(Invocation {
            grant_id: grant_id.into(),
            command,
            destination,
            requirements,
            bound: self.clone(),
            args: args.to_vec(),
        })
    }
}

/// Plain-text review data generated by the receiver, independently of rule syntax.
/// Version 1 renders every section and field; new rendering semantics need a new version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub version: u32,
    pub title: String,
    pub sections: Vec<ReviewSection>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewSection {
    pub title: String,
    pub fields: Vec<ReviewField>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewField {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub principal: String,
    pub source: String,
    pub bound: BoundRule,
    // Keep the review opaque in transports so older bridges preserve future formats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<serde_json::Value>,
    pub digest: String,
    pub revision: String,
    pub principal_revision: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleState {
    pub proposal: Proposal,
    pub status: String,
    pub reason: String,
    pub grant_expires_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(Word),
    Symbol(char),
    Newline,
    IntegerBounds(String),
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn flush_literal(parts: &mut Vec<Part>, text: &mut String) {
    if !text.is_empty() {
        parts.push(Part::Literal(std::mem::take(text)));
    }
}

fn lex(source: &str, version: u32) -> Result<Vec<Token>> {
    ensure!(source.len() <= MAX_SOURCE_BYTES, "rule exceeds 16 KiB");
    ensure!(
        source
            .bytes()
            .all(|b| b.is_ascii_graphic() || b" \n\r\t".contains(&b)),
        "rules must use printable ASCII text"
    );
    let stored = version == 1;
    let mut definition = false;
    let mut depth: usize = 0;
    let mut chars = source.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\r' => {
                chars.next();
            }
            '\n' => {
                chars.next();
                tokens.push(Token::Newline);
                if depth == 0 {
                    definition = false;
                }
            }
            '#' => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                }
            }
            '(' if tokens
                .last()
                .is_some_and(|t| matches!(t, Token::Word(w) if w.literal() == Some("integer")))
                && tokens.len() >= 4
                && matches!(&tokens[tokens.len() - 4], Token::Word(w) if w.literal() == Some("type"))
                && (matches!(&tokens[tokens.len() - 2], Token::Word(w) if w.literal() == Some("="))
                    || tokens[tokens.len() - 2] == Token::Symbol('=')) =>
            {
                chars.next();
                let mut expression = String::new();
                let mut depth = 1;
                for c in chars.by_ref() {
                    if c == '(' {
                        depth += 1;
                    }
                    if c == ')' {
                        depth -= 1;
                    }
                    if depth == 0 {
                        break;
                    }
                    expression.push(c);
                }
                ensure!(depth == 0, "unclosed integer bounds");
                tokens.push(Token::IntegerBounds(expression));
            }
            '=' if definition && version >= 3 => {
                chars.next();
                tokens.push(Token::Symbol('='));
            }
            '(' | ')' | '{' | '}' | ':' | ',' => {
                chars.next();
                tokens.push(Token::Symbol(c));
                match c {
                    '(' | '{' => depth += 1,
                    ')' | '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            _ => {
                let mut parts = Vec::new();
                let mut text = String::new();
                let mut quote = None;
                let mut leading_home_variable = false;
                while let Some(&c) = chars.peek() {
                    if quote.is_none()
                        && (c.is_ascii_whitespace()
                            || "(){}:,".contains(c)
                            || (c == '=' && definition && version >= 3))
                    {
                        break;
                    }
                    chars.next();
                    if quote == Some('\'') {
                        if c == '\'' {
                            quote = None;
                        } else {
                            text.push(c);
                        }
                        continue;
                    }
                    if c == '"' {
                        quote = if quote.is_some() { None } else { Some('"') };
                    } else if c == '\'' && quote.is_none() {
                        quote = Some('\'');
                    } else if c == '\\' {
                        let escaped = chars.next().context("unfinished escape")?;
                        ensure!(
                            matches!(escaped, '\\' | '"' | '$' | '\'' | ' ' | '~' | '`'),
                            "unsupported escape"
                        );
                        text.push(escaped);
                    } else if c == '$' {
                        flush_literal(&mut parts, &mut text);
                        let braced = chars.peek() == Some(&'{');
                        if braced {
                            chars.next();
                        }
                        let mut name = String::new();
                        while chars
                            .peek()
                            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                        {
                            name.push(chars.next().unwrap());
                        }
                        ensure!(
                            identifier(&name),
                            "expected a variable name after $; shell expansion is unsupported"
                        );
                        if braced && chars.peek() == Some(&'.') {
                            chars.next();
                            let mut field = String::new();
                            while chars
                                .peek()
                                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                            {
                                field.push(chars.next().unwrap());
                            }
                            ensure!(identifier(&field), "expected a choice field name");
                            name.push('.');
                            name.push_str(&field);
                        }
                        if braced {
                            ensure!(chars.next() == Some('}'), "expected closing variable brace");
                        }
                        leading_home_variable |= name == "HOME" && parts.is_empty();
                        parts.push(Part::Variable(name));
                    } else if !stored && c == '~' && parts.is_empty() && text.is_empty() {
                        ensure!(
                            chars.peek().is_none_or(|c| *c == '/'
                                || *c == '"'
                                || c.is_ascii_whitespace()
                                || "(){}:,".contains(*c)),
                            "only ~ and ~/path are supported; named-user or embedded tilde expansion is unsupported"
                        );
                        parts.push(Part::Variable("HOME".into()));
                    } else {
                        ensure!(
                            c != '`'
                                && (quote.is_some()
                                    || (!";|&<>*?[]".contains(c) && (!stored || c != '~'))),
                            "shell operators, globbing and substitution are unsupported"
                        );
                        ensure!(c != '\n' && c != '\r', "newline inside argument");
                        text.push(c);
                    }
                }
                ensure!(quote.is_none(), "unclosed quote");
                flush_literal(&mut parts, &mut text);
                if parts.is_empty() {
                    parts.push(Part::Literal(String::new()));
                }
                ensure!(
                    stored
                        || !leading_home_variable
                        || !(parts.len() == 1
                            || matches!(parts.get(1), Some(Part::Literal(value)) if value.starts_with('/'))),
                    "use ~ or ~/path instead of $HOME or a braced HOME variable at the start of a word"
                );
                if depth == 0
                    && parts == [Part::Literal("type".into())]
                    && (tokens.is_empty() || tokens.last() == Some(&Token::Newline))
                {
                    definition = true;
                }
                tokens.push(Token::Word(Word(parts)));
            }
        }
    }
    Ok(tokens)
}

pub fn parse(source: &str) -> Result<Rule> {
    parse_tokens(lex(source, LANGUAGE_VERSION)?)
}

fn parse_tokens(tokens: Vec<Token>) -> Result<Rule> {
    validate_rule(parser::parse(&tokens)?)
}

fn validate_rule(rule: Rule) -> Result<Rule> {
    ensure!(crate::config::valid_name(&rule.name), "invalid rule name");
    let mut parameters = std::collections::BTreeSet::new();
    for parameter in &rule.parameters {
        ensure!(
            identifier(&parameter.name)
                && parameter.name != "HOME"
                && parameters.insert(&parameter.name),
            "invalid, reserved or duplicate parameter"
        );
    }
    for requirement in &rule.requirements {
        ensure!(
            matches!(
                requirement.kind.as_str(),
                "is-directory" | "absent" | "user-service-active-or-enabled"
            ),
            "unknown check '{}'",
            requirement.kind
        );
    }
    if let Some(new) = &rule.create_new {
        ensure!(
            identifier(&new.variable)
                && new.variable != "HOME"
                && !parameters.contains(&new.variable),
            "invalid or shadowed output variable"
        );
    }
    ensure!(
        !rule.program.is_empty() && !rule.program.starts_with('-'),
        "invalid executable"
    );
    rule.validate_types()?;
    let known = |name: &str| rule.known_binding(name);
    for word in rule
        .requirements
        .iter()
        .map(|r| &r.path)
        .chain(rule.create_new.iter().map(|n| &n.path))
    {
        ensure!(word.variables().all(&known), "unknown variable in path");
    }
    for word in &rule.args {
        ensure!(
            word.variables()
                .all(|name| known(name)
                    || rule.create_new.as_ref().is_some_and(|n| n.variable == name)),
            "unknown variable in command"
        );
    }
    if let Some(new) = &rule.create_new {
        ensure!(
            rule.args
                .iter()
                .any(|w| w.variables().any(|v| v == new.variable)),
            "command must use output variable ${}",
            new.variable
        );
    }
    Ok(rule)
}
