//! Bounded declarative rules. Shell-like words expand once into individual argv entries.
use crate::{Command, config::validate_cwd};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

pub const MAX_SOURCE_BYTES: usize = 16 * 1024;

mod types;
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
    #[serde(
        default = "legacy_language",
        skip_serializing_if = "is_legacy_language"
    )]
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

fn legacy_language() -> u32 {
    1
}
fn is_legacy_language(version: &u32) -> bool {
    *version == 1
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
                    "create-new-dir needs a child path"
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
                    "create-new-dir needs a child path"
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

fn lex(source: &str, stored: bool) -> Result<Vec<Token>> {
    ensure!(source.len() <= MAX_SOURCE_BYTES, "rule exceeds 16 KiB");
    ensure!(
        source
            .bytes()
            .all(|b| b.is_ascii_graphic() || b" \n\r\t".contains(&b)),
        "rules must use printable ASCII text"
    );
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
            }
            '#' => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                }
            }
            '(' | ')' | '{' | '}' | ':' | ',' => {
                chars.next();
                tokens.push(Token::Symbol(c));
            }
            _ => {
                let mut parts = Vec::new();
                let mut text = String::new();
                let mut quote = None;
                let mut leading_home_variable = false;
                while let Some(&c) = chars.peek() {
                    if quote.is_none() && (c.is_ascii_whitespace() || "(){}:,".contains(c)) {
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
                tokens.push(Token::Word(Word(parts)));
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: std::collections::VecDeque<Token>,
}
impl Parser {
    fn executable(&mut self) -> Result<String> {
        let word = self.word()?;
        if let Some(text) = word.literal() {
            return Ok(text.into());
        }
        if word.0.first() == Some(&Part::Variable("HOME".into())) {
            let mut text = String::from("~");
            for part in word.0.iter().skip(1) {
                let Part::Literal(value) = part else {
                    bail!("executable cannot use a parameter")
                };
                text.push_str(value);
            }
            ensure!(
                text == "~" || text.starts_with("~/"),
                "invalid home-relative executable"
            );
            return Ok(text);
        }
        bail!("executable must be literal; parameters cannot select a program")
    }

    fn type_definition(&mut self) -> Result<TypeDefinition> {
        self.keyword("type")?;
        let name = self.literal()?;
        self.keyword("=")?;
        let kind = self.literal()?;
        let definition = match kind.as_str() {
            "enum" => {
                self.symbol('{')?;
                self.lines();
                let mut values = Vec::new();
                loop {
                    values.push(self.literal()?);
                    ensure!(values.len() <= types::MAX_CHOICES, "too many enum values");
                    self.lines();
                    if self.tokens.front() != Some(&Token::Symbol(',')) {
                        break;
                    }
                    self.symbol(',')?;
                    self.lines();
                    if self.tokens.front() == Some(&Token::Symbol('}')) {
                        break;
                    }
                }
                self.symbol('}')?;
                TypeKind::Enum { values }
            }
            "uint" | "int" => {
                self.symbol('(')?;
                let min = self.literal()?;
                self.symbol(',')?;
                let max = self.literal()?;
                self.symbol(')')?;
                if kind == "uint" {
                    TypeKind::Uint {
                        min: min.parse().context("invalid uint minimum")?,
                        max: max.parse().context("invalid uint maximum")?,
                    }
                } else {
                    TypeKind::Int {
                        min: min.parse().context("invalid int minimum")?,
                        max: max.parse().context("invalid int maximum")?,
                    }
                }
            }
            "text" => {
                self.symbol('(')?;
                let pattern = self.literal()?;
                self.symbol(',')?;
                let min = self
                    .literal()?
                    .parse()
                    .context("invalid text minimum length")?;
                self.symbol(',')?;
                let max = self
                    .literal()?
                    .parse()
                    .context("invalid text maximum length")?;
                self.symbol(')')?;
                TypeKind::Text { pattern, min, max }
            }
            "choice" => {
                self.symbol('(')?;
                let mut fields = Vec::new();
                loop {
                    fields.push(self.literal()?);
                    ensure!(fields.len() <= types::MAX_FIELDS, "too many choice fields");
                    if self.tokens.front() != Some(&Token::Symbol(',')) {
                        break;
                    }
                    self.symbol(',')?;
                }
                self.symbol(')')?;
                self.symbol('{')?;
                self.lines();
                let mut cases = BTreeMap::new();
                while self.tokens.front() != Some(&Token::Symbol('}')) {
                    let label = self.literal()?;
                    self.keyword("=")?;
                    self.symbol('(')?;
                    let mut values = Vec::new();
                    loop {
                        values.push(self.literal()?);
                        ensure!(values.len() <= types::MAX_FIELDS, "too many choice values");
                        if self.tokens.front() != Some(&Token::Symbol(',')) {
                            break;
                        }
                        self.symbol(',')?;
                    }
                    self.symbol(')')?;
                    ensure!(
                        cases.insert(label, values).is_none(),
                        "duplicate choice case"
                    );
                    ensure!(cases.len() <= types::MAX_CHOICES, "too many choice cases");
                    self.end_line()?;
                }
                self.symbol('}')?;
                TypeKind::Choice { fields, cases }
            }
            _ => TypeKind::Alias { target: kind },
        };
        Ok(TypeDefinition { name, definition })
    }

    fn lines(&mut self) {
        while self.tokens.front() == Some(&Token::Newline) {
            self.tokens.pop_front();
        }
    }
    fn symbol(&mut self, symbol: char) -> Result<()> {
        ensure!(
            self.tokens.pop_front() == Some(Token::Symbol(symbol)),
            "expected '{symbol}'"
        );
        Ok(())
    }
    fn word(&mut self) -> Result<Word> {
        match self.tokens.pop_front() {
            Some(Token::Word(w)) => Ok(w),
            _ => bail!("expected a word"),
        }
    }
    fn literal(&mut self) -> Result<String> {
        Ok(self
            .word()?
            .literal()
            .context("expected a literal word")?
            .into())
    }
    fn keyword(&mut self, expected: &str) -> Result<()> {
        ensure!(self.literal()? == expected, "expected '{expected}'");
        Ok(())
    }
    fn end_line(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.tokens.front(),
                Some(Token::Newline | Token::Symbol('}'))
            ),
            "expected end of statement"
        );
        self.lines();
        Ok(())
    }
}

pub fn parse(source: &str) -> Result<Rule> {
    parse_source(source, false)
}

// Existing approvals retain their exact source and digest when syntax changes.
pub fn parse_stored(source: &str) -> Result<Rule> {
    parse_source(source, true)
}

fn parse_source(source: &str, stored: bool) -> Result<Rule> {
    let mut p = Parser {
        tokens: lex(source, stored)?.into(),
    };
    p.lines();
    let mut types = Vec::new();
    while p
        .tokens
        .front()
        .is_some_and(|t| matches!(t, Token::Word(w) if w.literal() == Some("type")))
    {
        types.push(p.type_definition()?);
        ensure!(types.len() <= types::MAX_TYPES, "too many local types");
        p.end_line()?;
    }
    p.keyword("rule")?;
    let name = p.literal()?;
    ensure!(crate::config::valid_name(&name), "invalid rule name");
    p.symbol('(')?;
    let mut parameters = Vec::<Parameter>::new();
    if p.tokens.front() != Some(&Token::Symbol(')')) {
        loop {
            let name = p.literal()?;
            ensure!(
                identifier(&name) && name != "HOME" && !parameters.iter().any(|v| v.name == name),
                "invalid, reserved or duplicate parameter"
            );
            p.symbol(':')?;
            let kind = p.literal()?;
            parameters.push(Parameter { name, kind });
            ensure!(parameters.len() <= 16, "too many parameters");
            if p.tokens.front() != Some(&Token::Symbol(',')) {
                break;
            }
            p.symbol(',')?;
        }
    }
    p.symbol(')')?;
    p.symbol('{')?;
    p.lines();
    let mut requirements = Vec::new();
    while p
        .tokens
        .front()
        .is_some_and(|t| matches!(t, Token::Word(w) if w.literal() == Some("require")))
    {
        p.keyword("require")?;
        let kind = p.literal()?;
        ensure!(
            matches!(
                kind.as_str(),
                "is-dir" | "absent" | "user-service-active-or-enabled"
            ),
            "unknown check '{kind}'"
        );
        requirements.push(Requirement {
            kind,
            path: p.word()?,
        });
        ensure!(requirements.len() <= 16, "too many checks");
        p.end_line()?;
    }
    let create_new = if p
        .tokens
        .front()
        .is_some_and(|t| matches!(t, Token::Word(w) if matches!(w.literal(), Some("create-new-dir" | "create-new"))))
    {
        p.literal()?;
        let path = p.word()?;
        p.keyword("as")?;
        let variable = p.literal()?;
        ensure!(
            identifier(&variable)
                && variable != "HOME"
                && !parameters.iter().any(|v| v.name == variable),
            "invalid or shadowed output variable"
        );
        p.symbol('{')?;
        p.lines();
        Some(CreateNew { path, variable })
    } else {
        None
    };
    p.keyword("run")?;
    let program = p.executable()?;
    let sudo_password = program == "--sudo";
    let program = if sudo_password {
        p.executable()?
    } else {
        program
    };
    ensure!(
        !program.is_empty() && !program.starts_with('-'),
        "invalid executable"
    );
    let mut args = Vec::new();
    while matches!(p.tokens.front(), Some(Token::Word(_))) {
        args.push(p.word()?);
        ensure!(args.len() <= 256, "too many arguments");
    }
    p.end_line()?;
    p.symbol('}')?;
    p.lines();
    if create_new.is_some() {
        p.symbol('}')?;
        p.lines();
    }
    ensure!(p.tokens.is_empty(), "unexpected content after rule");
    let rule = Rule {
        name,
        language_version: if stored { 1 } else { 2 },
        types,
        parameters,
        requirements,
        create_new,
        program,
        args,
        sudo_password,
    };
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
