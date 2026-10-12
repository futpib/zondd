use crate::{Command, OperationInfo};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

pub fn revision(content: &str) -> String {
    Sha256::digest(content.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "crate::paths::runtime_dir")]
    pub runtime_dir: PathBuf,
    #[serde(default)]
    pub approvals: Approvals,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default = "default_principals")]
    pub principals: BTreeMap<String, Principal>,
    #[serde(default)]
    pub operations: BTreeMap<String, Operation>,
    #[serde(default)]
    pub credential_recipients: BTreeMap<String, crate::credential::RecipientConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Approvals {
    pub enabled: bool,
    pub timeout_secs: u64,
    pub max_pending: usize,
}
impl Default for Approvals {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 300,
            max_pending: 64,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub command_timeout_secs: u64,
    pub max_output_bytes: usize,
    pub max_running: usize,
    pub max_connections: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            command_timeout_secs: 60,
            max_output_bytes: 1024 * 1024,
            max_running: 8,
            max_connections: 128,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    #[default]
    Deny,
    Ask,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub cwd: PathBuf,
    #[serde(default)]
    pub allow_exec: bool,
    #[serde(default)]
    pub default: Decision,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub program: String,
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    pub decision: Decision,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    #[serde(default)]
    pub description: String,
    pub program: String,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    #[serde(default)]
    pub arguments: Vec<Argument>,
    #[serde(default)]
    pub decision: Decision,
    #[serde(default)]
    pub sudo_password: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Argument {
    pub name: String,
    pub choices: Vec<String>,
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn validate_command(command: &Command) -> Result<()> {
    ensure!(
        Path::new(&command.program).is_absolute(),
        "program must be an absolute path"
    );
    ensure!(!command.program.contains('\0'), "NUL in program");
    ensure!(command.args.len() <= 256, "too many arguments");
    ensure!(
        command.args.iter().all(|s| !s.contains('\0')),
        "NUL in arguments"
    );
    Ok(())
}

pub fn validate_cwd(cwd: &Path) -> Result<()> {
    ensure!(cwd.is_absolute(), "cwd must be absolute");
    let bytes = cwd.as_os_str().as_encoded_bytes();
    ensure!(
        !bytes
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b".."),
        "cwd must not contain . or .."
    );
    ensure!(!bytes.contains(&0), "NUL in cwd");
    Ok(())
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.credential_recipients.len() <= 16,
            "at most 16 credential recipients"
        );
        let mut identities = std::collections::BTreeSet::new();
        for (name, recipient) in &self.credential_recipients {
            ensure!(valid_name(name), "invalid credential recipient name");
            recipient.validate()?;
            ensure!(
                identities.insert(&recipient.key_sha256),
                "credential recipients need distinct identities"
            );
        }
        ensure!(
            self.runtime_dir.is_absolute(),
            "runtime_dir must be absolute"
        );
        ensure!(
            (1..=1024).contains(&self.approvals.max_pending),
            "max_pending must be 1..1024"
        );
        ensure!(
            (1..=86400).contains(&self.approvals.timeout_secs),
            "approval timeout must be 1..86400"
        );
        ensure!(
            (1..=86400).contains(&self.limits.command_timeout_secs),
            "command timeout must be 1..86400"
        );
        ensure!(
            (1..=1024 * 1024).contains(&self.limits.max_output_bytes),
            "max_output_bytes must be 1..1048576"
        );
        ensure!(
            (1..=128).contains(&self.limits.max_running),
            "max_running must be 1..128"
        );
        ensure!(
            (1..=1024).contains(&self.limits.max_connections),
            "max_connections must be 1..1024"
        );
        for (name, p) in &self.principals {
            ensure!(valid_name(name), "invalid principal name {name}");
            ensure!(
                !matches!(name.as_str(), "admin" | "askpass" | "credential"),
                "reserved principal name {name}"
            );
            ensure!(p.cwd.is_absolute(), "cwd must be absolute");
            for op in &p.operations {
                ensure!(self.operations.contains_key(op), "unknown operation {op}");
            }
            for rule in &p.rules {
                if let Some(cwd) = &rule.cwd {
                    validate_cwd(cwd)?;
                }
                validate_command(&Command {
                    program: rule.program.clone(),
                    args: rule.args.clone().unwrap_or_default(),
                })?;
            }
        }
        for (name, op) in &self.operations {
            ensure!(valid_name(name), "invalid operation name {name}");
            if op.sudo_password {
                ensure!(
                    op.decision == Decision::Ask,
                    "sudo_password requires decision = ask for {name}"
                );
                ensure!(
                    self.approvals.enabled,
                    "sudo_password requires approvals for {name}"
                );
            }
            validate_command(&Command {
                program: op.program.clone(),
                args: op.fixed_args.clone(),
            })?;
            for arg in &op.arguments {
                ensure!(
                    valid_name(&arg.name) && !arg.choices.is_empty(),
                    "invalid argument schema"
                );
                ensure!(
                    arg.choices.iter().all(|s| !s.contains('\0')),
                    "NUL in argument schema"
                );
            }
        }
        Ok(())
    }

    pub fn operation(
        &self,
        p: &Principal,
        name: &str,
        args: &[String],
    ) -> Result<(Command, Decision)> {
        ensure!(
            p.operations.iter().any(|op| op == name),
            "operation not authorized"
        );
        let op = self
            .operations
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown operation"))?;
        ensure!(args.len() == op.arguments.len(), "wrong argument count");
        for (value, schema) in args.iter().zip(&op.arguments) {
            if !schema.choices.contains(value) {
                bail!("invalid value for {}", schema.name);
            }
        }
        let mut command = Command {
            program: op.program.clone(),
            args: op.fixed_args.clone(),
        };
        command.args.extend_from_slice(args);
        validate_command(&command)?;
        Ok((command, op.decision))
    }

    pub fn operations_for(&self, p: &Principal) -> Vec<OperationInfo> {
        p.operations
            .iter()
            .filter_map(|name| {
                self.operations.get(name).map(|op| OperationInfo {
                    name: name.clone(),
                    description: op.description.clone(),
                    arguments: op.arguments.clone(),
                })
            })
            .collect()
    }
}

impl Principal {
    pub fn decision(&self, command: &Command) -> Decision {
        self.decision_in(command, &self.cwd)
    }

    pub fn decision_in(&self, command: &Command, cwd: &Path) -> Decision {
        self.rules
            .iter()
            .find(|r| {
                r.program == command.program
                    && r.args.as_ref().is_none_or(|args| args == &command.args)
                    && r.cwd.as_deref().unwrap_or(&self.cwd) == cwd
            })
            .map_or_else(
                || {
                    if cwd == self.cwd {
                        self.default
                    } else {
                        Decision::Deny
                    }
                },
                |r| r.decision,
            )
    }
}

fn default_principals() -> BTreeMap<String, Principal> {
    BTreeMap::from([(
        "default".into(),
        Principal {
            cwd: crate::paths::home_dir(),
            allow_exec: true,
            default: Decision::Ask,
            operations: Vec::new(),
            rules: Vec::new(),
        },
    )])
}

/// An editable representation of the policy used when no policy file exists.
pub fn default_policy() -> String {
    format!(
        "# Built-in policy: every command requires approval.\n[approvals]\nenabled = true\ntimeout_secs = 300\n\n[principals.default]\ncwd = {}\nallow_exec = true\ndefault = \"ask\"\n",
        serde_json::to_string(&crate::paths::home_dir()).expect("home path")
    )
}

/// Absence uses built-in defaults; unreadable or malformed files never do.
pub fn read(path: &Path) -> Result<String> {
    crate::paths::trusted_location(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => ensure!(meta.is_file(), "config must be a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(512 * 1024 + 1)
        .read_to_string(&mut text)?;
    ensure!(text.len() <= 512 * 1024, "config exceeds 512 KiB");
    Ok(text)
}
