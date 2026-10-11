//! Application-neutral, transient human input. All answers are treated as secrets.

use crate::{Command, SecretString, config};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub label: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl AdapterConfig {
    pub fn command(&self) -> Command {
        Command {
            program: self.program.clone(),
            args: self.args.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.label.trim().is_empty()
                && self.label.len() <= 200
                && !self.label.chars().any(char::is_control),
            "invalid adapter label"
        );
        config::validate_command(&self.command())?;
        config::validate_cwd(&self.cwd)?;
        ensure!(
            self.env.len() <= 32
                && self
                    .env
                    .iter()
                    .all(|(k, v)| !k.is_empty() && !k.contains(['=', '\0']) && !v.contains('\0')),
            "invalid adapter environment"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Field {
    pub id: String,
    pub label: String,
    /// Unknown kinds are reviewed as YAML and answered as masked text.
    pub kind: String,
    #[serde(default = "required")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(flatten)]
    pub details: BTreeMap<String, serde_json::Value>,
}
fn required() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recipient {
    pub adapter: String,
    pub label: String,
    pub session_id: String,
    pub command: Command,
    pub cwd: PathBuf,
    pub origin: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub recipient: Recipient,
    pub prompt: String,
    pub fields: Vec<Field>,
    pub context: serde_json::Value,
    pub expires_unix_ms: u64,
}

impl Challenge {
    pub fn validate_fields(
        fields: &[Field],
        prompt: &str,
        context: &serde_json::Value,
    ) -> Result<()> {
        ensure!((1..=16).contains(&fields.len()), "expected 1..16 fields");
        ensure!(
            prompt.len() <= 4096 && serde_json::to_vec(context)?.len() <= 8192,
            "interaction description too large"
        );
        let mut ids = std::collections::BTreeSet::new();
        for f in fields {
            ensure!(
                config::valid_name(&f.id) && ids.insert(&f.id),
                "invalid or duplicate field id"
            );
            ensure!(
                !f.label.is_empty() && f.label.len() <= 200 && config::valid_name(&f.kind),
                "invalid field description"
            );
            ensure!(
                f.choices.len() <= 32
                    && f.choices.iter().all(|s| !s.is_empty()
                        && s.len() <= 1024
                        && !s.contains(['\n', '\r', '\0'])),
                "invalid field choices"
            );
            ensure!(
                f.kind != "choice" || !f.choices.is_empty(),
                "choice field needs choices"
            );
        }
        Ok(())
    }

    pub fn validate_answer(&self, values: &BTreeMap<String, SecretString>) -> Result<()> {
        ensure!(
            values
                .keys()
                .all(|id| self.fields.iter().any(|f| &f.id == id)),
            "unknown response field"
        );
        for f in &self.fields {
            let value = values.get(&f.id).map(|s| s.0.as_str()).unwrap_or("");
            ensure!(
                !f.required || !value.is_empty(),
                "required response field missing"
            );
            ensure!(
                value.len() <= 4096 && !value.contains(['\n', '\r', '\0']),
                "invalid response field"
            );
            ensure!(
                value.is_empty() || f.choices.is_empty() || f.choices.iter().any(|s| s == value),
                "response outside field choices"
            );
            ensure!(
                value.is_empty() || f.kind != "confirmation" || matches!(value, "yes" | "no"),
                "invalid confirmation"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterStatus {
    pub recipient: Recipient,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterRequest {
    Challenge {
        prompt: String,
        fields: Vec<Field>,
        #[serde(default)]
        context: serde_json::Value,
        #[serde(default = "timeout")]
        timeout_secs: u64,
    },
    Withdraw {
        challenge_id: String,
    },
    Result {
        challenge_id: String,
        outcome: String,
    },
    Status {
        state: String,
    },
}
fn timeout() -> u64 {
    86400
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdapterEvent {
    Retry,
    Ready {
        version: u32,
        session_id: String,
    },
    Opened {
        challenge_id: String,
    },
    Answered {
        challenge_id: String,
        status: String,
        values: Option<BTreeMap<String, SecretString>>,
    },
    Recorded,
    Error {
        message: String,
    },
}
