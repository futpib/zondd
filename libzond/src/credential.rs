//! Public local credential API v1. Application processes own their lifecycle.

use crate::{SecretString, config, interaction::Field};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientConfig {
    pub label: String,
    /// SHA-256 of a separately provisioned 64-character random hexadecimal key.
    pub key_sha256: String,
    pub field_ids: BTreeSet<String>,
    pub origins: BTreeSet<String>,
}

impl RecipientConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.label.trim().is_empty()
                && self.label.len() <= 200
                && !self.label.chars().any(char::is_control),
            "invalid credential recipient label"
        );
        ensure!(
            valid_key(&self.key_sha256),
            "invalid credential identity digest"
        );
        ensure!(
            (1..=64).contains(&self.field_ids.len())
                && self.field_ids.iter().all(|id| config::valid_name(id)),
            "invalid allowed credential fields"
        );
        ensure!(
            (1..=32).contains(&self.origins.len())
                && self.origins.iter().all(|origin| valid_origin(origin)),
            "expected canonical HTTP(S) provider origins"
        );
        Ok(())
    }
}

pub fn valid_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_origin(origin: &str) -> bool {
    url::Url::parse(origin).is_ok_and(|url| {
        matches!(url.scheme(), "https" | "http")
            && url.username().is_empty()
            && url.password().is_none()
            && url.origin().ascii_serialization() == origin
    })
}

/// Every frame uses the standard version/id/body envelope. IDs strictly increase
/// within a connection; an answer echoes the ID of the opening challenge.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Authenticate {
        recipient: String,
        key: SecretString,
    },
    Challenge {
        origin: String,
        #[serde(default)]
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
}

fn timeout() -> u64 {
    300
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Ready {
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
    Recorded {
        challenge_id: String,
    },
    Error {
        code: String,
    },
}

impl Event {
    pub fn error(code: &str) -> Self {
        Self::Error { code: code.into() }
    }
}
