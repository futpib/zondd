pub mod config;
pub mod wire;

use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Run {
        command: Command,
    },
    Invoke {
        operation: String,
        args: Vec<String>,
    },
    ListOperations,
    Pending,
    Resolve {
        approval_id: String,
        approve: bool,
    },
    Status,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub version: u32,
    pub id: u64,
    pub body: T,
}

impl<T> Envelope<T> {
    pub fn new(id: u64, body: T) -> Self {
        Self {
            version: VERSION,
            id,
            body,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pending {
    pub approval_id: String,
    pub principal: String,
    pub command: Command,
    pub operation: Option<String>,
    pub reason: String,
    pub expires_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationInfo {
    pub name: String,
    pub description: String,
    pub arguments: Vec<config::Argument>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Pending {
        request: Pending,
    },
    Completed {
        code: Option<i32>,
        signal: Option<i32>,
        stdout: String,
        stderr: String,
    },
    Rejected {
        reason: String,
    },
    Error {
        message: String,
    },
    Queue {
        requests: Vec<Pending>,
    },
    Resolved {
        approval_id: String,
        approved: bool,
    },
    Operations {
        operations: Vec<OperationInfo>,
    },
    Status {
        pending: usize,
        running: usize,
    },
}

impl Event {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending { .. })
    }
}
