pub mod config;
pub mod paths;
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
    Reload {
        #[serde(default)]
        revision: Option<String>,
    },
    History {
        before: Option<u64>,
        limit: Option<usize>,
    },
    RequestDetail {
        request_id: String,
    },
    Retry {
        request_id: String,
    },
    Actions {
        request_id: Option<String>,
        before: Option<u64>,
        limit: Option<usize>,
    },
    Audit {
        action: String,
        detail: serde_json::Value,
    },
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
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub cwd: std::path::PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestRecord {
    pub sequence: u64,
    pub request_id: String,
    pub retry_of: Option<String>,
    #[serde(default)]
    pub approval_id: Option<String>,
    pub principal: String,
    pub input: Request,
    pub command: Option<Command>,
    pub cwd: Option<std::path::PathBuf>,
    pub status: String,
    pub authorization: Option<String>,
    pub reason: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl RequestRecord {
    pub fn is_terminal(&self) -> bool {
        !matches!(
            self.status.as_str(),
            "received" | "pending" | "approved" | "allowed" | "running"
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionRecord {
    pub sequence: u64,
    pub time_unix_ms: u64,
    pub request_id: Option<String>,
    pub action: String,
    pub detail: serde_json::Value,
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
        revision: String,
    },
    Reloaded {
        revision: String,
        cancelled_approvals: usize,
        retained_approvals: usize,
        allowed_approvals: usize,
        refreshed_approvals: usize,
    },
    History {
        requests: Vec<RequestRecord>,
        next_before: Option<u64>,
    },
    RequestDetail {
        request: Box<RequestRecord>,
        actions: Vec<ActionRecord>,
        next_before: Option<u64>,
    },
    Submitted {
        request_id: String,
    },
    Actions {
        actions: Vec<ActionRecord>,
        next_before: Option<u64>,
    },
    Audited,
}

impl Event {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending { .. })
    }
}
