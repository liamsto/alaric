use serde::{Deserialize, Serialize};
use sqlx::{
    prelude::{FromRow, Type},
    types::{
        Uuid,
        chrono::{DateTime, Utc},
    },
};

use crate::protocol::{CommandId, RejectionCode, RequestId, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "command_run_outcome", rename_all = "snake_case")]
pub enum CommandRunOutcome {
    Completed,
    Rejected,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "command_rejection_code", rename_all = "snake_case")]
pub enum CommandRejectionCode {
    UnknownCommand,
    InvalidArgs,
    PolicyError,
    ExecutionError,
    Timeout,
    OutputLimit,
}

impl From<RejectionCode> for CommandRejectionCode {
    fn from(value: RejectionCode) -> Self {
        match value {
            RejectionCode::UnknownCommand => Self::UnknownCommand,
            RejectionCode::InvalidArgs => Self::InvalidArgs,
            RejectionCode::PolicyError => Self::PolicyError,
            RejectionCode::ExecutionError => Self::ExecutionError,
            RejectionCode::Timeout => Self::Timeout,
            RejectionCode::OutputLimit => Self::OutputLimit,
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct CommandRun {
    pub run_id: Uuid,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub command_id: CommandId,
    pub outcome: CommandRunOutcome,
    pub exit_code: Option<i32>,
    pub timed_out: Option<bool>,
    pub truncated: Option<bool>,
    pub rejection_code: Option<CommandRejectionCode>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub reported_at: DateTime<Utc>,
}

// Explicit agent report payload used by server-side ingestion APIs.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CommandRunReport {
    pub run_id: Uuid,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub command_id: CommandId,
    #[serde(flatten)]
    pub result: CommandRunResult,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommandRunResult {
    Completed {
        exit_code: i32,
        timed_out: bool,
        truncated: bool,
    },
    Rejected {
        code: CommandRejectionCode,
        message: String,
    },
    Error {
        code: String,
        message: String,
    },
}
