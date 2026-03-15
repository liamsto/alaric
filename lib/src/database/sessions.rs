use std::net::IpAddr;

use crate::protocol::{HandshakeErrorCode, SessionId};
use serde::{Deserialize, Serialize};
use sqlx::{
    prelude::FromRow,
    types::{
        Uuid,
        chrono::{DateTime, Utc},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "session_log_outcome", rename_all = "snake_case")]
pub enum SessionLogOutcome {
    Accepted,
    Rejected,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "handshake_rejection_code", rename_all = "snake_case")]
pub enum HandshakeRejectionCode {
    UnsupportedProtocolVersion,
    InvalidRequest,
    AgentIdInUse,
    AgentUnavailable,
    Unauthorized,
    InternalError,
}

impl From<HandshakeErrorCode> for HandshakeRejectionCode {
    fn from(value: HandshakeErrorCode) -> Self {
        match value {
            HandshakeErrorCode::UnsupportedProtocolVersion => Self::UnsupportedProtocolVersion,
            HandshakeErrorCode::InvalidRequest => Self::InvalidRequest,
            HandshakeErrorCode::AgentIdInUse => Self::AgentIdInUse,
            HandshakeErrorCode::AgentUnavailable => Self::AgentUnavailable,
            HandshakeErrorCode::Unauthorized => Self::Unauthorized,
            HandshakeErrorCode::InternalError => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct SessionLog {
    pub session_id: SessionId,
    pub client_principal_id: Option<Uuid>,
    pub target_agent_principal_id: Option<Uuid>,
    pub paired_agent_principal_id: Option<Uuid>,
    pub outcome: SessionLogOutcome,
    pub rejection_code: Option<HandshakeRejectionCode>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub client_peer_ip: Option<IpAddr>,
    pub client_peer_port: Option<u16>,
    pub agent_peer_ip: Option<IpAddr>,
    pub agent_peer_port: Option<u16>,
    pub opened_at: DateTime<Utc>,
    pub paired_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}
