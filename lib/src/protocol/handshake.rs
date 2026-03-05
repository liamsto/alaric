use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use super::ids::{AgentId, ClientId, SessionId};

pub const PROTOCOL_VERSION: u16 = 1;
pub const AUTH_METHOD_SHARED_TOKEN_V1: &str = "shared_token_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Agent,
    Client,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Agent => "agent",
            Role::Client => "client",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub method: String,
    pub token: String,
}

impl AuthRequest {
    pub fn shared_token(token: impl Into<String>) -> Self {
        Self {
            method: AUTH_METHOD_SHARED_TOKEN_V1.to_string(),
            token: token.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum HandshakeRequest {
    Agent {
        protocol_version: u16,
        agent_id: AgentId,
        auth: Option<AuthRequest>,
        metadata: BTreeMap<String, String>,
    },
    Client {
        protocol_version: u16,
        client_id: ClientId,
        target_agent_id: AgentId,
        auth: Option<AuthRequest>,
        metadata: BTreeMap<String, String>,
    },
}

impl HandshakeRequest {
    pub fn agent(agent_id: AgentId) -> Self {
        Self::Agent {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            auth: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn client(client_id: ClientId, target_agent_id: AgentId) -> Self {
        Self::Client {
            protocol_version: PROTOCOL_VERSION,
            client_id,
            target_agent_id,
            auth: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn protocol_version(&self) -> u16 {
        match self {
            HandshakeRequest::Agent {
                protocol_version, ..
            } => *protocol_version,
            HandshakeRequest::Client {
                protocol_version, ..
            } => *protocol_version,
        }
    }

    pub fn role(&self) -> Role {
        match self {
            HandshakeRequest::Agent { .. } => Role::Agent,
            HandshakeRequest::Client { .. } => Role::Client,
        }
    }

    pub fn with_auth(mut self, auth: AuthRequest) -> Self {
        match &mut self {
            HandshakeRequest::Agent { auth: slot, .. } => *slot = Some(auth),
            HandshakeRequest::Client { auth: slot, .. } => *slot = Some(auth),
        }
        self
    }

    pub fn auth(&self) -> Option<&AuthRequest> {
        match self {
            HandshakeRequest::Agent { auth, .. } => auth.as_ref(),
            HandshakeRequest::Client { auth, .. } => auth.as_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeErrorCode {
    UnsupportedProtocolVersion,
    InvalidRequest,
    AgentIdInUse,
    AgentUnavailable,
    Unauthorized,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeAccepted {
    pub protocol_version: u16,
    pub session_id: SessionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRejected {
    pub protocol_version: u16,
    pub code: HandshakeErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HandshakeResponse {
    Accepted(HandshakeAccepted),
    Rejected(HandshakeRejected),
}
