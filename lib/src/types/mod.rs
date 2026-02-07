use std::{collections::BTreeMap, error::Error, fmt, io};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

const MIN_ID_LEN: usize = 3;
const MAX_ID_LEN: usize = 64;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError {
    kind: &'static str,
    message: String,
}

impl IdError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} id {}", self.kind, self.message)
    }
}

impl Error for IdError {}

fn validate_id(kind: &'static str, value: &str) -> Result<(), IdError> {
    let len = value.len();
    if !(MIN_ID_LEN..=MAX_ID_LEN).contains(&len) {
        return Err(IdError::new(
            kind,
            format!(
                "must be between {} and {} characters",
                MIN_ID_LEN, MAX_ID_LEN
            ),
        ));
    }

    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(IdError::new(
            kind,
            "contains invalid characters (allowed: a-z, A-Z, 0-9, '-', '_', '.')",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(String);

impl AgentId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_id("agent", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for AgentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AgentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        AgentId::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId(String);

impl ClientId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_id("client", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ClientId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ClientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        ClientId::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub method: String,
    pub token: String,
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

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    Json(serde_json::Error),
    FrameTooLarge(usize),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Io(err) => write!(f, "I/O error: {}", err),
            ProtocolError::Json(err) => write!(f, "JSON error: {}", err),
            ProtocolError::FrameTooLarge(size) => write!(
                f,
                "frame is {} bytes, above configured maximum {}",
                size, MAX_FRAME_BYTES
            ),
        }
    }
}

impl Error for ProtocolError {}

impl From<io::Error> for ProtocolError {
    fn from(value: io::Error) -> Self {
        ProtocolError::Io(value)
    }
}

pub async fn write_json_frame<W, T>(writer: &mut W, message: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(message).map_err(ProtocolError::Json)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }

    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_json_frame<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let len = reader.read_u32().await? as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice::<T>(&payload).map_err(ProtocolError::Json)
}

#[cfg(test)]
mod tests {
    use super::{AgentId, ClientId, HandshakeRequest};

    #[test]
    fn agent_id_validation_rejects_invalid_chars() {
        assert!(AgentId::new("agent id").is_err());
    }

    #[test]
    fn client_id_validation_accepts_valid_chars() {
        assert!(ClientId::new("client_001.prod").is_ok());
    }

    #[test]
    fn handshake_helpers_set_expected_role() {
        let agent_id = AgentId::new("agent-main").expect("valid agent id");
        let request = HandshakeRequest::agent(agent_id);
        assert_eq!(request.role().as_str(), "agent");
    }
}
