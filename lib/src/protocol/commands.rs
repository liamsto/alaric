use std::{collections::BTreeMap, error::Error, fmt, io};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{SecureChannel, SecureChannelError};

const MIN_COMMAND_ID_LEN: usize = 1;
const MAX_COMMAND_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub u64);

impl From<u64> for RequestId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<RequestId> for u64 {
    fn from(value: RequestId) -> Self {
        value.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandIdError(String);

impl fmt::Display for CommandIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CommandIdError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandId(String);

impl CommandId {
    pub fn new(value: impl Into<String>) -> Result<Self, CommandIdError> {
        let value = value.into();
        let len = value.len();
        if !(MIN_COMMAND_ID_LEN..=MAX_COMMAND_ID_LEN).contains(&len) {
            return Err(CommandIdError(format!(
                "command id must be between {} and {} characters",
                MIN_COMMAND_ID_LEN, MAX_COMMAND_ID_LEN
            )));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(CommandIdError(
                "command id contains invalid characters (allowed: a-z, A-Z, 0-9, '-', '_', '.')"
                    .to_string(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CommandId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CommandId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Execute {
        request_id: RequestId,
        command_id: CommandId,
        args: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    UnknownCommand,
    InvalidArgs,
    PolicyError,
    ExecutionError,
    Timeout,
    OutputLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    Started {
        request_id: RequestId,
    },
    Output {
        request_id: RequestId,
        stream: OutputStream,
        chunk: String,
    },
    Completed {
        request_id: RequestId,
        exit_code: i32,
        timed_out: bool,
        truncated: bool,
    },
    Rejected {
        request_id: RequestId,
        code: RejectionCode,
        message: String,
    },
}

#[derive(Debug)]
pub enum CommandProtocolError {
    SecureChannel(SecureChannelError),
    Json(serde_json::Error),
    Io(io::Error),
}

impl fmt::Display for CommandProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandProtocolError::SecureChannel(err) => write!(f, "secure channel error: {}", err),
            CommandProtocolError::Json(err) => write!(f, "json error: {}", err),
            CommandProtocolError::Io(err) => write!(f, "io error: {}", err),
        }
    }
}

impl Error for CommandProtocolError {}

impl From<SecureChannelError> for CommandProtocolError {
    fn from(value: SecureChannelError) -> Self {
        Self::SecureChannel(value)
    }
}

impl From<serde_json::Error> for CommandProtocolError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<io::Error> for CommandProtocolError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub async fn send_secure_json<S, T>(
    channel: &mut SecureChannel,
    stream: &mut S,
    message: &T,
) -> Result<(), CommandProtocolError>
where
    S: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(message)?;
    channel.send(stream, &payload).await?;
    Ok(())
}

pub async fn recv_secure_json<S, T>(
    channel: &mut SecureChannel,
    stream: &mut S,
) -> Result<T, CommandProtocolError>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let payload = channel.recv(stream).await?;
    let message = serde_json::from_slice(&payload)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{AgentMessage, ClientMessage, CommandId, OutputStream, RejectionCode, RequestId};

    #[test]
    fn client_message_round_trip() {
        let mut args = BTreeMap::new();
        args.insert("path".to_string(), "/tmp".to_string());
        let original = ClientMessage::Execute {
            request_id: RequestId(42),
            command_id: CommandId::new("list_dir").expect("valid command id"),
            args,
        };

        let encoded = serde_json::to_vec(&original).expect("serialize client message");
        let decoded: ClientMessage =
            serde_json::from_slice(&encoded).expect("deserialize client message");

        assert_eq!(decoded, original);
    }

    #[test]
    fn agent_message_round_trip() {
        let original = AgentMessage::Output {
            request_id: RequestId(7),
            stream: OutputStream::Stdout,
            chunk: "hello".to_string(),
        };

        let encoded = serde_json::to_vec(&original).expect("serialize agent message");
        let decoded: AgentMessage =
            serde_json::from_slice(&encoded).expect("deserialize agent message");

        assert_eq!(decoded, original);
    }

    #[test]
    fn rejection_code_wire_value_stability() {
        let encoded =
            serde_json::to_string(&RejectionCode::OutputLimit).expect("serialize rejection code");
        assert_eq!(encoded, "\"output_limit\"");
    }
}
