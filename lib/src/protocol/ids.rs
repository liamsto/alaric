use std::{error::Error, fmt, str::FromStr};

use rand::random;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::types::Uuid;

const MIN_ID_LEN: usize = 3;
const MAX_ID_LEN: usize = 64;

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

    #[must_use]
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
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        AgentId::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentGroupId(String);

impl AgentGroupId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_id("agent_group", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for AgentGroupId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AgentGroupId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        AgentGroupId::new(value).map_err(serde::de::Error::custom)
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

    #[must_use]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(Uuid);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdError(String);

impl SessionId {
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = random::<[u8; 16]>();
        // RFC 4122 v4 UUID layout.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(Uuid::from_bytes(bytes))
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for SessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl From<Uuid> for SessionId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<SessionId> for Uuid {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

impl FromStr for SessionId {
    type Err = SessionIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|err| SessionIdError(format!("invalid session id '{}': {}", s, err)))
    }
}

impl fmt::Display for SessionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for SessionIdError {}
