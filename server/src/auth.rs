use std::{
    collections::HashMap,
    env,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use alaric_lib::protocol::{AUTH_METHOD_SHARED_TOKEN_V1, AgentId, ClientId, HandshakeRequest};
use serde::Deserialize;

const AUTH_CONFIG_VERSION_V1: u16 = 1;
const AUTH_CONFIG_PATH_ENV: &str = "SERVER_AUTH_CONFIG_PATH";
const DEFAULT_AUTH_CONFIG_PATH: &str = "./server-auth.json";

#[derive(Debug)]
pub enum HandshakeAuthError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Invalid(String),
    Unauthorized(String),
}

impl fmt::Display for HandshakeAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeAuthError::Io { path, source } => {
                write!(
                    f,
                    "failed to read handshake auth config '{}': {}",
                    path.display(),
                    source
                )
            }
            HandshakeAuthError::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse handshake auth config '{}': {}",
                    path.display(),
                    source
                )
            }
            HandshakeAuthError::Invalid(message) => {
                write!(f, "invalid handshake auth configuration: {}", message)
            }
            HandshakeAuthError::Unauthorized(message) => f.write_str(message),
        }
    }
}

impl Error for HandshakeAuthError {}

#[derive(Debug, Clone)]
pub struct HandshakeAuthenticator {
    agent_tokens: HashMap<AgentId, String>,
    client_tokens: HashMap<ClientId, String>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigFile {
    version: u16,
    #[serde(default)]
    agents: HashMap<String, String>,
    #[serde(default)]
    clients: HashMap<String, String>,
}

impl HandshakeAuthenticator {
    pub fn from_env_or_default_path() -> Result<Self, HandshakeAuthError> {
        let path =
            env::var(AUTH_CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_AUTH_CONFIG_PATH.to_string());
        Self::load_from_path(path)
    }

    pub fn new(
        agent_tokens: HashMap<AgentId, String>,
        client_tokens: HashMap<ClientId, String>,
    ) -> Result<Self, HandshakeAuthError> {
        if agent_tokens.is_empty() {
            return Err(HandshakeAuthError::Invalid(
                "at least one authorized agent is required".to_string(),
            ));
        }
        if client_tokens.is_empty() {
            return Err(HandshakeAuthError::Invalid(
                "at least one authorized client is required".to_string(),
            ));
        }

        if agent_tokens.values().any(|token| token.is_empty()) {
            return Err(HandshakeAuthError::Invalid(
                "agent auth token must not be empty".to_string(),
            ));
        }

        if client_tokens.values().any(|token| token.is_empty()) {
            return Err(HandshakeAuthError::Invalid(
                "client auth token must not be empty".to_string(),
            ));
        }

        Ok(Self {
            agent_tokens,
            client_tokens,
        })
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, HandshakeAuthError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| HandshakeAuthError::Io {
            path: path.clone(),
            source,
        })?;

        let config: AuthConfigFile =
            serde_json::from_str(&raw).map_err(|source| HandshakeAuthError::Parse {
                path: path.clone(),
                source,
            })?;

        if config.version != AUTH_CONFIG_VERSION_V1 {
            return Err(HandshakeAuthError::Invalid(format!(
                "unsupported auth config version {}; expected {}",
                config.version, AUTH_CONFIG_VERSION_V1
            )));
        }

        let mut agent_tokens = HashMap::new();
        for (id, token) in config.agents {
            let agent_id = AgentId::new(id).map_err(|err| {
                HandshakeAuthError::Invalid(format!("invalid authorized agent id: {}", err))
            })?;
            if token.is_empty() {
                return Err(HandshakeAuthError::Invalid(
                    "agent auth token must not be empty".to_string(),
                ));
            }
            agent_tokens.insert(agent_id, token);
        }

        let mut client_tokens = HashMap::new();
        for (id, token) in config.clients {
            let client_id = ClientId::new(id).map_err(|err| {
                HandshakeAuthError::Invalid(format!("invalid authorized client id: {}", err))
            })?;
            if token.is_empty() {
                return Err(HandshakeAuthError::Invalid(
                    "client auth token must not be empty".to_string(),
                ));
            }
            client_tokens.insert(client_id, token);
        }

        Self::new(agent_tokens, client_tokens)
    }

    pub fn authenticate(&self, request: &HandshakeRequest) -> Result<(), HandshakeAuthError> {
        let auth = request.auth().ok_or_else(|| {
            HandshakeAuthError::Unauthorized("missing handshake authentication payload".to_string())
        })?;

        if auth.method != AUTH_METHOD_SHARED_TOKEN_V1 {
            return Err(HandshakeAuthError::Unauthorized(format!(
                "unsupported authentication method '{}'",
                auth.method
            )));
        }

        match request {
            HandshakeRequest::Agent { agent_id, .. } => {
                let Some(expected_token) = self.agent_tokens.get(agent_id) else {
                    return Err(HandshakeAuthError::Unauthorized(format!(
                        "agent '{}' is not authorized",
                        agent_id
                    )));
                };

                if !constant_time_token_eq(auth.token.as_bytes(), expected_token.as_bytes()) {
                    return Err(HandshakeAuthError::Unauthorized(format!(
                        "authentication failed for agent '{}'",
                        agent_id
                    )));
                }
            }
            HandshakeRequest::Client { client_id, .. } => {
                let Some(expected_token) = self.client_tokens.get(client_id) else {
                    return Err(HandshakeAuthError::Unauthorized(format!(
                        "client '{}' is not authorized",
                        client_id
                    )));
                };

                if !constant_time_token_eq(auth.token.as_bytes(), expected_token.as_bytes()) {
                    return Err(HandshakeAuthError::Unauthorized(format!(
                        "authentication failed for client '{}'",
                        client_id
                    )));
                }
            }
        }

        Ok(())
    }
}

fn constant_time_token_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}
