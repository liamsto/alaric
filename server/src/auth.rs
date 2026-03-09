use std::{
    collections::HashMap,
    env,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use alaric_lib::{
    database::{Database, principals::PrincipalKind},
    protocol::{
        AUTH_METHOD_ED25519_CHALLENGE_V1, AgentId, ClientId, HandshakeChallenge,
        HandshakeProofRequest, HandshakeRequest, PROTOCOL_VERSION, decode_ed25519_public_key,
        verify_auth_proof_ed25519,
    },
};
use rand::random;
use serde::Deserialize;
use tokio::sync::Mutex;

const AUTH_CONFIG_VERSION_V2: u16 = 2;
const AUTH_CONFIG_PATH_ENV: &str = "SERVER_AUTH_CONFIG_PATH";
const DEFAULT_AUTH_CONFIG_PATH: &str = "./server-auth.json";
const CHALLENGE_TTL_SECS: u64 = 30;

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
    Database(String),
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
            HandshakeAuthError::Database(message) => {
                write!(f, "database-backed handshake auth failed: {}", message)
            }
        }
    }
}

impl Error for HandshakeAuthError {}

#[derive(Debug, Clone)]
pub struct IdentityPublicKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Debug)]
pub struct HandshakeAuthenticator {
    agent_keys: HashMap<AgentId, IdentityPublicKey>,
    client_keys: HashMap<ClientId, IdentityPublicKey>,
    issued_challenges: Mutex<HashMap<String, u64>>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigFile {
    version: u16,
    #[serde(default)]
    agents: HashMap<String, AuthConfigIdentity>,
    #[serde(default)]
    clients: HashMap<String, AuthConfigIdentity>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigIdentity {
    key_id: String,
    public_key: String,
}

impl HandshakeAuthenticator {
    pub fn from_env_or_default_path() -> Result<Self, HandshakeAuthError> {
        let path =
            env::var(AUTH_CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_AUTH_CONFIG_PATH.to_string());
        Self::load_from_path(path)
    }

    pub fn new(
        agent_keys: HashMap<AgentId, IdentityPublicKey>,
        client_keys: HashMap<ClientId, IdentityPublicKey>,
    ) -> Result<Self, HandshakeAuthError> {
        if agent_keys.is_empty() {
            return Err(HandshakeAuthError::Invalid(
                "at least one authorized agent is required".to_string(),
            ));
        }
        if client_keys.is_empty() {
            return Err(HandshakeAuthError::Invalid(
                "at least one authorized client is required".to_string(),
            ));
        }

        for (agent_id, key) in &agent_keys {
            if key.key_id.trim().is_empty() {
                return Err(HandshakeAuthError::Invalid(format!(
                    "agent '{}' has an empty key_id",
                    agent_id
                )));
            }
        }
        for (client_id, key) in &client_keys {
            if key.key_id.trim().is_empty() {
                return Err(HandshakeAuthError::Invalid(format!(
                    "client '{}' has an empty key_id",
                    client_id
                )));
            }
        }

        Ok(Self {
            agent_keys,
            client_keys,
            issued_challenges: Mutex::new(HashMap::new()),
        })
    }

    pub async fn from_database(database: &Database) -> Result<Self, HandshakeAuthError> {
        let rows = database
            .load_active_principal_keys()
            .await
            .map_err(|err| HandshakeAuthError::Database(err.to_string()))?;

        let mut agent_keys = HashMap::new();
        let mut client_keys = HashMap::new();

        for row in rows {
            match row.kind {
                PrincipalKind::Agent => {
                    let agent_id = AgentId::new(&row.external_id).map_err(|err| {
                        HandshakeAuthError::Invalid(format!(
                            "invalid authorized agent id from database: {}",
                            err
                        ))
                    })?;
                    agent_keys.entry(agent_id).or_insert(IdentityPublicKey {
                        key_id: row.key_id,
                        public_key: row.public_key,
                    });
                }
                PrincipalKind::Client => {
                    let client_id = ClientId::new(&row.external_id).map_err(|err| {
                        HandshakeAuthError::Invalid(format!(
                            "invalid authorized client id from database: {}",
                            err
                        ))
                    })?;
                    client_keys.entry(client_id).or_insert(IdentityPublicKey {
                        key_id: row.key_id,
                        public_key: row.public_key,
                    });
                }
            }
        }

        Self::new(agent_keys, client_keys)
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

        if config.version != AUTH_CONFIG_VERSION_V2 {
            return Err(HandshakeAuthError::Invalid(format!(
                "unsupported auth config version {}; expected {}",
                config.version, AUTH_CONFIG_VERSION_V2
            )));
        }

        let mut agent_keys = HashMap::new();
        for (id, config_identity) in config.agents {
            let agent_id = AgentId::new(id).map_err(|err| {
                HandshakeAuthError::Invalid(format!("invalid authorized agent id: {}", err))
            })?;
            let public_key =
                decode_ed25519_public_key(&config_identity.public_key).map_err(|err| {
                    HandshakeAuthError::Invalid(format!(
                        "agent '{}' has invalid public_key: {}",
                        agent_id, err
                    ))
                })?;
            agent_keys.insert(
                agent_id,
                IdentityPublicKey {
                    key_id: config_identity.key_id,
                    public_key,
                },
            );
        }

        let mut client_keys = HashMap::new();
        for (id, config_identity) in config.clients {
            let client_id = ClientId::new(id).map_err(|err| {
                HandshakeAuthError::Invalid(format!("invalid authorized client id: {}", err))
            })?;
            let public_key =
                decode_ed25519_public_key(&config_identity.public_key).map_err(|err| {
                    HandshakeAuthError::Invalid(format!(
                        "client '{}' has invalid public_key: {}",
                        client_id, err
                    ))
                })?;
            client_keys.insert(
                client_id,
                IdentityPublicKey {
                    key_id: config_identity.key_id,
                    public_key,
                },
            );
        }

        Self::new(agent_keys, client_keys)
    }

    pub async fn issue_challenge(
        &self,
        request: &HandshakeRequest,
    ) -> Result<HandshakeChallenge, HandshakeAuthError> {
        let _ = self.identity_key_for_request(request)?;
        let now_unix = current_unix_timestamp()?;
        let expires_at_unix = now_unix
            .checked_add(CHALLENGE_TTL_SECS)
            .ok_or_else(|| HandshakeAuthError::Invalid("challenge expiry overflow".to_string()))?;
        let nonce = hex::encode(random::<[u8; 32]>());

        let mut issued = self.issued_challenges.lock().await;
        prune_expired(&mut issued, now_unix);
        issued.insert(nonce.clone(), expires_at_unix);

        Ok(HandshakeChallenge::ed25519(nonce, expires_at_unix))
    }

    pub async fn authenticate(
        &self,
        request: &HandshakeRequest,
        challenge: &HandshakeChallenge,
        proof_request: &HandshakeProofRequest,
    ) -> Result<(), HandshakeAuthError> {
        let now_unix = current_unix_timestamp()?;
        if proof_request.protocol_version != PROTOCOL_VERSION {
            return Err(HandshakeAuthError::Unauthorized(format!(
                "proof protocol version mismatch; expected {}, got {}",
                PROTOCOL_VERSION, proof_request.protocol_version
            )));
        }

        if challenge.protocol_version != PROTOCOL_VERSION {
            return Err(HandshakeAuthError::Unauthorized(format!(
                "challenge protocol version mismatch; expected {}, got {}",
                PROTOCOL_VERSION, challenge.protocol_version
            )));
        }

        if challenge.method != AUTH_METHOD_ED25519_CHALLENGE_V1 {
            return Err(HandshakeAuthError::Unauthorized(format!(
                "unsupported challenge method '{}'",
                challenge.method
            )));
        }

        if proof_request.proof.method != challenge.method {
            return Err(HandshakeAuthError::Unauthorized(format!(
                "proof method '{}' does not match challenge method '{}'",
                proof_request.proof.method, challenge.method
            )));
        }

        if now_unix > challenge.expires_at_unix {
            return Err(HandshakeAuthError::Unauthorized(
                "challenge has expired".to_string(),
            ));
        }

        self.consume_challenge(&challenge.nonce, now_unix).await?;

        let trusted_key = self.identity_key_for_request(request)?;
        let verified = verify_auth_proof_ed25519(
            request,
            challenge,
            &proof_request.proof,
            &trusted_key.key_id,
            trusted_key.public_key,
        )
        .map_err(|err| {
            HandshakeAuthError::Unauthorized(format!("failed to verify auth proof: {}", err))
        })?;

        if !verified {
            return Err(HandshakeAuthError::Unauthorized(
                "signature verification failed".to_string(),
            ));
        }

        Ok(())
    }

    fn identity_key_for_request(
        &self,
        request: &HandshakeRequest,
    ) -> Result<&IdentityPublicKey, HandshakeAuthError> {
        match request {
            HandshakeRequest::Agent { agent_id, .. } => {
                self.agent_keys.get(agent_id).ok_or_else(|| {
                    HandshakeAuthError::Unauthorized(format!(
                        "agent '{}' is not authorized",
                        agent_id
                    ))
                })
            }
            HandshakeRequest::Client { client_id, .. } => {
                self.client_keys.get(client_id).ok_or_else(|| {
                    HandshakeAuthError::Unauthorized(format!(
                        "client '{}' is not authorized",
                        client_id
                    ))
                })
            }
        }
    }

    async fn consume_challenge(
        &self,
        nonce: &str,
        now_unix: u64,
    ) -> Result<(), HandshakeAuthError> {
        let mut issued = self.issued_challenges.lock().await;
        prune_expired(&mut issued, now_unix);
        let Some(expires_at_unix) = issued.remove(nonce) else {
            return Err(HandshakeAuthError::Unauthorized(
                "challenge nonce is unknown or already consumed".to_string(),
            ));
        };
        if now_unix > expires_at_unix {
            return Err(HandshakeAuthError::Unauthorized(
                "challenge has expired".to_string(),
            ));
        }
        Ok(())
    }
}

fn current_unix_timestamp() -> Result<u64, HandshakeAuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| {
            HandshakeAuthError::Invalid(format!(
                "system clock is set before unix epoch: {}",
                source
            ))
        })
}

fn prune_expired(issued: &mut HashMap<String, u64>, now_unix: u64) {
    issued.retain(|_, expires_at_unix| *expires_at_unix >= now_unix);
}
