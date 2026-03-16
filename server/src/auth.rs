use std::{
    collections::HashMap,
    error::Error,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use alaric_lib::{
    database::{Database, principals::PrincipalKind},
    protocol::{
        AUTH_METHOD_ED25519_CHALLENGE_V1, AgentId, ClientId, HandshakeChallenge,
        HandshakeProofRequest, HandshakeRequest, PROTOCOL_VERSION, verify_auth_proof_ed25519,
    },
};
use rand::random;
use tokio::sync::Mutex;

const CHALLENGE_TTL_SECS: u64 = 30;

#[derive(Debug)]
pub enum HandshakeAuthError {
    Invalid(String),
    Unauthorized(String),
    Database(String),
}

impl fmt::Display for HandshakeAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

impl HandshakeAuthenticator {
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
            .load_principal_keys()
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
            HandshakeRequest::ClientDiscovery { client_id, .. } => {
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
