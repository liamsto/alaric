use std::{collections::BTreeMap, error::Error, fmt};

use hacl_star::ed25519;
use serde::{Deserialize, Serialize};

use super::ids::{AgentId, ClientId, SessionId};

pub const PROTOCOL_VERSION: u16 = 1;
pub const AUTH_METHOD_ED25519_CHALLENGE_V1: &str = "ed25519_challenge_v1";
const AUTH_SIGNING_CONTEXT_V1: &str = "alaric-handshake-auth-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Agent,
    Client,
}

impl Role {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
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
#[serde(tag = "role", rename_all = "snake_case")]
pub enum HandshakeRequest {
    Agent {
        protocol_version: u16,
        agent_id: AgentId,
        metadata: BTreeMap<String, String>,
    },
    Client {
        protocol_version: u16,
        client_id: ClientId,
        target_agent_id: AgentId,
        metadata: BTreeMap<String, String>,
    },
    ClientDiscovery {
        protocol_version: u16,
        client_id: ClientId,
        metadata: BTreeMap<String, String>,
    },
}

impl HandshakeRequest {
    #[must_use]
    pub const fn agent(agent_id: AgentId) -> Self {
        Self::Agent {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn client(client_id: ClientId, target_agent_id: AgentId) -> Self {
        Self::Client {
            protocol_version: PROTOCOL_VERSION,
            client_id,
            target_agent_id,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn client_discovery(client_id: ClientId) -> Self {
        Self::ClientDiscovery {
            protocol_version: PROTOCOL_VERSION,
            client_id,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        match self {
            HandshakeRequest::Agent {
                protocol_version, ..
            } => *protocol_version,
            HandshakeRequest::Client {
                protocol_version, ..
            } => *protocol_version,
            HandshakeRequest::ClientDiscovery {
                protocol_version, ..
            } => *protocol_version,
        }
    }

    #[must_use]
    pub const fn role(&self) -> Role {
        match self {
            HandshakeRequest::Agent { .. } => Role::Agent,
            HandshakeRequest::Client { .. } => Role::Client,
            HandshakeRequest::ClientDiscovery { .. } => Role::Client,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProof {
    pub method: String,
    pub key_id: String,
    pub signature: String,
}

impl AuthProof {
    pub fn ed25519(key_id: impl Into<String>, signature: impl Into<String>) -> Self {
        Self {
            method: AUTH_METHOD_ED25519_CHALLENGE_V1.to_string(),
            key_id: key_id.into(),
            signature: signature.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeProofRequest {
    pub protocol_version: u16,
    pub proof: AuthProof,
}

impl HandshakeProofRequest {
    #[must_use]
    pub const fn new(proof: AuthProof) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            proof,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    pub protocol_version: u16,
    pub method: String,
    pub nonce: String,
    pub expires_at_unix: u64,
}

impl HandshakeChallenge {
    pub fn ed25519(nonce: impl Into<String>, expires_at_unix: u64) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            method: AUTH_METHOD_ED25519_CHALLENGE_V1.to_string(),
            nonce: nonce.into(),
            expires_at_unix,
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
    Challenge(HandshakeChallenge),
    Accepted(HandshakeAccepted),
    Rejected(HandshakeRejected),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCryptoError {
    ProtocolVersionMismatch {
        expected: u16,
        got: u16,
    },
    UnsupportedMethod(String),
    InvalidKeyId,
    InvalidHex {
        field: &'static str,
        message: String,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    Serialize(String),
}

impl fmt::Display for AuthCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthCryptoError::ProtocolVersionMismatch { expected, got } => {
                write!(
                    f,
                    "protocol version mismatch for auth payload; expected {}, got {}",
                    expected, got
                )
            }
            AuthCryptoError::UnsupportedMethod(method) => {
                write!(f, "unsupported auth method '{}'", method)
            }
            AuthCryptoError::InvalidKeyId => f.write_str("key_id must not be empty"),
            AuthCryptoError::InvalidHex { field, message } => {
                write!(f, "{} is not valid hex: {}", field, message)
            }
            AuthCryptoError::InvalidLength {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{} must be {} bytes, got {} bytes",
                    field, expected, actual
                )
            }
            AuthCryptoError::Serialize(message) => {
                write!(f, "failed to serialize auth payload: {}", message)
            }
        }
    }
}

impl Error for AuthCryptoError {}

#[derive(Debug, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
enum AuthPrincipal<'a> {
    Agent {
        agent_id: &'a AgentId,
    },
    Client {
        client_id: &'a ClientId,
        target_agent_id: &'a AgentId,
    },
    ClientDiscovery {
        client_id: &'a ClientId,
    },
}

#[derive(Debug, Serialize)]
struct AuthSigningPayload<'a> {
    context: &'static str,
    protocol_version: u16,
    method: &'a str,
    nonce: &'a str,
    expires_at_unix: u64,
    key_id: &'a str,
    principal: AuthPrincipal<'a>,
}

pub fn build_auth_proof_ed25519(
    request: &HandshakeRequest,
    challenge: &HandshakeChallenge,
    key_id: &str,
    private_key_hex: &str,
) -> Result<AuthProof, AuthCryptoError> {
    if key_id.trim().is_empty() {
        return Err(AuthCryptoError::InvalidKeyId);
    }

    if challenge.method != AUTH_METHOD_ED25519_CHALLENGE_V1 {
        return Err(AuthCryptoError::UnsupportedMethod(challenge.method.clone()));
    }

    let private_key_bytes =
        decode_hex_array::<{ ed25519::SECRET_LENGTH }>("private key", private_key_hex)?;
    let payload = signing_payload(request, challenge, key_id, &challenge.method)?;
    let signature = ed25519::SecretKey(private_key_bytes).signature(&payload);

    Ok(AuthProof::ed25519(key_id, hex::encode(signature.0)))
}

pub fn verify_auth_proof_ed25519(
    request: &HandshakeRequest,
    challenge: &HandshakeChallenge,
    proof: &AuthProof,
    expected_key_id: &str,
    public_key: [u8; ed25519::PUBLIC_LENGTH],
) -> Result<bool, AuthCryptoError> {
    if challenge.method != AUTH_METHOD_ED25519_CHALLENGE_V1 {
        return Err(AuthCryptoError::UnsupportedMethod(challenge.method.clone()));
    }

    if proof.method != challenge.method {
        return Ok(false);
    }

    if proof.key_id != expected_key_id {
        return Ok(false);
    }

    let payload = signing_payload(request, challenge, &proof.key_id, &proof.method)?;
    let signature_bytes =
        decode_hex_array::<{ ed25519::SIG_LENGTH }>("signature", &proof.signature)?;
    let signature = ed25519::Signature(signature_bytes);
    Ok(ed25519::PublicKey(public_key).verify(&payload, &signature))
}

pub fn decode_ed25519_public_key(
    value: &str,
) -> Result<[u8; ed25519::PUBLIC_LENGTH], AuthCryptoError> {
    decode_hex_array("public key", value)
}

fn signing_payload(
    request: &HandshakeRequest,
    challenge: &HandshakeChallenge,
    key_id: &str,
    method: &str,
) -> Result<Vec<u8>, AuthCryptoError> {
    if request.protocol_version() != challenge.protocol_version {
        return Err(AuthCryptoError::ProtocolVersionMismatch {
            expected: request.protocol_version(),
            got: challenge.protocol_version,
        });
    }

    let principal = match request {
        HandshakeRequest::Agent { agent_id, .. } => AuthPrincipal::Agent { agent_id },
        HandshakeRequest::Client {
            client_id,
            target_agent_id,
            ..
        } => AuthPrincipal::Client {
            client_id,
            target_agent_id,
        },
        HandshakeRequest::ClientDiscovery { client_id, .. } => {
            AuthPrincipal::ClientDiscovery { client_id }
        }
    };

    serde_json::to_vec(&AuthSigningPayload {
        context: AUTH_SIGNING_CONTEXT_V1,
        protocol_version: challenge.protocol_version,
        method,
        nonce: &challenge.nonce,
        expires_at_unix: challenge.expires_at_unix,
        key_id,
        principal,
    })
    .map_err(|source| AuthCryptoError::Serialize(source.to_string()))
}

fn decode_hex_array<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], AuthCryptoError> {
    let bytes = hex::decode(value).map_err(|source| AuthCryptoError::InvalidHex {
        field,
        message: source.to_string(),
    })?;
    if bytes.len() != N {
        return Err(AuthCryptoError::InvalidLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}
