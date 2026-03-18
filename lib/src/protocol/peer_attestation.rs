use std::{error::Error, fmt};

use hacl_star::ed25519;
use serde::{Deserialize, Serialize};

use super::{AgentId, ClientId, PROTOCOL_VERSION, PeerAttestationMode, Role, SessionId};

pub const E2E_ATTESTATION_CONTEXT_V1: &str = "alaric-e2e-peer-attestation-v1";
pub const E2E_ATTESTATION_ALGORITHM_ED25519: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAttestationProof {
    pub protocol_version: u16,
    pub algorithm: String,
    pub session_id: SessionId,
    pub noise_handshake_hash: String,
    pub client_id: ClientId,
    pub agent_id: AgentId,
    pub signer_role: Role,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAttestationInit {
    pub client_id: ClientId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<PeerAttestationProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAttestationResult {
    pub accepted: bool,
    pub mode: PeerAttestationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_proof: Option<PeerAttestationProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl PeerAttestationResult {
    pub fn accepted(mode: PeerAttestationMode, agent_proof: Option<PeerAttestationProof>) -> Self {
        Self {
            accepted: true,
            mode,
            agent_proof,
            message: None,
        }
    }

    pub fn rejected(mode: PeerAttestationMode, message: impl Into<String>) -> Self {
        Self {
            accepted: false,
            mode,
            agent_proof: None,
            message: Some(message.into()),
        }
    }
}

#[derive(Debug, Serialize)]
struct PeerAttestationSigningPayload<'a> {
    context: &'static str,
    protocol_version: u16,
    algorithm: &'a str,
    session_id: &'a SessionId,
    noise_handshake_hash: &'a str,
    client_id: &'a ClientId,
    agent_id: &'a AgentId,
    signer_role: Role,
    signer_key_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAttestationError {
    InvalidSignerKeyId,
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

impl fmt::Display for PeerAttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAttestationError::InvalidSignerKeyId => {
                f.write_str("signer_key_id must not be empty")
            }
            PeerAttestationError::InvalidHex { field, message } => {
                write!(f, "{} is not valid hex: {}", field, message)
            }
            PeerAttestationError::InvalidLength {
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
            PeerAttestationError::Serialize(message) => {
                write!(
                    f,
                    "failed to serialize peer attestation payload: {}",
                    message
                )
            }
        }
    }
}

impl Error for PeerAttestationError {}

pub fn build_peer_attestation_proof(
    session_id: &SessionId,
    noise_handshake_hash: [u8; 32],
    client_id: &ClientId,
    agent_id: &AgentId,
    signer_role: Role,
    signer_key_id: &str,
    signer_private_key_hex: &str,
) -> Result<PeerAttestationProof, PeerAttestationError> {
    if signer_key_id.trim().is_empty() {
        return Err(PeerAttestationError::InvalidSignerKeyId);
    }

    let mut proof = PeerAttestationProof {
        protocol_version: PROTOCOL_VERSION,
        algorithm: E2E_ATTESTATION_ALGORITHM_ED25519.to_string(),
        session_id: *session_id,
        noise_handshake_hash: hex::encode(noise_handshake_hash),
        client_id: client_id.clone(),
        agent_id: agent_id.clone(),
        signer_role,
        signer_key_id: signer_key_id.to_string(),
        signature: String::new(),
    };

    let payload = signing_payload(&proof)?;
    let private_key_bytes = decode_hex_array::<{ ed25519::SECRET_LENGTH }>(
        "peer attestation private key",
        signer_private_key_hex,
    )?;
    let signature = ed25519::SecretKey(private_key_bytes).signature(&payload);
    proof.signature = hex::encode(signature.0);
    Ok(proof)
}

pub fn verify_peer_attestation_proof(
    proof: &PeerAttestationProof,
    expected_session_id: &SessionId,
    expected_noise_handshake_hash: [u8; 32],
    expected_client_id: &ClientId,
    expected_agent_id: &AgentId,
    expected_signer_role: Role,
    expected_signer_key_id: &str,
    public_key: [u8; ed25519::PUBLIC_LENGTH],
) -> Result<bool, PeerAttestationError> {
    if proof.protocol_version != PROTOCOL_VERSION {
        return Ok(false);
    }
    if proof.algorithm != E2E_ATTESTATION_ALGORITHM_ED25519 {
        return Ok(false);
    }
    if proof.session_id != *expected_session_id {
        return Ok(false);
    }
    if proof.noise_handshake_hash != hex::encode(expected_noise_handshake_hash) {
        return Ok(false);
    }
    if proof.client_id != *expected_client_id {
        return Ok(false);
    }
    if proof.agent_id != *expected_agent_id {
        return Ok(false);
    }
    if proof.signer_role != expected_signer_role {
        return Ok(false);
    }
    if proof.signer_key_id != expected_signer_key_id {
        return Ok(false);
    }

    let payload = signing_payload(proof)?;
    let signature_bytes = decode_hex_array::<{ ed25519::SIG_LENGTH }>(
        "peer attestation signature",
        &proof.signature,
    )?;
    let signature = ed25519::Signature(signature_bytes);
    Ok(ed25519::PublicKey(public_key).verify(&payload, &signature))
}

fn signing_payload(proof: &PeerAttestationProof) -> Result<Vec<u8>, PeerAttestationError> {
    serde_json::to_vec(&PeerAttestationSigningPayload {
        context: E2E_ATTESTATION_CONTEXT_V1,
        protocol_version: proof.protocol_version,
        algorithm: &proof.algorithm,
        session_id: &proof.session_id,
        noise_handshake_hash: &proof.noise_handshake_hash,
        client_id: &proof.client_id,
        agent_id: &proof.agent_id,
        signer_role: proof.signer_role,
        signer_key_id: &proof.signer_key_id,
    })
    .map_err(|source| PeerAttestationError::Serialize(source.to_string()))
}

fn decode_hex_array<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], PeerAttestationError> {
    let bytes = hex::decode(value).map_err(|source| PeerAttestationError::InvalidHex {
        field,
        message: source.to_string(),
    })?;
    if bytes.len() != N {
        return Err(PeerAttestationError::InvalidLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        AgentId, ClientId, Role, SessionId, build_peer_attestation_proof,
        verify_peer_attestation_proof,
    };

    const AGENT_PRIVATE_KEY_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const AGENT_PUBLIC_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn fixed_handshake_hash() -> [u8; 32] {
        [0x2a; 32]
    }

    #[test]
    fn attestation_round_trip_succeeds() {
        let session_id = SessionId::new_random();
        let client_id = ClientId::new("client-local").expect("client id should be valid");
        let agent_id = AgentId::new("agent-default").expect("agent id should be valid");
        let proof = build_peer_attestation_proof(
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            AGENT_PRIVATE_KEY_HEX,
        )
        .expect("proof build should succeed");

        let agent_public_key =
            hex::decode(AGENT_PUBLIC_KEY_HEX).expect("agent public key hex should decode");
        let mut agent_public_key_bytes = [0u8; 32];
        agent_public_key_bytes.copy_from_slice(&agent_public_key);
        let verified = verify_peer_attestation_proof(
            &proof,
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            agent_public_key_bytes,
        )
        .expect("verification should not error");
        assert!(verified);
    }

    #[test]
    fn attestation_replay_across_sessions_fails() {
        let session_id = SessionId::new_random();
        let other_session_id = SessionId::new_random();
        let client_id = ClientId::new("client-local").expect("client id should be valid");
        let agent_id = AgentId::new("agent-default").expect("agent id should be valid");
        let proof = build_peer_attestation_proof(
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            AGENT_PRIVATE_KEY_HEX,
        )
        .expect("proof build should succeed");

        let agent_public_key =
            hex::decode(AGENT_PUBLIC_KEY_HEX).expect("agent public key hex should decode");
        let mut agent_public_key_bytes = [0u8; 32];
        agent_public_key_bytes.copy_from_slice(&agent_public_key);
        let verified = verify_peer_attestation_proof(
            &proof,
            &other_session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            agent_public_key_bytes,
        )
        .expect("verification should not error");
        assert!(!verified);
    }

    #[test]
    fn attestation_with_wrong_handshake_hash_fails() {
        let session_id = SessionId::new_random();
        let client_id = ClientId::new("client-local").expect("client id should be valid");
        let agent_id = AgentId::new("agent-default").expect("agent id should be valid");
        let proof = build_peer_attestation_proof(
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            AGENT_PRIVATE_KEY_HEX,
        )
        .expect("proof build should succeed");

        let agent_public_key =
            hex::decode(AGENT_PUBLIC_KEY_HEX).expect("agent public key hex should decode");
        let mut agent_public_key_bytes = [0u8; 32];
        agent_public_key_bytes.copy_from_slice(&agent_public_key);
        let mut mismatched_hash = fixed_handshake_hash();
        mismatched_hash[0] ^= 0xff;
        let verified = verify_peer_attestation_proof(
            &proof,
            &session_id,
            mismatched_hash,
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            agent_public_key_bytes,
        )
        .expect("verification should not error");
        assert!(!verified);
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let session_id = SessionId::new_random();
        let client_id = ClientId::new("client-local").expect("client id should be valid");
        let agent_id = AgentId::new("agent-default").expect("agent id should be valid");
        let mut proof = build_peer_attestation_proof(
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            AGENT_PRIVATE_KEY_HEX,
        )
        .expect("proof build should succeed");
        proof.signature.replace_range(..2, "00");

        let agent_public_key =
            hex::decode(AGENT_PUBLIC_KEY_HEX).expect("agent public key hex should decode");
        let mut agent_public_key_bytes = [0u8; 32];
        agent_public_key_bytes.copy_from_slice(&agent_public_key);
        let verified = verify_peer_attestation_proof(
            &proof,
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            agent_public_key_bytes,
        )
        .expect("verification should not error");
        assert!(!verified);
    }

    #[test]
    fn attestation_with_wrong_expected_role_fails() {
        let session_id = SessionId::new_random();
        let client_id = ClientId::new("client-local").expect("client id should be valid");
        let agent_id = AgentId::new("agent-default").expect("agent id should be valid");
        let proof = build_peer_attestation_proof(
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Agent,
            "agent-default-v1",
            AGENT_PRIVATE_KEY_HEX,
        )
        .expect("proof build should succeed");

        let agent_public_key =
            hex::decode(AGENT_PUBLIC_KEY_HEX).expect("agent public key hex should decode");
        let mut agent_public_key_bytes = [0u8; 32];
        agent_public_key_bytes.copy_from_slice(&agent_public_key);
        let verified = verify_peer_attestation_proof(
            &proof,
            &session_id,
            fixed_handshake_hash(),
            &client_id,
            &agent_id,
            Role::Client,
            "agent-default-v1",
            agent_public_key_bytes,
        )
        .expect("verification should not error");
        assert!(!verified);
    }
}
