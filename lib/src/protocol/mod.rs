mod attestation_policy;
mod commands;
mod discovery;
mod framing;
mod handshake;
mod identity;
mod ids;
mod peer_attestation;
mod secure;

pub use attestation_policy::{
    PairAttestationMode, PeerAttestationMode, PeerAttestationPolicy, PeerAttestationPolicyConfig,
    PeerAttestationPolicyError, PrincipalAttestationModes,
};
pub use commands::{
    AgentMessage, ClientMessage, CommandId, CommandIdError, CommandProtocolError, OutputStream,
    RejectionCode, RequestId, recv_secure_json, send_secure_json,
};
pub use discovery::{
    AgentDiscoveryEntry, AgentGroupDiscoveryEntry, AgentPresenceStatus, ListAgentsResponse,
};
pub use framing::{
    MAX_FRAME_BYTES, ProtocolError, read_bytes_frame, read_json_frame, write_bytes_frame,
    write_json_frame,
};
pub use handshake::{
    AUTH_METHOD_ED25519_CHALLENGE_V1, AuthCryptoError, AuthProof, HandshakeAccepted,
    HandshakeChallenge, HandshakeErrorCode, HandshakeProofRequest, HandshakeRejected,
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, Role, build_auth_proof_ed25519,
    decode_ed25519_public_key, verify_auth_proof_ed25519,
};
pub use identity::{
    IDENTITY_BUNDLE_SIGNATURE_ALGORITHM_ED25519, IDENTITY_BUNDLE_VERSION_V1, IdentityBundle,
    IdentityBundleError, IdentityBundleSignature, IdentityPrincipal, IdentityPublicKey,
    SignedIdentityBundle, TrustedIdentityKeys, sign_identity_bundle_ed25519,
};
pub use ids::{AgentGroupId, AgentId, ClientId, IdError, SessionId};
pub use peer_attestation::{
    E2E_ATTESTATION_ALGORITHM_ED25519, E2E_ATTESTATION_CONTEXT_V1, PeerAttestationError,
    PeerAttestationInit, PeerAttestationProof, PeerAttestationResult, build_peer_attestation_proof,
    verify_peer_attestation_proof,
};
pub use secure::{
    NOISE_HANDSHAKE_MSG_A_LEN, NOISE_HANDSHAKE_MSG_B_LEN, NOISE_HANDSHAKE_MSG_C_LEN,
    NOISE_PROLOGUE, SecureChannel, SecureChannelError,
};

#[cfg(test)]
mod tests {
    use super::{AgentGroupId, AgentId, ClientId, HandshakeRequest};

    #[test]
    fn agent_id_validation_rejects_invalid_chars() {
        assert!(AgentId::new("agent id").is_err());
    }

    #[test]
    fn client_id_validation_accepts_valid_chars() {
        assert!(ClientId::new("client_001.prod").is_ok());
    }

    #[test]
    fn agent_group_id_validation_accepts_valid_chars() {
        assert!(AgentGroupId::new("ca-west-prod01").is_ok());
    }

    #[test]
    fn handshake_helpers_set_expected_role() {
        let agent_id = AgentId::new("agent-main").expect("valid agent id");
        let request = HandshakeRequest::agent(agent_id);
        assert_eq!(request.role().as_str(), "agent");
    }

    #[test]
    fn client_discovery_helpers_set_expected_role() {
        let client_id = ClientId::new("client-main").expect("valid client id");
        let request = HandshakeRequest::client_discovery(client_id);
        assert_eq!(request.role().as_str(), "client");
    }
}
