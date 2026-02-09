mod framing;
mod handshake;
mod ids;
mod secure;

pub use framing::{
    MAX_FRAME_BYTES, ProtocolError, read_bytes_frame, read_json_frame, write_bytes_frame,
    write_json_frame,
};
pub use handshake::{
    AuthRequest, HandshakeAccepted, HandshakeErrorCode, HandshakeRejected, HandshakeRequest,
    HandshakeResponse, PROTOCOL_VERSION, Role,
};
pub use ids::{AgentId, ClientId, IdError, SessionId};
pub use secure::{
    NOISE_HANDSHAKE_MSG_A_LEN, NOISE_HANDSHAKE_MSG_B_LEN, NOISE_HANDSHAKE_MSG_C_LEN,
    NOISE_PROLOGUE, SecureChannel, SecureChannelError,
};

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
