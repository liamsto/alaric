use lib::protocol::{
    HandshakeAccepted, HandshakeErrorCode, HandshakeRejected, HandshakeResponse, PROTOCOL_VERSION,
    ProtocolError, SessionId, write_json_frame,
};
use tokio::net::TcpStream;

pub(crate) async fn send_accept(
    stream: &mut TcpStream,
    session_id: SessionId,
) -> Result<(), ProtocolError> {
    let response = HandshakeResponse::Accepted(HandshakeAccepted {
        protocol_version: PROTOCOL_VERSION,
        session_id,
    });
    write_json_frame(stream, &response).await
}

pub(crate) async fn send_reject(
    stream: &mut TcpStream,
    code: HandshakeErrorCode,
    message: impl Into<String>,
) -> Result<(), ProtocolError> {
    let response = HandshakeResponse::Rejected(HandshakeRejected {
        protocol_version: PROTOCOL_VERSION,
        code,
        message: message.into(),
    });
    write_json_frame(stream, &response).await
}
