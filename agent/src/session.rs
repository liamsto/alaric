use std::{error::Error, fmt};

use lib::{
    protocol::{
        ClientMessage, CommandProtocolError, SecureChannel, SecureChannelError, recv_secure_json,
    },
    security::noise::types::Keypair,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{executor::execute_request, policy::Policy};

#[derive(Debug)]
pub enum SessionError {
    Protocol(CommandProtocolError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Protocol(err) => write!(f, "protocol error: {}", err),
        }
    }
}

impl Error for SessionError {}

impl From<CommandProtocolError> for SessionError {
    fn from(value: CommandProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<SecureChannelError> for SessionError {
    fn from(value: SecureChannelError) -> Self {
        Self::Protocol(CommandProtocolError::from(value))
    }
}

pub async fn run_secure_session<S>(
    stream: &mut S,
    policy: &Policy,
    static_keypair: Keypair,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut secure = SecureChannel::handshake_xx_responder(stream, static_keypair).await?;
    let request = recv_secure_json::<_, ClientMessage>(&mut secure, stream).await?;

    match request {
        ClientMessage::Execute {
            request_id,
            command_id,
            args,
        } => {
            execute_request(&mut secure, stream, policy, request_id, &command_id, &args).await?;
        }
    }

    Ok(())
}
