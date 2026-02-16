use std::{error::Error, fmt};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::security::noise::{
    consts::{DHLEN, MAC_LENGTH},
    error::NoiseError,
    noisesession::NoiseSession,
    types::Keypair,
};

use super::{MAX_FRAME_BYTES, ProtocolError, read_bytes_frame, write_bytes_frame};

pub const NOISE_PROLOGUE: &[u8] = b"alaric/noise-xx-v1";
pub const NOISE_HANDSHAKE_MSG_A_LEN: usize = DHLEN + MAC_LENGTH;
pub const NOISE_HANDSHAKE_MSG_B_LEN: usize = (2 * DHLEN) + (2 * MAC_LENGTH);
pub const NOISE_HANDSHAKE_MSG_C_LEN: usize = DHLEN + (2 * MAC_LENGTH);

#[derive(Debug)]
pub enum SecureChannelError {
    Protocol(ProtocolError),
    Noise(NoiseError),
    InvalidHandshakeMessageLength {
        step: &'static str,
        expected: usize,
        got: usize,
    },
    TransportMessageTooLarge(usize),
    TransportFrameTooSmall(usize),
    HandshakeIncomplete,
}

impl fmt::Display for SecureChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecureChannelError::Protocol(err) => write!(f, "protocol error: {}", err),
            SecureChannelError::Noise(err) => write!(f, "noise error: {}", err),
            SecureChannelError::InvalidHandshakeMessageLength {
                step,
                expected,
                got,
            } => write!(
                f,
                "invalid Noise XX message length at {}: expected {} bytes, got {}",
                step, expected, got
            ),
            SecureChannelError::TransportMessageTooLarge(len) => write!(
                f,
                "transport message is {} bytes before MAC, above configured maximum {}",
                len,
                MAX_FRAME_BYTES.saturating_sub(MAC_LENGTH)
            ),
            SecureChannelError::TransportFrameTooSmall(len) => {
                write!(f, "received transport frame too small for MAC: {}", len)
            }
            SecureChannelError::HandshakeIncomplete => {
                f.write_str("noise handshake completed without entering transport mode")
            }
        }
    }
}

impl Error for SecureChannelError {}

impl From<ProtocolError> for SecureChannelError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<NoiseError> for SecureChannelError {
    fn from(value: NoiseError) -> Self {
        Self::Noise(value)
    }
}

pub struct SecureChannel {
    session: NoiseSession,
}

impl SecureChannel {
    pub async fn handshake_xx_initiator<S>(
        stream: &mut S,
        static_keypair: Keypair,
    ) -> Result<Self, SecureChannelError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut session = NoiseSession::init_session(true, NOISE_PROLOGUE, static_keypair);

        let mut msg_a = vec![0u8; NOISE_HANDSHAKE_MSG_A_LEN];
        session.send_message(&mut msg_a)?;
        write_bytes_frame(stream, &msg_a).await?;

        let mut msg_b = read_bytes_frame(stream).await?;
        validate_handshake_len("message_b", &msg_b, NOISE_HANDSHAKE_MSG_B_LEN)?;
        session.recv_message(&mut msg_b)?;

        let mut msg_c = vec![0u8; NOISE_HANDSHAKE_MSG_C_LEN];
        session.send_message(&mut msg_c)?;
        write_bytes_frame(stream, &msg_c).await?;

        Self::from_transport_session(session)
    }

    pub async fn handshake_xx_responder<S>(
        stream: &mut S,
        static_keypair: Keypair,
    ) -> Result<Self, SecureChannelError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut session = NoiseSession::init_session(false, NOISE_PROLOGUE, static_keypair);

        let mut msg_a = read_bytes_frame(stream).await?;
        validate_handshake_len("message_a", &msg_a, NOISE_HANDSHAKE_MSG_A_LEN)?;
        session.recv_message(&mut msg_a)?;

        let mut msg_b = vec![0u8; NOISE_HANDSHAKE_MSG_B_LEN];
        session.send_message(&mut msg_b)?;
        write_bytes_frame(stream, &msg_b).await?;

        let mut msg_c = read_bytes_frame(stream).await?;
        validate_handshake_len("message_c", &msg_c, NOISE_HANDSHAKE_MSG_C_LEN)?;
        session.recv_message(&mut msg_c)?;

        Self::from_transport_session(session)
    }

    pub async fn send<S>(
        &mut self,
        stream: &mut S,
        plaintext: &[u8],
    ) -> Result<(), SecureChannelError>
    where
        S: AsyncWrite + Unpin,
    {
        let frame_len = plaintext.len().checked_add(MAC_LENGTH).ok_or(
            SecureChannelError::TransportMessageTooLarge(plaintext.len()),
        )?;

        if frame_len > MAX_FRAME_BYTES {
            return Err(SecureChannelError::TransportMessageTooLarge(
                plaintext.len(),
            ));
        }

        let mut in_out = vec![0u8; frame_len];
        in_out[..plaintext.len()].copy_from_slice(plaintext);
        self.session.send_message(&mut in_out)?;
        write_bytes_frame(stream, &in_out).await?;
        Ok(())
    }

    pub async fn recv<S>(&mut self, stream: &mut S) -> Result<Vec<u8>, SecureChannelError>
    where
        S: AsyncRead + Unpin,
    {
        let mut in_out = read_bytes_frame(stream).await?;
        if in_out.len() < MAC_LENGTH {
            return Err(SecureChannelError::TransportFrameTooSmall(in_out.len()));
        }
        self.session.recv_message(&mut in_out)?;
        in_out.truncate(in_out.len() - MAC_LENGTH);
        Ok(in_out)
    }

    fn from_transport_session(session: NoiseSession) -> Result<Self, SecureChannelError> {
        if !session.is_transport() {
            return Err(SecureChannelError::HandshakeIncomplete);
        }

        Ok(Self { session })
    }
}

fn validate_handshake_len(
    step: &'static str,
    frame: &[u8],
    expected: usize,
) -> Result<(), SecureChannelError> {
    if frame.len() != expected {
        return Err(SecureChannelError::InvalidHandshakeMessageLength {
            step,
            expected,
            got: frame.len(),
        });
    }
    Ok(())
}
