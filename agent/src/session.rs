use std::{error::Error, fmt};

use alaric_lib::{
    protocol::{
        AgentId, ClientMessage, CommandProtocolError, IdentityBundle, PeerAttestationError,
        PeerAttestationInit, PeerAttestationMode, PeerAttestationPolicy, PeerAttestationResult,
        Role, SecureChannel, SecureChannelError, SessionId, build_peer_attestation_proof,
        recv_secure_json, send_secure_json, verify_peer_attestation_proof,
    },
    security::noise::types::Keypair,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{executor::execute_request, policy::Policy};

#[derive(Debug)]
pub enum SessionError {
    Protocol(CommandProtocolError),
    Attestation(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Protocol(err) => write!(f, "protocol error: {}", err),
            SessionError::Attestation(message) => write!(f, "attestation error: {}", message),
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

impl From<PeerAttestationError> for SessionError {
    fn from(value: PeerAttestationError) -> Self {
        Self::Attestation(value.to_string())
    }
}

pub async fn run_secure_session<S>(
    stream: &mut S,
    policy: &Policy,
    static_keypair: Keypair,
    session_id: SessionId,
    agent_id: &AgentId,
    auth_key_id: &str,
    auth_private_key: &str,
    attestation_policy: &PeerAttestationPolicy,
    identity_bundle: Option<&IdentityBundle>,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut secure = SecureChannel::handshake_xx_responder(stream, static_keypair).await?;
    perform_peer_attestation(
        &mut secure,
        stream,
        &session_id,
        agent_id,
        auth_key_id,
        auth_private_key,
        attestation_policy,
        identity_bundle,
    )
    .await?;

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

async fn perform_peer_attestation<S>(
    secure: &mut SecureChannel,
    stream: &mut S,
    session_id: &SessionId,
    agent_id: &AgentId,
    auth_key_id: &str,
    auth_private_key: &str,
    attestation_policy: &PeerAttestationPolicy,
    identity_bundle: Option<&IdentityBundle>,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake_hash = secure.handshake_hash();
    let init = recv_secure_json::<_, PeerAttestationInit>(secure, stream).await?;
    if let Some(client_proof) = &init.proof
        && client_proof.client_id != init.client_id
    {
        let message = format!(
            "client attestation init id '{}' does not match proof id '{}'",
            init.client_id, client_proof.client_id
        );
        send_secure_json(
            secure,
            stream,
            &PeerAttestationResult::rejected(PeerAttestationMode::Required, message.clone()),
        )
        .await?;
        return Err(SessionError::Attestation(message));
    }

    let mode = attestation_policy.resolve(&init.client_id, agent_id);
    if mode == PeerAttestationMode::Disabled {
        send_secure_json(secure, stream, &PeerAttestationResult::accepted(mode, None)).await?;
        return Ok(());
    }

    let Some(client_proof) = init.proof else {
        if mode.requires_attestation() {
            let message = format!(
                "peer attestation is required for client '{}' and agent '{}'",
                init.client_id, agent_id
            );
            send_secure_json(
                secure,
                stream,
                &PeerAttestationResult::rejected(mode, message.clone()),
            )
            .await?;
            return Err(SessionError::Attestation(message));
        }

        send_secure_json(secure, stream, &PeerAttestationResult::accepted(mode, None)).await?;
        return Ok(());
    };

    if client_proof.signer_role != Role::Client {
        let message = format!(
            "expected client attestation proof first, got role '{}'",
            client_proof.signer_role
        );
        send_secure_json(
            secure,
            stream,
            &PeerAttestationResult::rejected(mode, message.clone()),
        )
        .await?;
        return Err(SessionError::Attestation(message));
    }
    if client_proof.agent_id != *agent_id {
        let message = format!(
            "client proof agent id '{}' does not match connected agent '{}'",
            client_proof.agent_id, agent_id
        );
        send_secure_json(
            secure,
            stream,
            &PeerAttestationResult::rejected(mode, message.clone()),
        )
        .await?;
        return Err(SessionError::Attestation(message));
    }

    let Some(identity_bundle) = identity_bundle else {
        if mode.requires_attestation() {
            let message =
                "peer attestation is required but no identity bundle is loaded".to_string();
            send_secure_json(
                secure,
                stream,
                &PeerAttestationResult::rejected(mode, message.clone()),
            )
            .await?;
            return Err(SessionError::Attestation(message));
        }

        send_secure_json(secure, stream, &PeerAttestationResult::accepted(mode, None)).await?;
        return Ok(());
    };

    let Some(client_identity) = identity_bundle.client_identity_key(&client_proof.client_id) else {
        if mode.requires_attestation() {
            let message = format!(
                "identity bundle does not contain key material for client '{}'",
                client_proof.client_id
            );
            send_secure_json(
                secure,
                stream,
                &PeerAttestationResult::rejected(mode, message.clone()),
            )
            .await?;
            return Err(SessionError::Attestation(message));
        }

        send_secure_json(secure, stream, &PeerAttestationResult::accepted(mode, None)).await?;
        return Ok(());
    };
    let verified = verify_peer_attestation_proof(
        &client_proof,
        session_id,
        handshake_hash,
        &client_proof.client_id,
        agent_id,
        Role::Client,
        &client_identity.key_id,
        client_identity.public_key,
    )?;
    if !verified {
        let message = format!(
            "failed to verify client peer attestation for '{}'",
            client_proof.client_id
        );
        send_secure_json(
            secure,
            stream,
            &PeerAttestationResult::rejected(mode, message.clone()),
        )
        .await?;
        return Err(SessionError::Attestation(message));
    }

    let agent_proof = build_peer_attestation_proof(
        session_id,
        handshake_hash,
        &client_proof.client_id,
        agent_id,
        Role::Agent,
        auth_key_id,
        auth_private_key,
    )?;
    send_secure_json(
        secure,
        stream,
        &PeerAttestationResult::accepted(mode, Some(agent_proof)),
    )
    .await?;
    Ok(())
}
