use std::net::SocketAddr;

use crate::{
    error::BoxError,
    responses::{send_accept, send_challenge, send_reject},
    state::{ServerState, WaitingAgent},
};
use alaric_lib::protocol::{
    AgentId, ClientId, HandshakeErrorCode, HandshakeProofRequest, HandshakeRequest,
    PROTOCOL_VERSION, read_json_frame,
};
use tokio::{
    io::{AsyncReadExt, copy_bidirectional},
    net::TcpStream,
    sync::oneshot,
};
use tracing::{info, warn};

pub(crate) async fn handle_connection(
    mut stream: TcpStream,
    state: ServerState,
) -> Result<(), BoxError> {
    let peer = stream.peer_addr()?;
    let request = match read_json_frame::<_, HandshakeRequest>(&mut stream).await {
        Ok(request) => request,
        Err(err) => {
            warn!("invalid handshake from {}: {}", peer, err);
            let _ = send_reject(
                &mut stream,
                HandshakeErrorCode::InvalidRequest,
                format!("invalid handshake: {}", err),
            )
            .await;
            return Ok(());
        }
    };

    if request.protocol_version() != PROTOCOL_VERSION {
        send_reject(
            &mut stream,
            HandshakeErrorCode::UnsupportedProtocolVersion,
            format!(
                "server protocol version is {}, got {}",
                PROTOCOL_VERSION,
                request.protocol_version()
            ),
        )
        .await?;
        return Ok(());
    }

    let challenge = match state.authenticator.issue_challenge(&request).await {
        Ok(challenge) => challenge,
        Err(err) => {
            send_reject(
                &mut stream,
                HandshakeErrorCode::Unauthorized,
                format!("handshake authentication failed: {}", err),
            )
            .await?;
            warn!("rejected unauthorized handshake from {}: {}", peer, err);
            return Ok(());
        }
    };

    send_challenge(&mut stream, challenge.clone()).await?;

    let proof_request = match read_json_frame::<_, HandshakeProofRequest>(&mut stream).await {
        Ok(proof_request) => proof_request,
        Err(err) => {
            send_reject(
                &mut stream,
                HandshakeErrorCode::InvalidRequest,
                format!("invalid auth proof request: {}", err),
            )
            .await?;
            warn!("invalid auth proof request from {}: {}", peer, err);
            return Ok(());
        }
    };

    if let Err(err) = state
        .authenticator
        .authenticate(&request, &challenge, &proof_request)
        .await
    {
        send_reject(
            &mut stream,
            HandshakeErrorCode::Unauthorized,
            format!("handshake authentication failed: {}", err),
        )
        .await?;
        warn!("rejected unauthorized handshake from {}: {}", peer, err);
        return Ok(());
    }

    match request {
        HandshakeRequest::Agent { agent_id, .. } => {
            handle_agent(stream, state, peer, agent_id).await
        }
        HandshakeRequest::Client {
            client_id,
            target_agent_id,
            ..
        } => handle_client(stream, state, peer, client_id, target_agent_id).await,
    }
}

async fn handle_agent(
    mut stream: TcpStream,
    state: ServerState,
    peer: SocketAddr,
    agent_id: AgentId,
) -> Result<(), BoxError> {
    let session_id = state.next_session_id();
    let (tx, mut rx) = oneshot::channel::<TcpStream>();
    {
        let mut registry = state.agents.write().await;
        if registry.contains_key(&agent_id) {
            send_reject(
                &mut stream,
                HandshakeErrorCode::AgentIdInUse,
                format!("agent id '{}' is already connected", agent_id),
            )
            .await?;
            warn!(
                "rejected agent {} from {}: id already in use",
                agent_id, peer
            );
            return Ok(());
        }
        registry.insert(
            agent_id.clone(),
            WaitingAgent {
                session_id,
                waiter: tx,
            },
        );
    }

    if let Err(err) = send_accept(&mut stream, session_id).await {
        state.agents.write().await.remove(&agent_id);
        return Err(Box::new(err));
    }
    info!(
        "agent connected: {} (agent_id={}, session_id={}); waiting for client",
        peer, agent_id, session_id
    );

    let mut probe = [0u8; 1];
    let mut client_stream = tokio::select! {
        matched = &mut rx => {
            match matched {
                Ok(client_stream) => client_stream,
                Err(_) => {
                    state.agents.write().await.remove(&agent_id);
                    info!(
                        "agent {} from {} disconnected before client pairing",
                        agent_id, peer
                    );
                    return Ok(());
                }
            }
        }
        read_result = stream.read(&mut probe) => {
            match read_result {
                Ok(0) => {
                    info!(
                        "agent {} from {} disconnected before client pairing",
                        agent_id, peer
                    );
                }
                Ok(_) => {
                    warn!(
                        "agent {} from {} sent data before client pairing; closing connection",
                        agent_id, peer
                    );
                }
                Err(err) => {
                    warn!(
                        "error while waiting for agent {} from {}: {}",
                        agent_id, peer, err
                    );
                }
            }
            state.agents.write().await.remove(&agent_id);
            return Ok(());
        }
    };

    info!("paired client tunnel with agent {} from {}", agent_id, peer);
    match copy_bidirectional(&mut stream, &mut client_stream).await {
        Ok((agent_to_client, client_to_agent)) => {
            info!(
                "tunnel closed for agent {}: {} bytes agent->client, {} bytes client->agent",
                agent_id, agent_to_client, client_to_agent
            );
        }
        Err(err) => {
            warn!("tunnel I/O error for agent {}: {}", agent_id, err);
        }
    }

    state.agents.write().await.remove(&agent_id);
    info!("agent disconnected: {} (agent_id={})", peer, agent_id);
    Ok(())
}

async fn handle_client(
    mut stream: TcpStream,
    state: ServerState,
    peer: SocketAddr,
    client_id: ClientId,
    target_agent_id: AgentId,
) -> Result<(), BoxError> {
    let Some(waiting_agent) = state.agents.write().await.remove(&target_agent_id) else {
        send_reject(
            &mut stream,
            HandshakeErrorCode::AgentUnavailable,
            format!("target agent '{}' is not connected", target_agent_id),
        )
        .await?;
        warn!(
            "rejected client {} from {}: target agent {} unavailable",
            client_id, peer, target_agent_id
        );
        return Ok(());
    };

    let WaitingAgent {
        session_id,
        waiter: agent_waiter,
    } = waiting_agent;

    if let Err(err) = send_accept(&mut stream, session_id).await {
        state.agents.write().await.insert(
            target_agent_id.clone(),
            WaitingAgent {
                session_id,
                waiter: agent_waiter,
            },
        );
        return Err(Box::new(err));
    }

    info!(
        "client connected: {} (client_id={}, target_agent_id={}, session_id={})",
        peer, client_id, target_agent_id, session_id
    );

    if let Err(stream) = agent_waiter.send(stream) {
        drop(stream);
        warn!(
            "failed to pair client {} from {} with agent {}: agent no longer waiting",
            client_id, peer, target_agent_id
        );
    }

    Ok(())
}
