use std::net::SocketAddr;

use crate::{
    error::BoxError,
    responses::{send_accept, send_reject},
    state::ServerState,
};
use lib::types::{
    AgentId, ClientId, HandshakeErrorCode, HandshakeRequest, PROTOCOL_VERSION, read_json_frame,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::channel,
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
    let (tx, mut rx) = channel::<Vec<u8>>(128);
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
        registry.insert(agent_id.clone(), tx);
    }

    let session_id = state.next_session_id();
    if let Err(err) = send_accept(&mut stream, session_id).await {
        state.agents.write().await.remove(&agent_id);
        return Err(Box::new(err));
    }

    info!(
        "agent connected: {} (agent_id={}, session_id={})",
        peer, agent_id, session_id.0
    );

    while let Some(bytes) = rx.recv().await {
        if let Err(err) = stream.write_all(&bytes).await {
            warn!("agent {} stream closed: {}", agent_id, err);
            break;
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
    if !state.agents.read().await.contains_key(&target_agent_id) {
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
    }

    let session_id = state.next_session_id();
    send_accept(&mut stream, session_id).await?;
    info!(
        "client connected: {} (client_id={}, target_agent_id={}, session_id={})",
        peer, client_id, target_agent_id, session_id.0
    );

    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            info!(
                "client disconnected: {} (client_id={}, target_agent_id={})",
                peer, client_id, target_agent_id
            );
            return Ok(());
        }

        let Some(agent_tx) = state.agents.read().await.get(&target_agent_id).cloned() else {
            warn!(
                "dropping {} bytes from client {}: target agent {} unavailable",
                n, client_id, target_agent_id
            );
            continue;
        };

        if agent_tx.send(buf[..n].to_vec()).await.is_err() {
            warn!(
                "dropping {} bytes from client {}: target agent {} channel closed",
                n, client_id, target_agent_id
            );
            state.agents.write().await.remove(&target_agent_id);
        }
    }
}
