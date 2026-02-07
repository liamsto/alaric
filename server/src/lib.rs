use std::{
    collections::HashMap,
    error::Error,
    future::{Future, pending},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use lib::types::{
    AgentId, ClientId, HandshakeAccepted, HandshakeErrorCode, HandshakeRejected, HandshakeRequest,
    HandshakeResponse, PROTOCOL_VERSION, ProtocolError, SessionId, read_json_frame,
    write_json_frame,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{
        RwLock,
        mpsc::{Sender, channel},
    },
};
use tracing::{error, info, warn};

type AgentTx = Sender<Vec<u8>>;
type AgentRegistry = Arc<RwLock<HashMap<AgentId, AgentTx>>>;
type SessionCounter = Arc<AtomicU64>;

pub async fn run(listener: TcpListener) -> Result<(), Box<dyn Error + Send + Sync>> {
    run_until(listener, pending::<()>()).await
}

pub async fn run_until(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let local_addr = listener.local_addr()?;
    let agents: AgentRegistry = Arc::new(RwLock::new(HashMap::new()));
    let sessions: SessionCounter = Arc::new(AtomicU64::new(1));
    tokio::pin!(shutdown);

    info!("server listening on {}", local_addr);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received, stopping server accept loop");
                return Ok(());
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let agents = Arc::clone(&agents);
                        let sessions = Arc::clone(&sessions);
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, agents, sessions).await {
                                error!("connection handling failed: {}", err);
                            }
                        });
                    }
                    Err(err) => {
                        error!("accept error: {}", err);
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    agents: AgentRegistry,
    sessions: SessionCounter,
) -> Result<(), Box<dyn Error + Send + Sync>> {
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
            handle_agent(stream, agents, sessions, peer, agent_id).await
        }
        HandshakeRequest::Client {
            client_id,
            target_agent_id,
            ..
        } => handle_client(stream, agents, sessions, peer, client_id, target_agent_id).await,
    }
}

fn next_session_id(sessions: &AtomicU64) -> SessionId {
    SessionId(sessions.fetch_add(1, Ordering::Relaxed))
}

async fn send_accept(stream: &mut TcpStream, session_id: SessionId) -> Result<(), ProtocolError> {
    let response = HandshakeResponse::Accepted(HandshakeAccepted {
        protocol_version: PROTOCOL_VERSION,
        session_id,
    });
    write_json_frame(stream, &response).await
}

async fn send_reject(
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

async fn handle_agent(
    mut stream: TcpStream,
    agents: AgentRegistry,
    sessions: SessionCounter,
    peer: SocketAddr,
    agent_id: AgentId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (tx, mut rx) = channel::<Vec<u8>>(128);
    {
        let mut registry = agents.write().await;
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

    let session_id = next_session_id(sessions.as_ref());
    if let Err(err) = send_accept(&mut stream, session_id).await {
        agents.write().await.remove(&agent_id);
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

    agents.write().await.remove(&agent_id);
    info!("agent disconnected: {} (agent_id={})", peer, agent_id);
    Ok(())
}

async fn handle_client(
    mut stream: TcpStream,
    agents: AgentRegistry,
    sessions: SessionCounter,
    peer: SocketAddr,
    client_id: ClientId,
    target_agent_id: AgentId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !agents.read().await.contains_key(&target_agent_id) {
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

    let session_id = next_session_id(sessions.as_ref());
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

        let Some(agent_tx) = agents.read().await.get(&target_agent_id).cloned() else {
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
            agents.write().await.remove(&target_agent_id);
        }
    }
}
