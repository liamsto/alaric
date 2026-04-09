use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    error::BoxError,
    responses::{send_accept, send_challenge, send_reject},
    state::{ServerState, WaitingAgent},
};
use alaric_lib::database::Database;
use alaric_lib::protocol::{
    AgentId, ClientId, HandshakeErrorCode, HandshakeProofRequest, HandshakeRequest,
    ListAgentsResponse, PROTOCOL_VERSION, SessionId, read_json_frame, write_json_frame,
};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, copy_bidirectional},
    net::TcpStream,
    sync::{oneshot, watch},
    time::{Duration, MissedTickBehavior, interval},
};
use tracing::{info, warn};

const PRESENCE_HEARTBEAT_INTERVAL_SECS: u64 = 10;

pub async fn handle_connection(mut stream: TcpStream, state: ServerState) -> Result<(), BoxError> {
    let peer = stream.peer_addr()?;
    let request = match read_json_frame::<_, HandshakeRequest>(&mut stream).await {
        Ok(request) => request,
        Err(err) => {
            if let Err(store_err) = &state
                .database
                .record_session_rejection(
                    SessionId::new_random(),
                    None,
                    HandshakeErrorCode::InvalidRequest,
                    &format!("invalid handshake: {}", err),
                    peer,
                )
                .await
            {
                warn!(
                    "failed to persist invalid handshake rejection: {}",
                    store_err
                );
            }
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
        if let Err(store_err) = &state
            .database
            .record_session_rejection(
                SessionId::new_random(),
                Some(&request),
                HandshakeErrorCode::UnsupportedProtocolVersion,
                &format!(
                    "server protocol version is {}, got {}",
                    PROTOCOL_VERSION,
                    request.protocol_version()
                ),
                peer,
            )
            .await
        {
            warn!(
                "failed to persist protocol-version rejection: {}",
                store_err
            );
        }
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

    let authenticator = state.authenticator_snapshot().await;
    let challenge = match authenticator.issue_challenge(&request).await {
        Ok(challenge) => challenge,
        Err(err) => {
            if let Err(store_err) = &state
                .database
                .record_session_rejection(
                    SessionId::new_random(),
                    Some(&request),
                    HandshakeErrorCode::Unauthorized,
                    &format!("handshake authentication failed: {}", err),
                    peer,
                )
                .await
            {
                warn!(
                    "failed to persist challenge issuance rejection: {}",
                    store_err
                );
            }
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
            if let Err(store_err) = &state
                .database
                .record_session_rejection(
                    SessionId::new_random(),
                    Some(&request),
                    HandshakeErrorCode::InvalidRequest,
                    &format!("invalid auth proof request: {}", err),
                    peer,
                )
                .await
            {
                warn!("failed to persist auth-proof rejection: {}", store_err);
            }
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

    if let Err(err) = authenticator
        .authenticate(&request, &challenge, &proof_request)
        .await
    {
        if let Err(store_err) = &state
            .database
            .record_session_rejection(
                SessionId::new_random(),
                Some(&request),
                HandshakeErrorCode::Unauthorized,
                &format!("handshake authentication failed: {}", err),
                peer,
            )
            .await
        {
            warn!("failed to persist unauthorized rejection: {}", store_err);
        }
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
        HandshakeRequest::Agent {
            agent_id, metadata, ..
        } => handle_agent(stream, state, peer, agent_id, metadata).await,
        HandshakeRequest::Client {
            client_id,
            target_agent_id,
            ..
        } => handle_client(stream, state, peer, client_id, target_agent_id).await,
        HandshakeRequest::ClientDiscovery { client_id, .. } => {
            handle_client_discovery(stream, state, peer, client_id).await
        }
    }
}

async fn handle_agent(
    mut stream: TcpStream,
    state: ServerState,
    peer: SocketAddr,
    agent_id: AgentId,
    handshake_metadata: BTreeMap<String, String>,
) -> Result<(), BoxError> {
    let session_id = state.next_session_id();
    let agent_request = HandshakeRequest::agent(agent_id.clone());
    let presence_metadata = build_presence_metadata(&handshake_metadata);
    let (tx, mut rx) = oneshot::channel::<TcpStream>();
    let duplicate_agent = {
        let mut registry = state.agents.write().await;
        if registry.contains_key(&agent_id) {
            true
        } else {
            registry.insert(
                agent_id.clone(),
                WaitingAgent {
                    session_id,
                    waiter: tx,
                },
            );
            false
        }
    };

    if duplicate_agent {
        if let Err(store_err) = &state
            .database
            .record_session_rejection(
                SessionId::new_random(),
                Some(&agent_request),
                HandshakeErrorCode::AgentIdInUse,
                &format!("agent id '{}' is already connected", agent_id),
                peer,
            )
            .await
        {
            warn!("failed to persist duplicate-agent rejection: {}", store_err);
        }
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

    if let Err(err) = send_accept(&mut stream, session_id).await {
        state.agents.write().await.remove(&agent_id);
        return Err(Box::new(err));
    }
    if let Err(store_err) = &state
        .database
        .record_agent_waiting(session_id, &agent_id, &presence_metadata, peer)
        .await
    {
        warn!("failed to persist agent waiting state: {}", store_err);
    }
    let heartbeat_shutdown =
        spawn_presence_heartbeat(state.database.clone(), session_id, agent_id.clone());
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
                    if let Err(store_err) = &state.database
                            .record_agent_disconnected(
                                session_id,
                                &agent_id,
                                "agent disconnected before client pairing",
                                true,
                            )
                            .await
                        {
                            warn!("failed to persist agent disconnect: {}", store_err);
                        }
                    info!(
                        "agent {} from {} disconnected before client pairing",
                        agent_id, peer
                    );
                    stop_presence_heartbeat(&heartbeat_shutdown);
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
            if let Err(store_err) = &state.database
                    .record_agent_disconnected(
                        session_id,
                        &agent_id,
                        "agent disconnected before client pairing",
                        true,
                    )
                    .await
                {
                    warn!("failed to persist pre-pairing disconnect: {}", store_err);
                }
            stop_presence_heartbeat(&heartbeat_shutdown);
            return Ok(());
        }
    };

    info!("paired client tunnel with agent {} from {}", agent_id, peer);
    let tunnel_result = copy_bidirectional(&mut stream, &mut client_stream).await;
    match &tunnel_result {
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

    stop_presence_heartbeat(&heartbeat_shutdown);
    state.agents.write().await.remove(&agent_id);
    let mark_disconnect_as_error = tunnel_result.is_err();
    if let Err(store_err) = &state
        .database
        .record_agent_disconnected(
            session_id,
            &agent_id,
            "agent disconnected",
            mark_disconnect_as_error,
        )
        .await
    {
        warn!("failed to persist agent disconnection: {}", store_err);
    }
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
    let client_request = HandshakeRequest::client(client_id.clone(), target_agent_id.clone());
    let Some(waiting_agent) = state.agents.write().await.remove(&target_agent_id) else {
        if let Err(store_err) = &state
            .database
            .record_session_rejection(
                SessionId::new_random(),
                Some(&client_request),
                HandshakeErrorCode::AgentUnavailable,
                &format!("target agent '{}' is not connected", target_agent_id),
                peer,
            )
            .await
        {
            warn!(
                "failed to persist unavailable-agent rejection: {}",
                store_err
            );
        }
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

    if let Err(store_err) = &state
        .database
        .record_client_pairing(session_id, &client_id, &target_agent_id, peer)
        .await
    {
        warn!("failed to persist client pairing: {}", store_err);
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

async fn handle_client_discovery(
    mut stream: TcpStream,
    state: ServerState,
    peer: SocketAddr,
    client_id: ClientId,
) -> Result<(), BoxError> {
    let discovery_request = HandshakeRequest::client_discovery(client_id.clone());
    let database = &state.database;

    let agents = match database.list_discoverable_agents().await {
        Ok(agents) => agents,
        Err(err) => {
            warn!("failed to load discoverable agents: {}", err);
            if let Err(store_err) = database
                .record_session_rejection(
                    SessionId::new_random(),
                    Some(&discovery_request),
                    HandshakeErrorCode::InternalError,
                    &format!("failed to list agents: {}", err),
                    peer,
                )
                .await
            {
                warn!("failed to persist discovery-list rejection: {}", store_err);
            }
            send_reject(
                &mut stream,
                HandshakeErrorCode::InternalError,
                "failed to list agents",
            )
            .await?;
            return Ok(());
        }
    };

    let groups = match database.list_discoverable_agent_groups().await {
        Ok(groups) => groups,
        Err(err) => {
            warn!("failed to load discoverable agent groups: {}", err);
            if let Err(store_err) = database
                .record_session_rejection(
                    SessionId::new_random(),
                    Some(&discovery_request),
                    HandshakeErrorCode::InternalError,
                    &format!("failed to list agent groups: {}", err),
                    peer,
                )
                .await
            {
                warn!("failed to persist discovery-group rejection: {}", store_err);
            }
            send_reject(
                &mut stream,
                HandshakeErrorCode::InternalError,
                "failed to list agent groups",
            )
            .await?;
            return Ok(());
        }
    };

    let (discovered_agents, discovered_groups) = (agents, groups);

    let session_id = state.next_session_id();
    send_accept(&mut stream, session_id).await?;

    if let Err(store_err) = state
        .database
        .record_client_discovery(session_id, &client_id, peer)
        .await
    {
        warn!("failed to persist client discovery session: {}", store_err);
    }

    let response = ListAgentsResponse::new(
        current_unix_timestamp()?,
        discovered_agents,
        discovered_groups,
    );
    write_json_frame(&mut stream, &response).await?;
    info!(
        "client discovery completed: {} (client_id={}, session_id={}, agents={})",
        peer,
        client_id,
        session_id,
        response.agents.len()
    );
    Ok(())
}

fn spawn_presence_heartbeat(
    database: Arc<Database>,
    session_id: SessionId,
    agent_id: AgentId,
) -> Option<watch::Sender<bool>> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(PRESENCE_HEARTBEAT_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = database.record_agent_heartbeat(session_id, &agent_id).await {
                        warn!("failed to persist agent heartbeat (agent_id={}): {}", agent_id, err);
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
    Some(shutdown_tx)
}

fn stop_presence_heartbeat(shutdown: &Option<watch::Sender<bool>>) {
    if let Some(shutdown) = shutdown {
        let _ = shutdown.send(true);
    }
}

fn build_presence_metadata(handshake_metadata: &BTreeMap<String, String>) -> Value {
    let capabilities = parse_csv_metadata(handshake_metadata.get("capabilities"));
    let tags = parse_csv_metadata(handshake_metadata.get("tags"));

    serde_json::json!({
        "capabilities": capabilities,
        "tags": tags,
    })
}

fn parse_csv_metadata(raw: Option<&String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    if let Some(raw) = raw {
        for value in raw.split(',') {
            let value = value.trim();
            if !value.is_empty() {
                out.insert(value.to_string());
            }
        }
    }

    out.into_iter().collect()
}

fn current_unix_timestamp() -> Result<u64, BoxError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
