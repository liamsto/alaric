use std::net::SocketAddr;
use std::{collections::HashMap, error::Error, time::Duration};

use alaric_lib::protocol::{
    AgentId, AuthRequest, ClientId, HandshakeErrorCode, HandshakeRequest, HandshakeResponse,
    PROTOCOL_VERSION, SecureChannel, read_json_frame, write_json_frame,
};
use alaric_lib::security::noise::types::Keypair;
use alaric_server::HandshakeAuthenticator;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const AGENT_TOKEN: &str = "agent-test-token";
const CLIENT_TOKEN: &str = "client-test-token";

fn test_authenticator(
    agent_ids: &[&str],
    client_ids: &[&str],
) -> Result<HandshakeAuthenticator, Box<dyn Error>> {
    let mut agents = HashMap::new();
    for agent_id in agent_ids {
        agents.insert(AgentId::new(*agent_id)?, AGENT_TOKEN.to_string());
    }

    let mut clients = HashMap::new();
    for client_id in client_ids {
        clients.insert(ClientId::new(*client_id)?, CLIENT_TOKEN.to_string());
    }

    Ok(HandshakeAuthenticator::new(agents, clients)?)
}

fn auth_agent_request(agent_id: &str, token: &str) -> Result<HandshakeRequest, Box<dyn Error>> {
    Ok(
        HandshakeRequest::agent(AgentId::new(agent_id)?)
            .with_auth(AuthRequest::shared_token(token)),
    )
}

fn auth_client_request(
    client_id: &str,
    target_agent_id: &str,
    token: &str,
) -> Result<HandshakeRequest, Box<dyn Error>> {
    Ok(
        HandshakeRequest::client(ClientId::new(client_id)?, AgentId::new(target_agent_id)?)
            .with_auth(AuthRequest::shared_token(token)),
    )
}

async fn spawn_server(
    authenticator: HandshakeAuthenticator,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let _ = alaric_server::run_with_auth(listener, authenticator).await;
    });
    Ok((addr, task))
}

#[tokio::test]
async fn accepts_handshake_and_routes_payload() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-route"], &["client-route"])?).await?;

    let mut agent = TcpStream::connect(addr).await?;
    write_json_frame(&mut agent, &auth_agent_request("agent-route", AGENT_TOKEN)?).await?;
    let agent_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut agent),
    )
    .await??;
    assert!(matches!(agent_response, HandshakeResponse::Accepted(_)));
    let agent_task = tokio::spawn(async move {
        let mut agent_secure =
            SecureChannel::handshake_xx_responder(&mut agent, Keypair::default_keypair())
                .await
                .expect("agent Noise XX handshake should succeed");

        let received = agent_secure
            .recv(&mut agent)
            .await
            .expect("agent should receive encrypted client payload");
        assert_eq!(received, b"hello-agent");

        agent_secure
            .send(&mut agent, b"hello-client")
            .await
            .expect("agent should send encrypted response");
    });

    let mut client = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut client,
        &auth_client_request("client-route", "agent-route", CLIENT_TOKEN)?,
    )
    .await?;
    let client_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut client),
    )
    .await??;
    assert!(matches!(client_response, HandshakeResponse::Accepted(_)));
    let mut client_secure = timeout(
        Duration::from_secs(2),
        SecureChannel::handshake_xx_initiator(&mut client, Keypair::default_keypair()),
    )
    .await??;

    let payload = b"hello-agent";
    client_secure.send(&mut client, payload).await?;

    let response = timeout(Duration::from_secs(2), client_secure.recv(&mut client)).await??;
    assert_eq!(response, b"hello-client");

    timeout(Duration::from_secs(2), agent_task).await??;

    drop(client);
    server_task.abort();
    let _ = server_task.await;

    Ok(())
}

#[tokio::test]
async fn rejects_unsupported_protocol_version() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-bad-version"],
        &["client-version"],
    )?)
    .await?;

    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut stream,
        &HandshakeRequest::Agent {
            protocol_version: PROTOCOL_VERSION + 1,
            agent_id: AgentId::new("agent-bad-version")?,
            auth: Some(AuthRequest::shared_token(AGENT_TOKEN)),
            metadata: Default::default(),
        },
    )
    .await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    match response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(
                rejected.code,
                HandshakeErrorCode::UnsupportedProtocolVersion
            );
        }
        HandshakeResponse::Accepted(_) => panic!("expected handshake rejection"),
    }

    drop(stream);
    server_task.abort();
    let _ = server_task.await;

    Ok(())
}

#[tokio::test]
async fn rejects_duplicate_agent_id() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-dup"], &["client-dup"])?).await?;

    let mut first = TcpStream::connect(addr).await?;
    write_json_frame(&mut first, &auth_agent_request("agent-dup", AGENT_TOKEN)?).await?;
    let first_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut first),
    )
    .await??;
    assert!(matches!(first_response, HandshakeResponse::Accepted(_)));

    let mut second = TcpStream::connect(addr).await?;
    write_json_frame(&mut second, &auth_agent_request("agent-dup", AGENT_TOKEN)?).await?;
    let second_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut second),
    )
    .await??;

    match second_response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::AgentIdInUse);
        }
        HandshakeResponse::Accepted(_) => panic!("expected duplicate agent rejection"),
    }

    drop(second);
    drop(first);
    server_task.abort();
    let _ = server_task.await;

    Ok(())
}

#[tokio::test]
async fn rejects_client_when_target_agent_is_missing() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-not-online"],
        &["client-missing"],
    )?)
    .await?;

    let mut client = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut client,
        &auth_client_request("client-missing", "agent-not-online", CLIENT_TOKEN)?,
    )
    .await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut client),
    )
    .await??;

    match response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::AgentUnavailable);
        }
        HandshakeResponse::Accepted(_) => panic!("expected unavailable-agent rejection"),
    }

    drop(client);
    server_task.abort();
    let _ = server_task.await;

    Ok(())
}

#[tokio::test]
async fn rejects_missing_auth_payload() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-missing-auth"],
        &["client-missing-auth"],
    )?)
    .await?;

    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut stream,
        &HandshakeRequest::agent(AgentId::new("agent-missing-auth")?),
    )
    .await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    match response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::Unauthorized);
        }
        HandshakeResponse::Accepted(_) => panic!("expected unauthorized rejection"),
    }

    drop(stream);
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn rejects_auth_with_invalid_token() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-bad-token"],
        &["client-bad-token"],
    )?)
    .await?;

    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut stream,
        &auth_agent_request("agent-bad-token", "not-the-token")?,
    )
    .await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    match response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::Unauthorized);
        }
        HandshakeResponse::Accepted(_) => panic!("expected unauthorized rejection"),
    }

    drop(stream);
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn rejects_auth_with_unsupported_method() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-bad-method"],
        &["client-bad-method"],
    )?)
    .await?;

    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut stream,
        &HandshakeRequest::Agent {
            protocol_version: PROTOCOL_VERSION,
            agent_id: AgentId::new("agent-bad-method")?,
            auth: Some(AuthRequest {
                method: "unsupported_method".to_string(),
                token: AGENT_TOKEN.to_string(),
            }),
            metadata: Default::default(),
        },
    )
    .await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    match response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::Unauthorized);
        }
        HandshakeResponse::Accepted(_) => panic!("expected unauthorized rejection"),
    }

    drop(stream);
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
