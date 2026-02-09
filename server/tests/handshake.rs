use std::{collections::BTreeMap, error::Error, time::Duration};

use lib::protocol::{
    AgentId, ClientId, HandshakeErrorCode, HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION,
    SecureChannel, read_json_frame, write_json_frame,
};
use lib::security::noise::types::Keypair;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

async fn spawn_server() -> Result<(std::net::SocketAddr, JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let _ = alaric_server::run(listener).await;
    });
    Ok((addr, task))
}

#[tokio::test]
async fn accepts_handshake_and_routes_payload() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server().await?;

    let mut agent = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut agent,
        &HandshakeRequest::agent(AgentId::new("agent-route")?),
    )
    .await?;
    let agent_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut agent),
    )
    .await??;
    assert!(matches!(agent_response, HandshakeResponse::Accepted(_)));
    let agent_task = tokio::spawn(async move {
        let mut agent_secure =
            SecureChannel::handshake_xx_responder(&mut agent, Keypair::default())
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
        &HandshakeRequest::client(ClientId::new("client-route")?, AgentId::new("agent-route")?),
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
        SecureChannel::handshake_xx_initiator(&mut client, Keypair::default()),
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
    let (addr, server_task) = spawn_server().await?;

    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut stream,
        &HandshakeRequest::Agent {
            protocol_version: PROTOCOL_VERSION + 1,
            agent_id: AgentId::new("agent-bad-version")?,
            auth: None,
            metadata: BTreeMap::new(),
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
    let (addr, server_task) = spawn_server().await?;

    let mut first = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut first,
        &HandshakeRequest::agent(AgentId::new("agent-dup")?),
    )
    .await?;
    let first_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut first),
    )
    .await??;
    assert!(matches!(first_response, HandshakeResponse::Accepted(_)));

    let mut second = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut second,
        &HandshakeRequest::agent(AgentId::new("agent-dup")?),
    )
    .await?;
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
    let (addr, server_task) = spawn_server().await?;

    let mut client = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut client,
        &HandshakeRequest::client(
            ClientId::new("client-missing")?,
            AgentId::new("agent-not-online")?,
        ),
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
