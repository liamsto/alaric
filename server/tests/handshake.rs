use std::net::SocketAddr;
use std::{collections::HashMap, error::Error, time::Duration};

use alaric_lib::protocol::{
    AgentId, AuthProof, ClientId, HandshakeErrorCode, HandshakeProofRequest, HandshakeRequest,
    HandshakeResponse, PROTOCOL_VERSION, SecureChannel, build_auth_proof_ed25519,
    decode_ed25519_public_key, read_json_frame, write_json_frame,
};
use alaric_lib::security::noise::types::Keypair;
use alaric_server::{HandshakeAuthenticator, IdentityPublicKey};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const AGENT_KEY_ID: &str = "agent-default-v1";
const CLIENT_KEY_ID: &str = "client-local-v1";
const AGENT_PRIVATE_KEY_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AGENT_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const CLIENT_PRIVATE_KEY_HEX: &str =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const CLIENT_PUBLIC_KEY_HEX: &str =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

fn test_authenticator(
    agent_ids: &[&str],
    client_ids: &[&str],
) -> Result<HandshakeAuthenticator, Box<dyn Error>> {
    let agent_public_key = decode_ed25519_public_key(AGENT_PUBLIC_KEY_HEX)?;
    let client_public_key = decode_ed25519_public_key(CLIENT_PUBLIC_KEY_HEX)?;

    let mut agents = HashMap::new();
    for agent_id in agent_ids {
        agents.insert(
            AgentId::new(*agent_id)?,
            IdentityPublicKey {
                key_id: AGENT_KEY_ID.to_string(),
                public_key: agent_public_key,
            },
        );
    }

    let mut clients = HashMap::new();
    for client_id in client_ids {
        clients.insert(
            ClientId::new(*client_id)?,
            IdentityPublicKey {
                key_id: CLIENT_KEY_ID.to_string(),
                public_key: client_public_key,
            },
        );
    }

    Ok(HandshakeAuthenticator::new(agents, clients)?)
}

fn agent_request(agent_id: &str) -> Result<HandshakeRequest, Box<dyn Error>> {
    Ok(HandshakeRequest::agent(AgentId::new(agent_id)?))
}

fn client_request(
    client_id: &str,
    target_agent_id: &str,
) -> Result<HandshakeRequest, Box<dyn Error>> {
    Ok(HandshakeRequest::client(
        ClientId::new(client_id)?,
        AgentId::new(target_agent_id)?,
    ))
}

async fn perform_authenticated_handshake(
    stream: &mut TcpStream,
    request: HandshakeRequest,
    key_id: &str,
    private_key_hex: &str,
) -> Result<HandshakeResponse, Box<dyn Error>> {
    write_json_frame(stream, &request).await?;
    let first = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(stream),
    )
    .await??;

    match first {
        HandshakeResponse::Challenge(challenge) => {
            let proof = build_auth_proof_ed25519(&request, &challenge, key_id, private_key_hex)?;
            write_json_frame(stream, &HandshakeProofRequest::new(proof)).await?;
            let final_response = timeout(
                Duration::from_secs(2),
                read_json_frame::<_, HandshakeResponse>(stream),
            )
            .await??;
            Ok(final_response)
        }
        other => Ok(other),
    }
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
    let agent_response = perform_authenticated_handshake(
        &mut agent,
        agent_request("agent-route")?,
        AGENT_KEY_ID,
        AGENT_PRIVATE_KEY_HEX,
    )
    .await?;
    let HandshakeResponse::Accepted(agent_accepted) = agent_response else {
        panic!("expected accepted response for agent");
    };

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
    let client_response = perform_authenticated_handshake(
        &mut client,
        client_request("client-route", "agent-route")?,
        CLIENT_KEY_ID,
        CLIENT_PRIVATE_KEY_HEX,
    )
    .await?;
    let HandshakeResponse::Accepted(client_accepted) = client_response else {
        panic!("expected accepted response for client");
    };
    assert_eq!(agent_accepted.session_id, client_accepted.session_id);

    let mut client_secure = timeout(
        Duration::from_secs(2),
        SecureChannel::handshake_xx_initiator(&mut client, Keypair::default_keypair()),
    )
    .await??;

    client_secure.send(&mut client, b"hello-agent").await?;
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
        _ => panic!("expected handshake rejection"),
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
    let first_response = perform_authenticated_handshake(
        &mut first,
        agent_request("agent-dup")?,
        AGENT_KEY_ID,
        AGENT_PRIVATE_KEY_HEX,
    )
    .await?;
    assert!(matches!(first_response, HandshakeResponse::Accepted(_)));

    let mut second = TcpStream::connect(addr).await?;
    let second_response = perform_authenticated_handshake(
        &mut second,
        agent_request("agent-dup")?,
        AGENT_KEY_ID,
        AGENT_PRIVATE_KEY_HEX,
    )
    .await?;

    match second_response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::AgentIdInUse);
        }
        _ => panic!("expected duplicate agent rejection"),
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
    let response = perform_authenticated_handshake(
        &mut client,
        client_request("client-missing", "agent-not-online")?,
        CLIENT_KEY_ID,
        CLIENT_PRIVATE_KEY_HEX,
    )
    .await?;

    match response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::AgentUnavailable);
        }
        _ => panic!("expected unavailable-agent rejection"),
    }

    drop(client);
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_auth_proof_signature() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-bad-signature"],
        &["client-bad-signature"],
    )?)
    .await?;

    let request = agent_request("agent-bad-signature")?;
    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(&mut stream, &request).await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    let HandshakeResponse::Challenge(challenge) = response else {
        panic!("expected challenge response");
    };

    // Intentionally sign with the client key while claiming the agent key id.
    let proof =
        build_auth_proof_ed25519(&request, &challenge, AGENT_KEY_ID, CLIENT_PRIVATE_KEY_HEX)?;
    write_json_frame(&mut stream, &HandshakeProofRequest::new(proof)).await?;

    let final_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    match final_response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::Unauthorized);
        }
        _ => panic!("expected unauthorized rejection"),
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

    let request = agent_request("agent-bad-method")?;
    let mut stream = TcpStream::connect(addr).await?;
    write_json_frame(&mut stream, &request).await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    let HandshakeResponse::Challenge(challenge) = response else {
        panic!("expected challenge response");
    };

    let proof =
        build_auth_proof_ed25519(&request, &challenge, AGENT_KEY_ID, AGENT_PRIVATE_KEY_HEX)?;
    let bad_method_proof = AuthProof {
        method: "unsupported_method".to_string(),
        key_id: proof.key_id,
        signature: proof.signature,
    };
    write_json_frame(&mut stream, &HandshakeProofRequest::new(bad_method_proof)).await?;

    let final_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut stream),
    )
    .await??;

    match final_response {
        HandshakeResponse::Rejected(rejected) => {
            assert_eq!(rejected.code, HandshakeErrorCode::Unauthorized);
        }
        _ => panic!("expected unauthorized rejection"),
    }

    drop(stream);
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
