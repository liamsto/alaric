use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    net::SocketAddr,
    time::Duration,
};

use alaric_agent::{
    policy::{ArgSpec, CommandSpec, Policy, ValidationRule},
    session::run_secure_session,
};
use alaric_lib::{
    protocol::{
        AgentId, AgentMessage, ClientId, ClientMessage, HandshakeProofRequest, HandshakeRequest,
        HandshakeResponse, OutputStream, RejectionCode, SecureChannel, build_auth_proof_ed25519,
        decode_ed25519_public_key, read_json_frame, recv_secure_json, send_secure_json,
        write_json_frame,
    },
    security::noise::types::Keypair,
};
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

async fn connect_agent(
    addr: std::net::SocketAddr,
    agent_id: &str,
) -> Result<TcpStream, Box<dyn Error>> {
    let mut agent = TcpStream::connect(addr).await?;
    let request = HandshakeRequest::agent(AgentId::new(agent_id)?);
    write_json_frame(&mut agent, &request).await?;
    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut agent),
    )
    .await??;
    let HandshakeResponse::Challenge(challenge) = response else {
        panic!("expected handshake challenge");
    };
    let proof =
        build_auth_proof_ed25519(&request, &challenge, AGENT_KEY_ID, AGENT_PRIVATE_KEY_HEX)?;
    write_json_frame(&mut agent, &HandshakeProofRequest::new(proof)).await?;
    let final_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut agent),
    )
    .await??;
    assert!(matches!(final_response, HandshakeResponse::Accepted(_)));
    Ok(agent)
}

async fn connect_client_secure(
    addr: SocketAddr,
    client_id: &str,
    target_agent_id: &str,
) -> Result<(TcpStream, SecureChannel), Box<dyn Error>> {
    let mut client = TcpStream::connect(addr).await?;
    let request =
        HandshakeRequest::client(ClientId::new(client_id)?, AgentId::new(target_agent_id)?);
    write_json_frame(&mut client, &request).await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut client),
    )
    .await??;
    let HandshakeResponse::Challenge(challenge) = response else {
        panic!("expected handshake challenge");
    };
    let proof =
        build_auth_proof_ed25519(&request, &challenge, CLIENT_KEY_ID, CLIENT_PRIVATE_KEY_HEX)?;
    write_json_frame(&mut client, &HandshakeProofRequest::new(proof)).await?;

    let final_response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut client),
    )
    .await??;
    assert!(matches!(final_response, HandshakeResponse::Accepted(_)));

    let secure = timeout(
        Duration::from_secs(2),
        SecureChannel::handshake_xx_initiator(&mut client, Keypair::default_keypair()),
    )
    .await??;
    Ok((client, secure))
}

async fn receive_until_terminal(
    secure: &mut SecureChannel,
    stream: &mut TcpStream,
) -> Result<Vec<AgentMessage>, Box<dyn Error>> {
    let mut messages = Vec::new();
    loop {
        let message = timeout(
            Duration::from_secs(3),
            recv_secure_json::<_, AgentMessage>(secure, stream),
        )
        .await??;
        let terminal = matches!(
            message,
            AgentMessage::Completed { .. } | AgentMessage::Rejected { .. }
        );
        messages.push(message);
        if terminal {
            return Ok(messages);
        }
    }
}

fn base_policy() -> Policy {
    let policy = Policy {
        version: 1,
        default_timeout_secs: 2,
        max_output_bytes: 4096,
        commands: vec![
            CommandSpec {
                id: "echo".to_string(),
                program: "/bin/echo".to_string(),
                fixed_args: Vec::new(),
                arg_specs: vec![ArgSpec {
                    name: "text".to_string(),
                    required: true,
                    validation: Some(ValidationRule::Regex {
                        pattern: "[a-z]+".to_string(),
                    }),
                }],
                timeout_secs: None,
                max_output_bytes: None,
            },
            CommandSpec {
                id: "sleep".to_string(),
                program: "/bin/sleep".to_string(),
                fixed_args: Vec::new(),
                arg_specs: vec![ArgSpec {
                    name: "seconds".to_string(),
                    required: true,
                    validation: Some(ValidationRule::Regex {
                        pattern: "[0-9]+".to_string(),
                    }),
                }],
                timeout_secs: Some(1),
                max_output_bytes: None,
            },
            CommandSpec {
                id: "flood".to_string(),
                program: "/bin/echo".to_string(),
                fixed_args: vec!["x".repeat(512)],
                arg_specs: Vec::new(),
                timeout_secs: None,
                max_output_bytes: Some(64),
            },
        ],
    };
    policy.validate().expect("base policy should be valid");
    policy
}

#[tokio::test]
async fn allows_command_and_streams_output() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-cmd-ok"], &["client-cmd-ok"])?).await?;
    let mut agent_stream = connect_agent(addr, "agent-cmd-ok").await?;
    let policy = base_policy();

    let agent_task = tokio::spawn(async move {
        run_secure_session(&mut agent_stream, &policy, Keypair::default_keypair())
            .await
            .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-cmd-ok", "agent-cmd-ok").await?;
    let mut args = BTreeMap::new();
    args.insert("text".to_string(), "hello".to_string());
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: 1,
            command_id: "echo".to_string(),
            args,
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages[0],
        AgentMessage::Started { request_id: 1 }
    ));
    assert!(messages.iter().any(|message| matches!(
        message,
        AgentMessage::Output {
            request_id: 1,
            stream: OutputStream::Stdout,
            chunk
        } if chunk.contains("hello")
    )));
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Completed {
            request_id: 1,
            exit_code: 0,
            timed_out: false,
            truncated: false
        })
    ));

    timeout(Duration::from_secs(2), agent_task).await??;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn rejects_unknown_command() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-unknown"], &["client-unknown"])?).await?;
    let mut agent_stream = connect_agent(addr, "agent-unknown").await?;
    let policy = base_policy();
    let agent_task = tokio::spawn(async move {
        run_secure_session(&mut agent_stream, &policy, Keypair::default_keypair())
            .await
            .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-unknown", "agent-unknown").await?;
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: 2,
            command_id: "does_not_exist".to_string(),
            args: BTreeMap::new(),
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Rejected {
            request_id: 2,
            code: RejectionCode::UnknownCommand,
            ..
        })
    ));

    timeout(Duration::from_secs(2), agent_task).await??;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_argument_value() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-invalid-arg"],
        &["client-invalid-arg"],
    )?)
    .await?;
    let mut agent_stream = connect_agent(addr, "agent-invalid-arg").await?;
    let policy = base_policy();
    let agent_task = tokio::spawn(async move {
        run_secure_session(&mut agent_stream, &policy, Keypair::default_keypair())
            .await
            .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-invalid-arg", "agent-invalid-arg").await?;
    let mut args = BTreeMap::new();
    args.insert("text".to_string(), "HELLO123".to_string());
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: 3,
            command_id: "echo".to_string(),
            args,
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Rejected {
            request_id: 3,
            code: RejectionCode::InvalidArgs,
            ..
        })
    ));

    timeout(Duration::from_secs(2), agent_task).await??;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn times_out_long_running_command() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-timeout"], &["client-timeout"])?).await?;
    let mut agent_stream = connect_agent(addr, "agent-timeout").await?;
    let policy = base_policy();
    let agent_task = tokio::spawn(async move {
        run_secure_session(&mut agent_stream, &policy, Keypair::default_keypair())
            .await
            .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-timeout", "agent-timeout").await?;
    let mut args = BTreeMap::new();
    args.insert("seconds".to_string(), "3".to_string());
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: 4,
            command_id: "sleep".to_string(),
            args,
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages[0],
        AgentMessage::Started { request_id: 4 }
    ));
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Completed {
            request_id: 4,
            timed_out: true,
            ..
        })
    ));

    timeout(Duration::from_secs(2), agent_task).await??;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn truncates_output_at_limit() -> Result<(), Box<dyn Error>> {
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-truncate"],
        &["client-truncate"],
    )?)
    .await?;
    let mut agent_stream = connect_agent(addr, "agent-truncate").await?;
    let policy = base_policy();
    let agent_task = tokio::spawn(async move {
        run_secure_session(&mut agent_stream, &policy, Keypair::default_keypair())
            .await
            .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-truncate", "agent-truncate").await?;
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: 5,
            command_id: "flood".to_string(),
            args: BTreeMap::new(),
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages[0],
        AgentMessage::Started { request_id: 5 }
    ));
    assert!(messages.iter().any(|message| matches!(
        message,
        AgentMessage::Output {
            request_id: 5,
            stream: OutputStream::Stdout,
            ..
        }
    )));
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Completed {
            request_id: 5,
            truncated: true,
            ..
        })
    ));

    timeout(Duration::from_secs(2), agent_task).await??;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
