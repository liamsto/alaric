use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alaric_agent::{
    policy::{ArgSpec, CommandSpec, Policy, ValidationRule},
    session::run_secure_session,
};
use alaric_lib::{
    protocol::{
        AgentId, AgentMessage, ClientId, ClientMessage, CommandId, HandshakeProofRequest,
        HandshakeRequest, HandshakeResponse, IdentityBundle, IdentityPrincipal, OutputStream,
        PeerAttestationInit, PeerAttestationPolicy, PeerAttestationResult, RejectionCode,
        RequestId, Role, SecureChannel, SessionId, TrustedIdentityKeys, build_auth_proof_ed25519,
        build_peer_attestation_proof, decode_ed25519_public_key, read_json_frame, recv_secure_json,
        send_secure_json, sign_identity_bundle_ed25519, verify_peer_attestation_proof,
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
const IDENTITY_SIGNING_KEY_ID: &str = "control-plane-v1";

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
) -> Result<(TcpStream, SessionId), Box<dyn Error>> {
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
    let HandshakeResponse::Accepted(accepted) = final_response else {
        panic!("expected accepted response");
    };
    Ok((agent, accepted.session_id))
}

async fn connect_client_secure(
    addr: SocketAddr,
    client_id: &str,
    target_agent_id: &str,
    identity_bundle: &IdentityBundle,
) -> Result<(TcpStream, SecureChannel), Box<dyn Error>> {
    let mut client = TcpStream::connect(addr).await?;
    let client_id = ClientId::new(client_id)?;
    let target_agent_id = AgentId::new(target_agent_id)?;
    let request = HandshakeRequest::client(client_id.clone(), target_agent_id.clone());
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
    let HandshakeResponse::Accepted(accepted) = final_response else {
        panic!("expected accepted response");
    };

    let mut secure = timeout(
        Duration::from_secs(2),
        SecureChannel::handshake_xx_initiator(&mut client, Keypair::default_keypair()),
    )
    .await??;

    let handshake_hash = secure.handshake_hash();
    let client_proof = build_peer_attestation_proof(
        &accepted.session_id,
        handshake_hash,
        &client_id,
        &target_agent_id,
        Role::Client,
        CLIENT_KEY_ID,
        CLIENT_PRIVATE_KEY_HEX,
    )?;
    send_secure_json(
        &mut secure,
        &mut client,
        &PeerAttestationInit {
            client_id: client_id.clone(),
            proof: Some(client_proof),
        },
    )
    .await?;

    let result = recv_secure_json::<_, PeerAttestationResult>(&mut secure, &mut client).await?;
    assert!(result.accepted, "agent should accept peer attestation");
    let Some(agent_proof) = result.agent_proof else {
        panic!("agent should return an attestation proof");
    };
    let Some(agent_identity) = identity_bundle.agent_identity_key(&target_agent_id) else {
        return Err(format!(
            "missing identity bundle key for agent '{}'",
            target_agent_id
        )
        .into());
    };
    let verified = verify_peer_attestation_proof(
        &agent_proof,
        &accepted.session_id,
        handshake_hash,
        &client_id,
        &target_agent_id,
        Role::Agent,
        &agent_identity.key_id,
        agent_identity.public_key,
    )?;
    assert!(verified, "agent peer attestation should verify");

    Ok((client, secure))
}

fn test_identity_bundle(agent_id: &str, client_id: &str) -> Result<IdentityBundle, Box<dyn Error>> {
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let signed_bundle = sign_identity_bundle_ed25519(
        now_unix + 300,
        BTreeMap::from([(
            agent_id.to_string(),
            IdentityPrincipal {
                key_id: AGENT_KEY_ID.to_string(),
                public_key: AGENT_PUBLIC_KEY_HEX.to_string(),
            },
        )]),
        BTreeMap::from([(
            client_id.to_string(),
            IdentityPrincipal {
                key_id: CLIENT_KEY_ID.to_string(),
                public_key: CLIENT_PUBLIC_KEY_HEX.to_string(),
            },
        )]),
        IDENTITY_SIGNING_KEY_ID,
        AGENT_PRIVATE_KEY_HEX,
    )?;

    let trusted_keys = TrustedIdentityKeys::from_json_map(
        &serde_json::json!({
            IDENTITY_SIGNING_KEY_ID: AGENT_PUBLIC_KEY_HEX
        })
        .to_string(),
    )?;
    let signed_bundle_json = serde_json::to_string(&signed_bundle)?;
    Ok(IdentityBundle::from_signed_json(
        &signed_bundle_json,
        &trusted_keys,
    )?)
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

fn default_attestation_policy() -> PeerAttestationPolicy {
    PeerAttestationPolicy::default()
}

#[tokio::test]
async fn allows_command_and_streams_output() -> Result<(), Box<dyn Error>> {
    let identity_bundle = test_identity_bundle("agent-cmd-ok", "client-cmd-ok")?;
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-cmd-ok"], &["client-cmd-ok"])?).await?;
    let (mut agent_stream, agent_session_id) = connect_agent(addr, "agent-cmd-ok").await?;
    let agent_id = AgentId::new("agent-cmd-ok")?;
    let policy = base_policy();
    let attestation_policy = default_attestation_policy();
    let agent_identity_bundle = identity_bundle.clone();

    let agent_task = tokio::spawn(async move {
        run_secure_session(
            &mut agent_stream,
            &policy,
            Keypair::default_keypair(),
            agent_session_id,
            &agent_id,
            AGENT_KEY_ID,
            AGENT_PRIVATE_KEY_HEX,
            &attestation_policy,
            Some(&agent_identity_bundle),
        )
        .await
        .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-cmd-ok", "agent-cmd-ok", &identity_bundle).await?;
    let mut args = BTreeMap::new();
    args.insert("text".to_string(), "hello".to_string());
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: RequestId(1),
            command_id: CommandId::new("echo").expect("valid command id"),
            args,
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages[0],
        AgentMessage::Started {
            request_id: RequestId(1)
        }
    ));
    assert!(messages.iter().any(|message| matches!(
        message,
        AgentMessage::Output {
            request_id: RequestId(1),
            stream: OutputStream::Stdout,
            chunk
        } if chunk.contains("hello")
    )));
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Completed {
            request_id: RequestId(1),
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
    let identity_bundle = test_identity_bundle("agent-unknown", "client-unknown")?;
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-unknown"], &["client-unknown"])?).await?;
    let (mut agent_stream, agent_session_id) = connect_agent(addr, "agent-unknown").await?;
    let agent_id = AgentId::new("agent-unknown")?;
    let policy = base_policy();
    let attestation_policy = default_attestation_policy();
    let agent_identity_bundle = identity_bundle.clone();
    let agent_task = tokio::spawn(async move {
        run_secure_session(
            &mut agent_stream,
            &policy,
            Keypair::default_keypair(),
            agent_session_id,
            &agent_id,
            AGENT_KEY_ID,
            AGENT_PRIVATE_KEY_HEX,
            &attestation_policy,
            Some(&agent_identity_bundle),
        )
        .await
        .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-unknown", "agent-unknown", &identity_bundle).await?;
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: RequestId(2),
            command_id: CommandId::new("does_not_exist").expect("valid command id"),
            args: BTreeMap::new(),
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Rejected {
            request_id: RequestId(2),
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
    let identity_bundle = test_identity_bundle("agent-invalid-arg", "client-invalid-arg")?;
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-invalid-arg"],
        &["client-invalid-arg"],
    )?)
    .await?;
    let (mut agent_stream, agent_session_id) = connect_agent(addr, "agent-invalid-arg").await?;
    let agent_id = AgentId::new("agent-invalid-arg")?;
    let policy = base_policy();
    let attestation_policy = default_attestation_policy();
    let agent_identity_bundle = identity_bundle.clone();
    let agent_task = tokio::spawn(async move {
        run_secure_session(
            &mut agent_stream,
            &policy,
            Keypair::default_keypair(),
            agent_session_id,
            &agent_id,
            AGENT_KEY_ID,
            AGENT_PRIVATE_KEY_HEX,
            &attestation_policy,
            Some(&agent_identity_bundle),
        )
        .await
        .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) = connect_client_secure(
        addr,
        "client-invalid-arg",
        "agent-invalid-arg",
        &identity_bundle,
    )
    .await?;
    let mut args = BTreeMap::new();
    args.insert("text".to_string(), "HELLO123".to_string());
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: RequestId(3),
            command_id: CommandId::new("echo").expect("valid command id"),
            args,
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Rejected {
            request_id: RequestId(3),
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
    let identity_bundle = test_identity_bundle("agent-timeout", "client-timeout")?;
    let (addr, server_task) =
        spawn_server(test_authenticator(&["agent-timeout"], &["client-timeout"])?).await?;
    let (mut agent_stream, agent_session_id) = connect_agent(addr, "agent-timeout").await?;
    let agent_id = AgentId::new("agent-timeout")?;
    let policy = base_policy();
    let attestation_policy = default_attestation_policy();
    let agent_identity_bundle = identity_bundle.clone();
    let agent_task = tokio::spawn(async move {
        run_secure_session(
            &mut agent_stream,
            &policy,
            Keypair::default_keypair(),
            agent_session_id,
            &agent_id,
            AGENT_KEY_ID,
            AGENT_PRIVATE_KEY_HEX,
            &attestation_policy,
            Some(&agent_identity_bundle),
        )
        .await
        .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-timeout", "agent-timeout", &identity_bundle).await?;
    let mut args = BTreeMap::new();
    args.insert("seconds".to_string(), "3".to_string());
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: RequestId(4),
            command_id: CommandId::new("sleep").expect("valid command id"),
            args,
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages[0],
        AgentMessage::Started {
            request_id: RequestId(4)
        }
    ));
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Completed {
            request_id: RequestId(4),
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
    let identity_bundle = test_identity_bundle("agent-truncate", "client-truncate")?;
    let (addr, server_task) = spawn_server(test_authenticator(
        &["agent-truncate"],
        &["client-truncate"],
    )?)
    .await?;
    let (mut agent_stream, agent_session_id) = connect_agent(addr, "agent-truncate").await?;
    let agent_id = AgentId::new("agent-truncate")?;
    let policy = base_policy();
    let attestation_policy = default_attestation_policy();
    let agent_identity_bundle = identity_bundle.clone();
    let agent_task = tokio::spawn(async move {
        run_secure_session(
            &mut agent_stream,
            &policy,
            Keypair::default_keypair(),
            agent_session_id,
            &agent_id,
            AGENT_KEY_ID,
            AGENT_PRIVATE_KEY_HEX,
            &attestation_policy,
            Some(&agent_identity_bundle),
        )
        .await
        .expect("agent secure session should succeed");
    });

    let (mut client_stream, mut secure) =
        connect_client_secure(addr, "client-truncate", "agent-truncate", &identity_bundle).await?;
    send_secure_json(
        &mut secure,
        &mut client_stream,
        &ClientMessage::Execute {
            request_id: RequestId(5),
            command_id: CommandId::new("flood").expect("valid command id"),
            args: BTreeMap::new(),
        },
    )
    .await?;

    let messages = receive_until_terminal(&mut secure, &mut client_stream).await?;
    assert!(matches!(
        messages[0],
        AgentMessage::Started {
            request_id: RequestId(5)
        }
    ));
    assert!(messages.iter().any(|message| matches!(
        message,
        AgentMessage::Output {
            request_id: RequestId(5),
            stream: OutputStream::Stdout,
            ..
        }
    )));
    assert!(matches!(
        messages.last(),
        Some(AgentMessage::Completed {
            request_id: RequestId(5),
            truncated: true,
            ..
        })
    ));

    timeout(Duration::from_secs(2), agent_task).await??;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
