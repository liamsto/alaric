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
        AgentId, AgentMessage, AuthRequest, ClientId, ClientMessage, HandshakeRequest,
        HandshakeResponse, OutputStream, RejectionCode, SecureChannel, read_json_frame,
        recv_secure_json, send_secure_json, write_json_frame,
    },
    security::noise::types::Keypair,
};
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
    write_json_frame(
        &mut agent,
        &HandshakeRequest::agent(AgentId::new(agent_id)?)
            .with_auth(AuthRequest::shared_token(AGENT_TOKEN)),
    )
    .await?;
    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut agent),
    )
    .await??;
    assert!(matches!(response, HandshakeResponse::Accepted(_)));
    Ok(agent)
}

async fn connect_client_secure(
    addr: SocketAddr,
    client_id: &str,
    target_agent_id: &str,
) -> Result<(TcpStream, SecureChannel), Box<dyn Error>> {
    let mut client = TcpStream::connect(addr).await?;
    write_json_frame(
        &mut client,
        &HandshakeRequest::client(ClientId::new(client_id)?, AgentId::new(target_agent_id)?)
            .with_auth(AuthRequest::shared_token(CLIENT_TOKEN)),
    )
    .await?;

    let response = timeout(
        Duration::from_secs(2),
        read_json_frame::<_, HandshakeResponse>(&mut client),
    )
    .await??;
    assert!(matches!(response, HandshakeResponse::Accepted(_)));

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
