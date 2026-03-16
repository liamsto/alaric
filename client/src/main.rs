use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io::{self, Write},
};

use alaric_lib::{
    constants::DEFAULT_SERVER_PORT,
    protocol::{
        AgentId, AgentMessage, ClientId, ClientMessage, CommandId, HandshakeProofRequest,
        HandshakeRequest, HandshakeResponse, ListAgentsResponse, OutputStream, RequestId,
        SecureChannel, build_auth_proof_ed25519, read_json_frame, recv_secure_json,
        send_secure_json, write_json_frame,
    },
    security::noise::types::Keypair,
};
use tokio::{net::TcpStream, select};
use tracing::info;

mod signal;

#[derive(Debug)]
struct RunCliArgs {
    command_id: CommandId,
    args: BTreeMap<String, String>,
}

#[derive(Debug)]
enum CliCommand {
    Run(RunCliArgs),
    ListAgents,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let shutdown = signal::shutdown_signal();
    tokio::pin!(shutdown);

    let cli_command = match parse_cli_args(env::args().skip(1)) {
        Ok(CliParseOutcome::Run(command)) => command,
        Ok(CliParseOutcome::PrintHelp) => {
            println!("{}", usage_text());
            return Ok(());
        }
        Err(err) => {
            return Err(format!("{}\n\n{}", err, usage_text()).into());
        }
    };

    let addr = format!("127.0.0.1:{}", DEFAULT_SERVER_PORT);
    let client_id = ClientId::new(
        env::var("CLIENT_ID").unwrap_or_else(|_| format!("client-{}", std::process::id())),
    )?;
    let auth_key_id = env::var("CLIENT_AUTH_KEY_ID")
        .map_err(|_| "CLIENT_AUTH_KEY_ID must be set for handshake authentication")?;
    let auth_private_key = env::var("CLIENT_AUTH_PRIVATE_KEY")
        .map_err(|_| "CLIENT_AUTH_PRIVATE_KEY must be set for handshake authentication")?;
    let request = build_handshake_request(&cli_command, &client_id)?;

    let mut stream = tokio::select! {
        connect_result = TcpStream::connect(addr) => connect_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received before connect, exiting");
            return Ok(());
        }
    };
    info!("connected to {}", stream.peer_addr()?);
    tokio::select! {
        write_result = write_json_frame(&mut stream, &request) => write_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received during handshake, exiting");
            return Ok(());
        }
    }

    let response = tokio::select! {
        read_result = read_json_frame::<_, HandshakeResponse>(&mut stream) => read_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received while waiting for handshake response, exiting");
            return Ok(());
        }
    };

    let response = match response {
        HandshakeResponse::Challenge(challenge) => {
            let proof =
                build_auth_proof_ed25519(&request, &challenge, &auth_key_id, &auth_private_key)?;
            let proof_request = HandshakeProofRequest::new(proof);
            select! {
                write_result = write_json_frame(&mut stream, &proof_request) => write_result?,
                _ = &mut shutdown => {
                    info!("shutdown signal received during auth proof exchange, exiting");
                    return Ok(());
                }
            };

            select! {
                read_result = read_json_frame::<_, HandshakeResponse>(&mut stream) => read_result?,
                _ = &mut shutdown => {
                    info!("shutdown signal received while waiting for handshake completion, exiting");
                    return Ok(());
                }
            }
        }
        HandshakeResponse::Accepted(accepted) => {
            info!(
                "handshake accepted (client_id={}, {}, session_id={})",
                client_id,
                request_context(&request),
                accepted.session_id
            );
            HandshakeResponse::Accepted(accepted)
        }
        HandshakeResponse::Rejected(rejected) => {
            return Err(format!(
                "handshake rejected for client {} ({}): {:?}: {}",
                client_id,
                request_context(&request),
                rejected.code,
                rejected.message
            )
            .into());
        }
    };

    match response {
        HandshakeResponse::Accepted(accepted) => {
            info!(
                "handshake accepted (client_id={}, {}, session_id={})",
                client_id,
                request_context(&request),
                accepted.session_id
            );
        }
        HandshakeResponse::Rejected(rejected) => {
            return Err(format!(
                "handshake rejected for client {} ({}): {:?}: {}",
                client_id,
                request_context(&request),
                rejected.code,
                rejected.message
            )
            .into());
        }
        HandshakeResponse::Challenge(_) => {
            return Err("unexpected second handshake challenge from server".into());
        }
    };

    if let CliCommand::ListAgents = &cli_command {
        let response = select! {
            read_result = read_json_frame::<_, ListAgentsResponse>(&mut stream) => read_result?,
            _ = &mut shutdown => {
                info!("shutdown signal received while waiting for discovery response, exiting");
                return Ok(());
            }
        };
        print_discovered_agents(&response);
        return Ok(());
    }

    let CliCommand::Run(run_args) = cli_command else {
        return Ok(());
    };

    let mut secure = select! {
        secure_result = SecureChannel::handshake_xx_initiator(&mut stream, Keypair::default_keypair()) => secure_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received before secure handshake, exiting");
            return Ok(());
        }
    };

    let request_id = RequestId(1);
    let execute = ClientMessage::Execute {
        request_id,
        command_id: run_args.command_id,
        args: run_args.args,
    };
    select! {
        send_result = send_secure_json(&mut secure, &mut stream, &execute) => send_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received before execute request, exiting");
            return Ok(());
        }
    }

    loop {
        let message = select! {
            message_result = recv_secure_json::<_, AgentMessage>(&mut secure, &mut stream) => message_result?,
            _ = &mut shutdown => {
                info!("shutdown signal received while waiting for command output, exiting");
                return Ok(());
            }
        };

        match message {
            AgentMessage::Started {
                request_id: message_request_id,
            } if message_request_id == request_id => {
                info!("command started (request_id={})", request_id);
            }
            AgentMessage::Output {
                request_id: message_request_id,
                stream: output_stream,
                chunk,
            } if message_request_id == request_id => match output_stream {
                OutputStream::Stdout => {
                    print!("{}", chunk);
                    io::stdout().flush()?;
                }
                OutputStream::Stderr => {
                    eprint!("{}", chunk);
                    io::stderr().flush()?;
                }
            },
            AgentMessage::Completed {
                request_id: message_request_id,
                exit_code,
                timed_out,
                truncated,
            } if message_request_id == request_id => {
                info!(
                    "command completed (request_id={}, exit_code={}, timed_out={}, truncated={})",
                    request_id, exit_code, timed_out, truncated
                );
                if let Some(failure_message) =
                    completion_failure_message(exit_code, timed_out, truncated)
                {
                    return Err(format!(
                        "command failed (request_id={}): {}",
                        request_id, failure_message
                    )
                    .into());
                }
                break;
            }
            AgentMessage::Rejected {
                request_id: message_request_id,
                code,
                message,
            } if message_request_id == request_id => {
                return Err(format!(
                    "command rejected (request_id={}, code={:?}): {}",
                    request_id, code, message
                )
                .into());
            }
            _ => {}
        }
    }

    Ok(())
}

enum CliParseOutcome {
    Run(CliCommand),
    PrintHelp,
}

fn parse_cli_args(args: impl IntoIterator<Item = String>) -> Result<CliParseOutcome, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|value| value == "--help" || value == "-h")
    {
        return Ok(CliParseOutcome::PrintHelp);
    }

    if args.first().is_some_and(|value| value == "list-agents") {
        if args.len() != 1 {
            return Err("list-agents does not take additional arguments".to_string());
        }
        return Ok(CliParseOutcome::Run(CliCommand::ListAgents));
    }

    if args.first().is_some_and(|value| value == "run")
        && args
            .get(1)
            .is_some_and(|value| value == "--help" || value == "-h")
    {
        return Ok(CliParseOutcome::PrintHelp);
    }

    let run_args = if args.first().is_some_and(|value| value == "run") {
        parse_run_args(args.iter().skip(1).cloned())?
    } else {
        parse_run_args(args)?
    };

    Ok(CliParseOutcome::Run(CliCommand::Run(run_args)))
}

fn parse_run_args(args: impl IntoIterator<Item = String>) -> Result<RunCliArgs, String> {
    let mut command_id = env::var("COMMAND_ID").ok();
    let mut parsed_args = BTreeMap::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--command-id" => {
                let Some(value) = iter.next() else {
                    return Err("--command-id requires a value".to_string());
                };
                if value.is_empty() {
                    return Err("--command-id must not be empty".to_string());
                }
                command_id = Some(value);
            }
            "--arg" => {
                let Some(value) = iter.next() else {
                    return Err("--arg requires a key=value value".to_string());
                };
                let Some((key, val)) = value.split_once('=') else {
                    return Err(format!(
                        "invalid --arg value '{}'; expected key=value",
                        value
                    ));
                };
                if key.is_empty() {
                    return Err("argument key must not be empty".to_string());
                }
                parsed_args.insert(key.to_string(), val.to_string());
            }
            _ => {
                return Err(format!("unknown argument '{}'", arg));
            }
        }
    }

    let command_id = command_id.ok_or_else(|| "missing --command-id".to_string())?;
    let command_id = CommandId::new(command_id).map_err(|err| {
        format!(
            "invalid command id provided via --command-id/COMMAND_ID: {}",
            err
        )
    })?;
    Ok(RunCliArgs {
        command_id,
        args: parsed_args,
    })
}

fn usage_text() -> &'static str {
    "Usage:
  alaric-client list-agents
  alaric-client run --command-id <id> [--arg name=value]...
  alaric-client --command-id <id> [--arg name=value]...

Environment:
  CLIENT_ID          Optional client id (default: client-<pid>)
  TARGET_AGENT_ID    Optional target agent id (default: agent-default)
  CLIENT_AUTH_KEY_ID      Required handshake auth key id for this client id
  CLIENT_AUTH_PRIVATE_KEY Required Ed25519 private key hex for this client id
  COMMAND_ID         Optional fallback for --command-id"
}

fn build_handshake_request(
    command: &CliCommand,
    client_id: &ClientId,
) -> Result<HandshakeRequest, Box<dyn Error>> {
    match command {
        CliCommand::Run(_) => {
            let target_agent_id = AgentId::new(
                env::var("TARGET_AGENT_ID").unwrap_or_else(|_| "agent-default".to_string()),
            )?;
            Ok(HandshakeRequest::client(client_id.clone(), target_agent_id))
        }
        CliCommand::ListAgents => Ok(HandshakeRequest::client_discovery(client_id.clone())),
    }
}

fn request_context(request: &HandshakeRequest) -> String {
    match request {
        HandshakeRequest::Client {
            target_agent_id, ..
        } => format!("target={}", target_agent_id),
        HandshakeRequest::ClientDiscovery { .. } => "mode=discovery".to_string(),
        HandshakeRequest::Agent { .. } => "mode=agent".to_string(),
    }
}

fn print_discovered_agents(response: &ListAgentsResponse) {
    if response.agents.is_empty() {
        println!("no agents discovered");
        return;
    }

    println!("agent_id\tstatus\tstatus_age_secs\tcapabilities\ttags\tdisplay_name");
    for agent in &response.agents {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            agent.agent_id,
            agent.status.as_str(),
            agent.status_age_secs,
            agent.capabilities.join(","),
            agent.tags.join(","),
            agent.display_name.as_deref().unwrap_or("")
        );
    }
}

fn completion_failure_message(exit_code: i32, timed_out: bool, truncated: bool) -> Option<String> {
    let mut reasons = Vec::new();
    if exit_code != 0 {
        reasons.push(format!("exit_code={}", exit_code));
    }
    if timed_out {
        reasons.push("timed_out=true".to_string());
    }
    if truncated {
        reasons.push("truncated=true".to_string());
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::{CliCommand, CliParseOutcome, completion_failure_message, parse_cli_args};

    #[test]
    fn completion_success_has_no_failure_message() {
        assert_eq!(completion_failure_message(0, false, false), None);
    }

    #[test]
    fn non_zero_exit_reports_failure() {
        assert_eq!(
            completion_failure_message(2, false, false),
            Some("exit_code=2".to_string())
        );
    }

    #[test]
    fn timeout_and_truncation_are_reported() {
        assert_eq!(
            completion_failure_message(0, true, true),
            Some("timed_out=true, truncated=true".to_string())
        );
    }

    #[test]
    fn parse_list_agents_command() {
        let parsed = parse_cli_args(["list-agents".to_string()]).expect("list-agents should parse");
        assert!(matches!(
            parsed,
            CliParseOutcome::Run(CliCommand::ListAgents)
        ));
    }

    #[test]
    fn parse_legacy_run_command() {
        let parsed = parse_cli_args([
            "--command-id".to_string(),
            "echo_text".to_string(),
            "--arg".to_string(),
            "text=hello".to_string(),
        ])
        .expect("legacy run args should parse");

        assert!(matches!(parsed, CliParseOutcome::Run(CliCommand::Run(_))));
    }
}
