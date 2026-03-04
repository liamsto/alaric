use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io::{self, Write},
};

use lib::{
    constants::DEFAULT_SERVER_PORT,
    protocol::{
        AgentId, AgentMessage, ClientId, ClientMessage, HandshakeRequest, HandshakeResponse,
        OutputStream, SecureChannel, read_json_frame, recv_secure_json, send_secure_json,
        write_json_frame,
    },
    security::noise::types::Keypair,
};
use tokio::{net::TcpStream, select};
use tracing::info;

mod signal;

#[derive(Debug)]
struct CliArgs {
    command_id: String,
    args: BTreeMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let shutdown = signal::shutdown_signal();
    tokio::pin!(shutdown);

    let cli = match parse_cli_args(env::args().skip(1)) {
        Ok(CliParseOutcome::Run(cli)) => cli,
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
    let target_agent_id =
        AgentId::new(env::var("TARGET_AGENT_ID").unwrap_or_else(|_| "agent-default".into()))?;

    let mut stream = tokio::select! {
        connect_result = TcpStream::connect(addr) => connect_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received before connect, exiting");
            return Ok(());
        }
    };
    info!("connected to {}", stream.peer_addr()?);
    let request = HandshakeRequest::client(client_id.clone(), target_agent_id.clone());
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

    match response {
        HandshakeResponse::Accepted(accepted) => {
            info!(
                "handshake accepted (client_id={}, target_agent_id={}, session_id={})",
                client_id, target_agent_id, accepted.session_id.0
            );
        }
        HandshakeResponse::Rejected(rejected) => {
            return Err(format!(
                "handshake rejected for client {} (target={}): {:?}: {}",
                client_id, target_agent_id, rejected.code, rejected.message
            )
            .into());
        }
    }

    let mut secure = select! {
        secure_result = SecureChannel::handshake_xx_initiator(&mut stream, Keypair::default_keypair()) => secure_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received before secure handshake, exiting");
            return Ok(());
        }
    };

    let request_id = 1_u64;
    let execute = ClientMessage::Execute {
        request_id,
        command_id: cli.command_id,
        args: cli.args,
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
    Run(CliArgs),
    PrintHelp,
}

fn parse_cli_args(args: impl IntoIterator<Item = String>) -> Result<CliParseOutcome, String> {
    let mut command_id = env::var("COMMAND_ID").ok();
    let mut parsed_args = BTreeMap::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(CliParseOutcome::PrintHelp),
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
    Ok(CliParseOutcome::Run(CliArgs {
        command_id,
        args: parsed_args,
    }))
}

fn usage_text() -> &'static str {
    "Usage:
  alaric-client --command-id <id> [--arg name=value]...

Environment:
  CLIENT_ID          Optional client id (default: client-<pid>)
  TARGET_AGENT_ID    Optional target agent id (default: agent-default)
  COMMAND_ID         Optional fallback for --command-id"
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
    use super::completion_failure_message;

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
}
