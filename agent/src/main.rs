use std::{env, error::Error, time::Duration};

use lib::constants::DEFAULT_SERVER_PORT;
use lib::types::{AgentId, HandshakeRequest, HandshakeResponse, read_json_frame, write_json_frame};
use tokio::{io::AsyncReadExt, net::TcpStream, time::sleep};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let addr = format!("127.0.0.1:{}", DEFAULT_SERVER_PORT);
    let agent_id = AgentId::new(env::var("AGENT_ID").unwrap_or_else(|_| "agent-default".into()))?;

    loop {
        let connect_result = tokio::select! {
            result = TcpStream::connect(&addr) => result,
            _ = &mut shutdown => {
                info!("shutdown signal received before connect, exiting");
                break;
            }
        };

        match connect_result {
            Ok(stream) => {
                tokio::select! {
                    result = connection_loop(stream, agent_id.clone()) => {
                        if let Err(err) = result {
                            error!("connection error: {}", err);
                        }
                    }
                    _ = &mut shutdown => {
                        info!("shutdown signal received, closing active connection");
                        break;
                    }
                }
            }
            Err(err) => {
                error!("connect failed: {}", err);
            }
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = &mut shutdown => {
                info!("shutdown signal received, exiting");
                break;
            }
        }
    }

    Ok(())
}

async fn connection_loop(
    mut stream: TcpStream,
    agent_id: AgentId,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("connected to {}", stream.peer_addr()?);
    let request = HandshakeRequest::agent(agent_id.clone());
    write_json_frame(&mut stream, &request).await?;

    match read_json_frame::<_, HandshakeResponse>(&mut stream).await? {
        HandshakeResponse::Accepted(accepted) => {
            info!(
                "handshake accepted (agent_id={}, session_id={})",
                agent_id, accepted.session_id.0
            );
        }
        HandshakeResponse::Rejected(rejected) => {
            return Err(format!(
                "handshake rejected for agent {} ({}): {}",
                agent_id,
                format!("{:?}", rejected.code),
                rejected.message
            )
            .into());
        }
    }

    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        info!("bytes received: {}", str::from_utf8(&buf[..n])?);
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            signal_result = tokio::signal::ctrl_c() => {
                if let Err(err) = signal_result {
                    info!("failed to listen for Ctrl+C: {}", err);
                } else {
                    info!("received Ctrl+C");
                }
            }
            _ = terminate.recv() => {
                info!("received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            info!("failed to listen for Ctrl+C: {}", err);
        } else {
            info!("received Ctrl+C");
        }
    }
}
