use std::{env, error::Error};

use lib::{
    constants::DEFAULT_SERVER_PORT,
    protocol::{
        AgentId, ClientId, HandshakeRequest, HandshakeResponse, SecureChannel, read_json_frame,
        write_json_frame,
    },
    security::noise::types::Keypair,
};
use tokio::{
    net::TcpStream,
    time::{Duration, sleep},
};
use tracing::info;

use crate::signal;

pub async fn run() -> Result<(), Box<dyn Error>> {
    let shutdown = signal::shutdown_signal();
    tokio::pin!(shutdown);

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

    let mut secure_channel = tokio::select! {
        secure_result = SecureChannel::handshake_xx_initiator(&mut stream, Keypair::default()) => secure_result?,
        _ = &mut shutdown => {
            info!("shutdown signal received during Noise handshake, exiting");
            return Ok(());
        }
    };
    info!("Noise XX transport established");

    loop {
        tokio::select! {
            write_result = secure_channel.send(&mut stream, b"Hello world!") => {
                write_result?;
            }
            _ = &mut shutdown => {
                info!("shutdown signal received, exiting client loop");
                break;
            }
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = &mut shutdown => {
                info!("shutdown signal received, exiting client loop");
                break;
            }
        }
    }

    Ok(())
}
