use std::error::Error;

use lib::constants::DEFAULT_SERVER_PORT;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_SERVER_PORT)).await?;
    alaric_server::run_until(listener, shutdown_signal()).await
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
