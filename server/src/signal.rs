use tracing::info;

pub async fn shutdown_signal() {
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
