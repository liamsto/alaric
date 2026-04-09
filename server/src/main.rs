use crate::signal::shutdown_signal;
use alaric_lib::constants::DEFAULT_SERVER_PORT;
use alaric_lib::database::Database;
use alaric_server::HandshakeAuthenticator;
use alaric_server::connection::handle_connection;
use alaric_server::state::ServerState;
use std::error::Error;
use std::sync::Arc;
use tokio::{net::TcpListener, time::Duration};
use tracing::{error, info, warn};

mod signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_SERVER_PORT)).await?;
    let database = Arc::new(Database::from_env().await?);
    let authenticator = HandshakeAuthenticator::from_database(&database).await?;
    let local_addr = listener.local_addr()?;
    let state = ServerState::new(authenticator, database);
    let auth_refresh_task = tokio::spawn(refresh_listen(state.clone(), state.database.clone()));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    info!("server listening on {}", local_addr);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                auth_refresh_task.abort();
                info!("shutdown signal received, stopping server accept loop");
                return Ok(());
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, state).await {
                                error!("connection handling failed: {}", err);
                            }
                        });
                    }
                    Err(err) => {
                        error!("accept error: {}", err);
                    }
                }
            }
        }
    }
}

async fn refresh_listen(state: ServerState, database: Arc<Database>) {
    const RECONNECT_DELAY_SECS: u64 = 1;

    loop {
        let mut listener = match database.listen_for_auth_config_changes().await {
            Ok(listener) => listener,
            Err(err) => {
                warn!(
                    "failed to connect postgres listener for auth refresh: {}; retrying",
                    err
                );
                tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
                continue;
            }
        };

        info!("listening for auth config changes on postgres");

        loop {
            let notification = match listener.recv().await {
                Ok(notification) => notification,
                Err(err) => {
                    warn!(
                        "postgres auth-listener receive error: {}; reconnecting",
                        err
                    );
                    break;
                }
            };

            match HandshakeAuthenticator::from_database(&database).await {
                Ok(authenticator) => {
                    state.replace_authenticator(authenticator).await;
                    info!(
                        "reloaded handshake authenticator after notification {}:{}",
                        notification.channel, notification.payload
                    );
                }
                Err(err) => {
                    warn!(
                        "failed to reload handshake authenticator after notification {}:{}: {}",
                        notification.channel, notification.payload, err
                    );
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
    }
}
