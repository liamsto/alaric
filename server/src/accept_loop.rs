use std::{
    env,
    future::{Future, pending},
    io,
    sync::Arc,
    time::Duration,
};

use crate::{
    auth::HandshakeAuthenticator, connection::handle_connection, error::BoxError,
    state::ServerState,
};
use alaric_lib::database::{Database, DatabaseConfig, LogRetentionDays};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub async fn run(listener: TcpListener) -> Result<(), BoxError> {
    run_until(listener, pending::<()>()).await
}

pub async fn run_with_auth(
    listener: TcpListener,
    authenticator: HandshakeAuthenticator,
) -> Result<(), BoxError> {
    run_until_with_auth(listener, pending::<()>(), authenticator).await
}

pub async fn run_until(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), BoxError> {
    let database = database_from_env().await?;
    let authenticator = HandshakeAuthenticator::from_database(&database).await?;
    run_until_with_auth_and_db(listener, shutdown, authenticator, Some(database)).await
}

pub async fn run_until_with_auth(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
    authenticator: HandshakeAuthenticator,
) -> Result<(), BoxError> {
    run_until_with_auth_and_db(listener, shutdown, authenticator, None).await
}

pub async fn run_until_with_auth_and_db(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
    authenticator: HandshakeAuthenticator,
    database: Option<Arc<Database>>,
) -> Result<(), BoxError> {
    let local_addr = listener.local_addr()?;
    let state = ServerState::new(authenticator, database);
    let mut auth_refresh_task = state
        .database
        .clone()
        .map(|database| tokio::spawn(run_auth_refresh_listener(state.clone(), database)));
    tokio::pin!(shutdown);

    info!("server listening on {}", local_addr);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                if let Some(task) = auth_refresh_task.take() {
                    task.abort();
                }
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

async fn run_auth_refresh_listener(state: ServerState, database: Arc<Database>) {
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

async fn database_from_env() -> Result<Arc<Database>, BoxError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DATABASE_URL must be set for the server",
        )
    })?;

    let mut config = DatabaseConfig::new(database_url);
    if let Ok(raw) = env::var("DATABASE_MAX_CONNECTIONS") {
        config.max_connections = raw.parse::<u32>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DATABASE_MAX_CONNECTIONS '{}': {}", raw, err),
            )
        })?;
    }
    if let Ok(raw) = env::var("DATABASE_ACQUIRE_TIMEOUT_SECS") {
        let seconds = raw.parse::<u64>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DATABASE_ACQUIRE_TIMEOUT_SECS '{}': {}", raw, err),
            )
        })?;
        config.acquire_timeout = Duration::from_secs(seconds);
    }
    if let Ok(raw) = env::var("LOG_RETENTION_DAYS") {
        let days = raw.parse::<u16>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid LOG_RETENTION_DAYS '{}': {}", raw, err),
            )
        })?;
        config.log_retention_days = LogRetentionDays::new(days).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid LOG_RETENTION_DAYS: {}", err),
            )
        })?;
    }

    let database = Database::connect_and_migrate(&config).await?;
    let prune = database.prune_phase1_logs().await?;
    info!(
        "phase-1 retention prune complete: command_runs_deleted={}, session_logs_deleted={}",
        prune.command_runs_deleted, prune.session_logs_deleted
    );
    Ok(Arc::new(database))
}
