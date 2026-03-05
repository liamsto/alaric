use std::future::{Future, pending};

use crate::{
    auth::HandshakeAuthenticator, connection::handle_connection, error::BoxError,
    state::ServerState,
};
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run(listener: TcpListener) -> Result<(), BoxError> {
    let authenticator = HandshakeAuthenticator::from_env_or_default_path()?;
    run_until_with_auth(listener, pending::<()>(), authenticator).await
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
    let authenticator = HandshakeAuthenticator::from_env_or_default_path()?;
    run_until_with_auth(listener, shutdown, authenticator).await
}

pub async fn run_until_with_auth(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
    authenticator: HandshakeAuthenticator,
) -> Result<(), BoxError> {
    let local_addr = listener.local_addr()?;
    let state = ServerState::new(authenticator);
    tokio::pin!(shutdown);

    info!("server listening on {}", local_addr);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
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
