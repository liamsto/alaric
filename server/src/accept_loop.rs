use std::future::{Future, pending};

use crate::{connection::handle_connection, error::BoxError, state::ServerState};
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run(listener: TcpListener) -> Result<(), BoxError> {
    run_until(listener, pending::<()>()).await
}

pub async fn run_until(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), BoxError> {
    let local_addr = listener.local_addr()?;
    let state = ServerState::new();
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
