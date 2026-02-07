use std::error::Error;

use lib::constants::DEFAULT_SERVER_PORT;
use tokio::net::TcpListener;

mod signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_SERVER_PORT)).await?;
    alaric_server::run_until(listener, signal::shutdown_signal()).await
}
