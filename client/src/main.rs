use std::error::Error;

mod app;
mod signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    app::run().await
}
