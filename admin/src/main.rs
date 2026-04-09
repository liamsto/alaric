use clap::{Parser, Subcommand};
use std::{env, error::Error, io, time::Duration};

use alaric_lib::database::{Database, DatabaseConfig};

mod group;
mod key;
mod principal;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(arg_required_else_help = true)]
    Principal(principal::PrincipalCommand),
    #[command(arg_required_else_help = true)]
    Key(key::KeyCommand),
    #[command(arg_required_else_help = true)]
    Group(group::GroupCommand),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let cli = Cli::parse();
    let database = connect_env().await?;

    match cli.command {
        Command::Principal(command) => principal::run(&database, command).await?,
        Command::Key(command) => key::run(&database, command).await?,
        Command::Group(command) => group::run(&database, command).await?,
    }

    database.close().await;
    Ok(())
}

async fn connect_env() -> Result<Database, Box<dyn Error + Send + Sync>> {
    let database_url = env::var("DATABASE_URL").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DATABASE_URL must be set before running admin commands",
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

    Ok(Database::connect_and_migrate(&config).await?)
}
