use std::error::Error;

use clap::{Parser, Subcommand};

use crate::run::run_cmd;

mod list_agents;
mod run;
mod session;

type DynError = Box<dyn Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    ListAgents(list_agents::ListAgentsCommand),
    #[command(arg_required_else_help = true)]
    Run(run::RunCommand),
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let cli = Cli::parse();
    let auth = session::ClientAuth::load_from_env()?;

    match cli.command {
        Command::ListAgents(command) => list_agents::run(&auth, command).await?,
        Command::Run(command) => run_cmd(&auth, command).await?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::Cli;

    #[test]
    fn parses_list_agents() {
        let cli = Cli::try_parse_from(["alaric-client", "list-agents"])
            .expect("list-agents should parse");
        assert!(matches!(
            cli.command,
            crate::Command::ListAgents(super::list_agents::ListAgentsCommand)
        ));
    }

    #[test]
    fn parses_run() {
        let cli = Cli::try_parse_from([
            "alaric-client",
            "run",
            "--command-id",
            "echo_text",
            "--arg",
            "text=hello",
            "--target",
            "agent-default",
        ])
        .expect("run should parse");

        assert!(matches!(
            cli.command,
            crate::Command::Run(super::run::RunCommand { .. })
        ));
    }
}
