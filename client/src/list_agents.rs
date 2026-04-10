use clap::Args;

use crate::{DynError, session};

#[derive(Args, Debug)]
pub(super) struct ListAgentsCommand;

pub(super) async fn run(auth: &session::ClientAuth, _: ListAgentsCommand) -> Result<(), DynError> {
    let response = session::fetch_discovery(auth).await?;

    if response.agents.is_empty() {
        println!("no agents discovered");
    } else {
        println!("agent_id\tstatus\tstatus_age_secs\tcapabilities\ttags\tdisplay_name");
        for agent in response.agents {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                agent.agent_id,
                agent.status.as_str(),
                agent.status_age_secs,
                agent.capabilities.join(","),
                agent.tags.join(","),
                agent.display_name.unwrap_or_default(),
            );
        }
    }

    if response.groups.is_empty() {
        return Ok(());
    }

    println!();
    println!("group_id\tmembers\tdisplay_name");
    for group in response.groups {
        println!(
            "{}\t{}\t{}",
            group.group_id,
            group
                .members
                .iter()
                .map(|member| member.as_str())
                .collect::<Vec<_>>()
                .join(","),
            group.display_name.unwrap_or_default(),
        );
    }

    Ok(())
}
