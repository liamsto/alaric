use std::error::Error;

use alaric_lib::database::{
    Database, GroupAddOutcome, GroupCreateOutcome, GroupDeleteOutcome, GroupMoveOutcome,
    GroupRemoveOutcome, GroupSetNameOutcome, GroupUpsertOutcome,
};
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub(super) struct GroupCommand {
    #[command(subcommand)]
    command: GroupSubcommand,
}

#[derive(Subcommand, Debug)]
enum GroupSubcommand {
    Create(CreateCommand),
    Upsert(UpsertCommand),
    Add(AddCommand),
    Remove(RemoveCommand),
    Move(MoveCommand),
    SetName(SetNameCommand),
    Delete(DeleteCommand),
    List,
}

#[derive(Args, Debug)]
struct CreateCommand {
    group_id: String,

    #[arg(long = "display-name")]
    display_name: Option<String>,
}

#[derive(Args, Debug)]
struct UpsertCommand {
    group_id: String,

    #[arg(long = "display-name")]
    display_name: Option<String>,

    #[arg(long = "member")]
    member_agent_ids: Vec<String>,
}

#[derive(Args, Debug)]
struct AddCommand {
    group_id: String,
    agent_id: String,
}

#[derive(Args, Debug)]
struct RemoveCommand {
    group_id: String,
    agent_id: String,
}

#[derive(Args, Debug)]
struct MoveCommand {
    old_group_id: String,
    new_group_id: String,
    agent_id: String,
}

#[derive(Args, Debug)]
struct SetNameCommand {
    group_id: String,
    display_name: String,
}

#[derive(Args, Debug)]
struct DeleteCommand {
    group_id: String,
}

pub(super) async fn run(
    database: &Database,
    command: GroupCommand,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command.command {
        GroupSubcommand::Create(command) => {
            let outcome = database
                .admin_create_agent_group(&command.group_id, command.display_name.as_deref())
                .await?;

            match outcome {
                GroupCreateOutcome::Created => {
                    println!("group created: id={}", command.group_id);
                }
                GroupCreateOutcome::AlreadyExists => {
                    println!("group already exists (no action): id={}", command.group_id);
                }
            }
        }
        GroupSubcommand::Upsert(command) => {
            let outcome = database
                .admin_upsert_agent_group(
                    &command.group_id,
                    command.display_name.as_deref(),
                    &command.member_agent_ids,
                )
                .await?;

            match outcome {
                GroupUpsertOutcome::Created => {
                    println!("group upserted (created): id={}", command.group_id);
                }
                GroupUpsertOutcome::Updated => {
                    println!("group upserted (updated): id={}", command.group_id);
                }
            }
        }
        GroupSubcommand::Add(command) => {
            let outcome = database
                .admin_add_agent_to_group(&command.group_id, &command.agent_id)
                .await?;

            match outcome {
                GroupAddOutcome::Added => {
                    println!(
                        "agent added to group: group_id={}, agent_id={}",
                        command.group_id, command.agent_id
                    );
                }
                GroupAddOutcome::AlreadyMember => {
                    println!(
                        "agent already in group (no action): group_id={}, agent_id={}",
                        command.group_id, command.agent_id
                    );
                }
                GroupAddOutcome::GroupNotFound => {
                    println!("group not found: id={}", command.group_id);
                }
                GroupAddOutcome::AgentNotFound => {
                    println!("agent not found or disabled: id={}", command.agent_id);
                }
            }
        }
        GroupSubcommand::Remove(command) => {
            let outcome = database
                .admin_remove_agent_from_group(&command.group_id, &command.agent_id)
                .await?;

            match outcome {
                GroupRemoveOutcome::Removed => {
                    println!(
                        "agent removed from group: group_id={}, agent_id={}",
                        command.group_id, command.agent_id
                    );
                }
                GroupRemoveOutcome::NotMember => {
                    println!(
                        "agent not in group (no action): group_id={}, agent_id={}",
                        command.group_id, command.agent_id
                    );
                }
                GroupRemoveOutcome::GroupNotFound => {
                    println!("group not found: id={}", command.group_id);
                }
                GroupRemoveOutcome::AgentNotFound => {
                    println!("agent not found or disabled: id={}", command.agent_id);
                }
            }
        }
        GroupSubcommand::Move(command) => {
            let outcome = database
                .admin_move_agent_between_groups(
                    &command.old_group_id,
                    &command.new_group_id,
                    &command.agent_id,
                )
                .await?;

            match outcome {
                GroupMoveOutcome::Moved {
                    removed_from_old_group,
                    added_to_new_group,
                } => match (removed_from_old_group, added_to_new_group) {
                    (true, true) => {
                        println!(
                            "agent moved: agent_id={}, from={}, to={}",
                            command.agent_id, command.old_group_id, command.new_group_id
                        );
                    }
                    (true, false) => {
                        println!(
                            "agent removed from old group; already in destination group: agent_id={}, from={}, to={}",
                            command.agent_id, command.old_group_id, command.new_group_id
                        );
                    }
                    (false, true) => {
                        println!(
                            "agent added to destination group; was not in source group: agent_id={}, from={}, to={}",
                            command.agent_id, command.old_group_id, command.new_group_id
                        );
                    }
                    (false, false) => {
                        println!(
                            "no move performed (already absent from source and present in destination): agent_id={}, from={}, to={}",
                            command.agent_id, command.old_group_id, command.new_group_id
                        );
                    }
                },
                GroupMoveOutcome::SourceGroupNotFound => {
                    println!("source group not found: id={}", command.old_group_id);
                }
                GroupMoveOutcome::DestinationGroupNotFound => {
                    println!("destination group not found: id={}", command.new_group_id);
                }
                GroupMoveOutcome::AgentNotFound => {
                    println!("agent not found or disabled: id={}", command.agent_id);
                }
                GroupMoveOutcome::SameGroup => {
                    println!(
                        "source and destination groups are identical (no action): id={}",
                        command.old_group_id
                    );
                }
            }
        }
        GroupSubcommand::SetName(command) => {
            let outcome = database
                .admin_set_agent_group_name(&command.group_id, &command.display_name)
                .await?;

            match outcome {
                GroupSetNameOutcome::Updated => {
                    println!("group display name updated: id={}", command.group_id);
                }
                GroupSetNameOutcome::GroupNotFound => {
                    println!("group not found: id={}", command.group_id);
                }
            }
        }
        GroupSubcommand::Delete(command) => {
            let outcome = database.admin_delete_agent_group(&command.group_id).await?;
            match outcome {
                GroupDeleteOutcome::Deleted => {
                    println!("group deleted: id={}", command.group_id);
                }
                GroupDeleteOutcome::NotFound => {
                    println!("group not found: id={}", command.group_id);
                }
            }
        }
        GroupSubcommand::List => {
            let groups = database.admin_list_agent_groups().await?;
            if groups.is_empty() {
                println!("no groups found");
                return Ok(());
            }

            println!("group_id\tmembers\tdisplay_name\tcreated_at");
            for group in groups {
                println!(
                    "{}\t{}\t{}\t{}",
                    group.external_id,
                    group.member_agent_ids.join(","),
                    group.display_name.unwrap_or_default(),
                    group.created_at.to_rfc3339(),
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::Cli;

    #[test]
    fn parses_group_upsert_with_member_flags() {
        let cli = Cli::try_parse_from([
            "aadmin",
            "group",
            "upsert",
            "ca-west-prod01",
            "--display-name",
            "Canada West Production 1",
            "--member",
            "agent-a",
            "--member",
            "agent-b",
        ])
        .expect("group upsert should parse");
        assert!(matches!(
            cli.command,
            crate::Command::Group(super::GroupCommand { .. })
        ));
    }

    #[test]
    fn parses_group_set_name() {
        let cli = Cli::try_parse_from([
            "aadmin",
            "group",
            "set-name",
            "ca-west-prod01",
            "CA West Name",
        ])
        .expect("group set-name should parse");
        assert!(matches!(
            cli.command,
            crate::Command::Group(super::GroupCommand { .. })
        ));
    }
}
