use std::{env, error::Error, io, time::Duration};

use alaric_lib::{
    database::{
        AgentGroupCreateOutcome, AgentGroupDeleteOutcome, AgentGroupMemberAddOutcome,
        AgentGroupMemberRemoveOutcome, AgentGroupMoveOutcome, AgentGroupSetNameOutcome, Database,
        DatabaseConfig, KeyAddOutcome, KeyRevokeOutcome, PrincipalAddOutcome,
        PrincipalAttestationSetOutcome, PrincipalDisableOutcome, principals::PrincipalKind,
    },
    protocol::PeerAttestationMode,
};

#[derive(Debug)]
enum CliParseOutcome {
    Run(Command),
    PrintHelp,
}

#[derive(Debug)]
enum Command {
    PrincipalAdd {
        kind: PrincipalKind,
        external_id: String,
        display_name: Option<String>,
        attestation_mode: Option<PeerAttestationMode>,
    },
    PrincipalDisable {
        kind: PrincipalKind,
        external_id: String,
    },
    PrincipalSetAttestation {
        kind: PrincipalKind,
        external_id: String,
        attestation_mode: PeerAttestationMode,
    },
    PrincipalList {
        kind: Option<PrincipalKind>,
    },
    KeyAdd {
        kind: PrincipalKind,
        external_id: String,
        key_id: String,
        public_key_hex: String,
    },
    KeyRotate {
        kind: PrincipalKind,
        external_id: String,
        new_key_id: String,
        new_public_key_hex: String,
    },
    KeyRevoke {
        kind: PrincipalKind,
        external_id: String,
        key_id: String,
    },
    GroupCreate {
        group_id: String,
        display_name: Option<String>,
    },
    GroupAdd {
        group_id: String,
        agent_id: String,
    },
    GroupRemove {
        group_id: String,
        agent_id: String,
    },
    GroupMove {
        old_group_id: String,
        new_group_id: String,
        agent_id: String,
    },
    GroupSetName {
        group_id: String,
        display_name: String,
    },
    GroupDelete {
        external_id: String,
    },
    GroupList,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let command = match parse_cli_args(env::args().skip(1)) {
        Ok(CliParseOutcome::Run(command)) => command,
        Ok(CliParseOutcome::PrintHelp) => {
            println!("{}", usage_text());
            return Ok(());
        }
        Err(err) => return Err(format!("{}\n\n{}", err, usage_text()).into()),
    };

    let database = connect_database_from_env().await?;
    run_command(&database, command).await?;
    database.close().await;
    Ok(())
}

async fn connect_database_from_env() -> Result<Database, Box<dyn Error + Send + Sync>> {
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

async fn run_command(
    database: &Database,
    command: Command,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command {
        Command::PrincipalAdd {
            kind,
            external_id,
            display_name,
            attestation_mode,
        } => {
            let outcome = database
                .admin_add_principal(
                    kind,
                    &external_id,
                    display_name.as_deref(),
                    attestation_mode,
                )
                .await?;
            match outcome {
                PrincipalAddOutcome::Added => {
                    println!(
                        "principal added: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
                PrincipalAddOutcome::Reenabled => {
                    println!(
                        "principal re-enabled: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
                PrincipalAddOutcome::AlreadyActive => {
                    println!(
                        "principal already active: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
            }
        }
        Command::PrincipalSetAttestation {
            kind,
            external_id,
            attestation_mode,
        } => {
            let outcome = database
                .admin_set_principal_attestation(kind, &external_id, attestation_mode)
                .await?;
            match outcome {
                PrincipalAttestationSetOutcome::Updated => {
                    println!(
                        "principal attestation updated: kind={}, id={}, attestation={}",
                        principal_kind_name(kind),
                        external_id,
                        attestation_mode_name(attestation_mode)
                    );
                }
                PrincipalAttestationSetOutcome::NotFound => {
                    println!(
                        "principal not found: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
            }
        }
        Command::PrincipalDisable { kind, external_id } => {
            let outcome = database.admin_disable_principal(kind, &external_id).await?;
            match outcome {
                PrincipalDisableOutcome::Disabled => {
                    println!(
                        "principal disabled: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
                PrincipalDisableOutcome::AlreadyDisabled => {
                    println!(
                        "principal already disabled: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
                PrincipalDisableOutcome::NotFound => {
                    println!(
                        "principal not found: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
            }
        }
        Command::PrincipalList { kind } => {
            let principals = database.admin_list_principals(kind).await?;
            if principals.is_empty() {
                println!("no principals found");
                return Ok(());
            }

            println!(
                "kind\texternal_id\tstatus\tattestation\tactive_keys\ttotal_keys\tdisplay_name\tcreated_at"
            );
            for principal in principals {
                let status = if principal.disabled_at.is_some() {
                    "disabled"
                } else {
                    "active"
                };
                let display_name = principal.display_name.unwrap_or_default();
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    principal_kind_name(principal.kind),
                    principal.external_id,
                    status,
                    attestation_mode_name(principal.attestation_mode),
                    principal.active_key_count,
                    principal.key_count,
                    display_name,
                    principal.created_at.to_rfc3339(),
                );
            }
        }
        Command::KeyAdd {
            kind,
            external_id,
            key_id,
            public_key_hex,
        } => {
            let outcome = database
                .admin_add_key(kind, &external_id, &key_id, &public_key_hex)
                .await?;
            match outcome {
                KeyAddOutcome::Added => {
                    println!(
                        "key added: kind={}, id={}, key_id={}",
                        principal_kind_name(kind),
                        external_id,
                        key_id
                    );
                }
                KeyAddOutcome::Updated => {
                    println!(
                        "key updated: kind={}, id={}, key_id={}",
                        principal_kind_name(kind),
                        external_id,
                        key_id
                    );
                }
                KeyAddOutcome::PrincipalNotFound => {
                    println!(
                        "principal not found: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
            }
        }
        Command::KeyRotate {
            kind,
            external_id,
            new_key_id,
            new_public_key_hex,
        } => {
            let outcome = database
                .admin_rotate_key(kind, &external_id, &new_key_id, &new_public_key_hex)
                .await?;
            let Some(outcome) = outcome else {
                println!(
                    "principal not found: kind={}, id={}",
                    principal_kind_name(kind),
                    external_id
                );
                return Ok(());
            };

            let replacement = if outcome.replaced_existing_key {
                "updated existing key id"
            } else {
                "inserted new key id"
            };
            println!(
                "key rotated: kind={}, id={}, key_id={} ({}), revoked_other_keys={}",
                principal_kind_name(kind),
                external_id,
                new_key_id,
                replacement,
                outcome.revoked_other_keys
            );
        }
        Command::KeyRevoke {
            kind,
            external_id,
            key_id,
        } => {
            let outcome = database
                .admin_revoke_key(kind, &external_id, &key_id)
                .await?;
            match outcome {
                KeyRevokeOutcome::Revoked => {
                    println!(
                        "key revoked: kind={}, id={}, key_id={}",
                        principal_kind_name(kind),
                        external_id,
                        key_id
                    );
                }
                KeyRevokeOutcome::AlreadyRevoked => {
                    println!(
                        "key already revoked: kind={}, id={}, key_id={}",
                        principal_kind_name(kind),
                        external_id,
                        key_id
                    );
                }
                KeyRevokeOutcome::KeyNotFound => {
                    println!(
                        "key not found: kind={}, id={}, key_id={}",
                        principal_kind_name(kind),
                        external_id,
                        key_id
                    );
                }
                KeyRevokeOutcome::PrincipalNotFound => {
                    println!(
                        "principal not found: kind={}, id={}",
                        principal_kind_name(kind),
                        external_id
                    );
                }
            }
        }
        Command::GroupCreate {
            group_id,
            display_name,
        } => {
            let outcome = database
                .admin_create_agent_group(&group_id, display_name.as_deref())
                .await?;
            match outcome {
                AgentGroupCreateOutcome::Created => {
                    println!("group created: id={}", group_id);
                }
                AgentGroupCreateOutcome::AlreadyExists => {
                    println!("group already exists (no action): id={}", group_id);
                }
            }
        }
        Command::GroupAdd { group_id, agent_id } => {
            let outcome = database
                .admin_add_agent_to_group(&group_id, &agent_id)
                .await?;
            match outcome {
                AgentGroupMemberAddOutcome::Added => {
                    println!(
                        "agent added to group: group_id={}, agent_id={}",
                        group_id, agent_id
                    );
                }
                AgentGroupMemberAddOutcome::AlreadyMember => {
                    println!(
                        "agent already in group (no action): group_id={}, agent_id={}",
                        group_id, agent_id
                    );
                }
                AgentGroupMemberAddOutcome::GroupNotFound => {
                    println!("group not found: id={}", group_id);
                }
                AgentGroupMemberAddOutcome::AgentNotFound => {
                    println!("agent not found or disabled: id={}", agent_id);
                }
            }
        }
        Command::GroupRemove { group_id, agent_id } => {
            let outcome = database
                .admin_remove_agent_from_group(&group_id, &agent_id)
                .await?;
            match outcome {
                AgentGroupMemberRemoveOutcome::Removed => {
                    println!(
                        "agent removed from group: group_id={}, agent_id={}",
                        group_id, agent_id
                    );
                }
                AgentGroupMemberRemoveOutcome::NotMember => {
                    println!(
                        "agent not in group (no action): group_id={}, agent_id={}",
                        group_id, agent_id
                    );
                }
                AgentGroupMemberRemoveOutcome::GroupNotFound => {
                    println!("group not found: id={}", group_id);
                }
                AgentGroupMemberRemoveOutcome::AgentNotFound => {
                    println!("agent not found or disabled: id={}", agent_id);
                }
            }
        }
        Command::GroupMove {
            old_group_id,
            new_group_id,
            agent_id,
        } => {
            let outcome = database
                .admin_move_agent_between_groups(&old_group_id, &new_group_id, &agent_id)
                .await?;
            match outcome {
                AgentGroupMoveOutcome::Moved {
                    removed_from_old_group,
                    added_to_new_group,
                } => match (removed_from_old_group, added_to_new_group) {
                    (true, true) => {
                        println!(
                            "agent moved: agent_id={}, from={}, to={}",
                            agent_id, old_group_id, new_group_id
                        );
                    }
                    (true, false) => {
                        println!(
                            "agent removed from old group; already in destination group: agent_id={}, from={}, to={}",
                            agent_id, old_group_id, new_group_id
                        );
                    }
                    (false, true) => {
                        println!(
                            "agent added to destination group; was not in source group: agent_id={}, from={}, to={}",
                            agent_id, old_group_id, new_group_id
                        );
                    }
                    (false, false) => {
                        println!(
                            "no move performed (already absent from source and present in destination): agent_id={}, from={}, to={}",
                            agent_id, old_group_id, new_group_id
                        );
                    }
                },
                AgentGroupMoveOutcome::SourceGroupNotFound => {
                    println!("source group not found: id={}", old_group_id);
                }
                AgentGroupMoveOutcome::DestinationGroupNotFound => {
                    println!("destination group not found: id={}", new_group_id);
                }
                AgentGroupMoveOutcome::AgentNotFound => {
                    println!("agent not found or disabled: id={}", agent_id);
                }
                AgentGroupMoveOutcome::SameGroup => {
                    println!(
                        "source and destination groups are identical (no action): id={}",
                        old_group_id
                    );
                }
            }
        }
        Command::GroupSetName {
            group_id,
            display_name,
        } => {
            let outcome = database
                .admin_set_agent_group_name(&group_id, &display_name)
                .await?;
            match outcome {
                AgentGroupSetNameOutcome::Updated => {
                    println!("group display name updated: id={}", group_id);
                }
                AgentGroupSetNameOutcome::GroupNotFound => {
                    println!("group not found: id={}", group_id);
                }
            }
        }
        Command::GroupDelete { external_id } => {
            let outcome = database.admin_delete_agent_group(&external_id).await?;
            match outcome {
                AgentGroupDeleteOutcome::Deleted => {
                    println!("group deleted: id={}", external_id);
                }
                AgentGroupDeleteOutcome::NotFound => {
                    println!("group not found: id={}", external_id);
                }
            }
        }
        Command::GroupList => {
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

fn parse_cli_args(args: impl IntoIterator<Item = String>) -> Result<CliParseOutcome, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.is_empty() {
        return Ok(CliParseOutcome::PrintHelp);
    }
    if args[0] == "--help" || args[0] == "-h" {
        return Ok(CliParseOutcome::PrintHelp);
    }

    let command = match args[0].as_str() {
        "principal" => parse_principal_command(&args[1..])?,
        "key" => parse_key_command(&args[1..])?,
        "group" => parse_group_command(&args[1..])?,
        other => return Err(format!("unknown command '{}'", other)),
    };
    Ok(CliParseOutcome::Run(command))
}

fn parse_principal_command(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err("missing principal subcommand".to_string());
    }

    match args[0].as_str() {
        "add" => {
            if args.len() < 3 {
                return Err(
                    "principal add requires: principal add <agent|client> <external_id>"
                        .to_string(),
                );
            }
            let kind = parse_principal_kind(&args[1])?;
            let external_id = args[2].clone();

            let mut display_name = None;
            let mut attestation_mode = None;
            let mut index = 3usize;
            while index < args.len() {
                match args[index].as_str() {
                    "--display-name" => {
                        let Some(value) = args.get(index + 1) else {
                            return Err("--display-name requires a value".to_string());
                        };
                        display_name = Some(value.clone());
                        index += 2;
                    }
                    "--attestation" => {
                        let Some(value) = args.get(index + 1) else {
                            return Err("--attestation requires a value".to_string());
                        };
                        attestation_mode = Some(parse_attestation_mode(value)?);
                        index += 2;
                    }
                    value => {
                        return Err(format!("unknown argument '{}'", value));
                    }
                }
            }

            Ok(Command::PrincipalAdd {
                kind,
                external_id,
                display_name,
                attestation_mode,
            })
        }
        "set-attestation" => {
            if args.len() != 4 {
                return Err(
                    "principal set-attestation requires: principal set-attestation <agent|client> <external_id> <required|preferred|disabled>"
                        .to_string(),
                );
            }

            Ok(Command::PrincipalSetAttestation {
                kind: parse_principal_kind(&args[1])?,
                external_id: args[2].clone(),
                attestation_mode: parse_attestation_mode(&args[3])?,
            })
        }
        "disable" => {
            if args.len() != 3 {
                return Err(
                    "principal disable requires: principal disable <agent|client> <external_id>"
                        .to_string(),
                );
            }

            Ok(Command::PrincipalDisable {
                kind: parse_principal_kind(&args[1])?,
                external_id: args[2].clone(),
            })
        }
        "list" => {
            if args.len() == 1 {
                return Ok(Command::PrincipalList { kind: None });
            }
            if args.len() == 2 {
                if args[1] == "all" {
                    return Ok(Command::PrincipalList { kind: None });
                }
                return Ok(Command::PrincipalList {
                    kind: Some(parse_principal_kind(&args[1])?),
                });
            }

            Err("principal list accepts at most one optional kind: agent|client|all".to_string())
        }
        other => Err(format!("unknown principal subcommand '{}'", other)),
    }
}

fn parse_key_command(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err("missing key subcommand".to_string());
    }

    match args[0].as_str() {
        "add" => {
            if args.len() != 5 {
                return Err(
                    "key add requires: key add <agent|client> <external_id> <key_id> <public_key_hex>"
                        .to_string(),
                );
            }

            Ok(Command::KeyAdd {
                kind: parse_principal_kind(&args[1])?,
                external_id: args[2].clone(),
                key_id: args[3].clone(),
                public_key_hex: args[4].clone(),
            })
        }
        "rotate" => {
            if args.len() != 5 {
                return Err(
                    "key rotate requires: key rotate <agent|client> <external_id> <new_key_id> <new_public_key_hex>"
                        .to_string(),
                );
            }

            Ok(Command::KeyRotate {
                kind: parse_principal_kind(&args[1])?,
                external_id: args[2].clone(),
                new_key_id: args[3].clone(),
                new_public_key_hex: args[4].clone(),
            })
        }
        "revoke" => {
            if args.len() != 4 {
                return Err(
                    "key revoke requires: key revoke <agent|client> <external_id> <key_id>"
                        .to_string(),
                );
            }

            Ok(Command::KeyRevoke {
                kind: parse_principal_kind(&args[1])?,
                external_id: args[2].clone(),
                key_id: args[3].clone(),
            })
        }
        other => Err(format!("unknown key subcommand '{}'", other)),
    }
}

fn parse_group_command(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err("missing group subcommand".to_string());
    }

    match args[0].as_str() {
        "create" => {
            if args.len() < 2 {
                return Err(
                    "group create requires: group create <group_id> [--display-name <name>]"
                        .to_string(),
                );
            }

            let group_id = args[1].clone();
            let mut display_name = None;
            let mut index = 2usize;
            while index < args.len() {
                match args[index].as_str() {
                    "--display-name" => {
                        let Some(value) = args.get(index + 1) else {
                            return Err("--display-name requires a value".to_string());
                        };
                        display_name = Some(value.clone());
                        index += 2;
                    }
                    other => {
                        return Err(format!("unknown argument '{}'", other));
                    }
                }
            }

            Ok(Command::GroupCreate {
                group_id,
                display_name,
            })
        }
        "add" => {
            if args.len() != 3 {
                return Err("group add requires: group add <group_id> <agent_id>".to_string());
            }
            Ok(Command::GroupAdd {
                group_id: args[1].clone(),
                agent_id: args[2].clone(),
            })
        }
        "remove" => {
            if args.len() != 3 {
                return Err("group remove requires: group remove <group_id> <agent_id>".to_string());
            }
            Ok(Command::GroupRemove {
                group_id: args[1].clone(),
                agent_id: args[2].clone(),
            })
        }
        "move" => {
            if args.len() != 4 {
                return Err(
                    "group move requires: group move <old_group_id> <new_group_id> <agent_id>"
                        .to_string(),
                );
            }
            Ok(Command::GroupMove {
                old_group_id: args[1].clone(),
                new_group_id: args[2].clone(),
                agent_id: args[3].clone(),
            })
        }
        "set-name" => {
            if args.len() != 3 {
                return Err(
                    "group set-name requires: group set-name <group_id> <display_name>".to_string(),
                );
            }
            Ok(Command::GroupSetName {
                group_id: args[1].clone(),
                display_name: args[2].clone(),
            })
        }
        "delete" => {
            if args.len() != 2 {
                return Err("group delete requires: group delete <group_id>".to_string());
            }
            Ok(Command::GroupDelete {
                external_id: args[1].clone(),
            })
        }
        "list" => {
            if args.len() != 1 {
                return Err("group list does not take additional arguments".to_string());
            }
            Ok(Command::GroupList)
        }
        other => Err(format!("unknown group subcommand '{}'", other)),
    }
}

fn parse_principal_kind(raw: &str) -> Result<PrincipalKind, String> {
    match raw {
        "agent" => Ok(PrincipalKind::Agent),
        "client" => Ok(PrincipalKind::Client),
        _ => Err(format!(
            "invalid principal kind '{}'; expected 'agent' or 'client'",
            raw
        )),
    }
}

fn parse_attestation_mode(raw: &str) -> Result<PeerAttestationMode, String> {
    match raw {
        "required" => Ok(PeerAttestationMode::Required),
        "preferred" => Ok(PeerAttestationMode::Preferred),
        "disabled" => Ok(PeerAttestationMode::Disabled),
        _ => Err(format!(
            "invalid attestation mode '{}'; expected 'required', 'preferred', or 'disabled'",
            raw
        )),
    }
}

const fn principal_kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Agent => "agent",
        PrincipalKind::Client => "client",
    }
}

const fn attestation_mode_name(mode: PeerAttestationMode) -> &'static str {
    match mode {
        PeerAttestationMode::Required => "required",
        PeerAttestationMode::Preferred => "preferred",
        PeerAttestationMode::Disabled => "disabled",
    }
}

const fn usage_text() -> &'static str {
    "Usage:
  aadmin principal add <agent|client> <external_id> [--display-name <name>] [--attestation <required|preferred|disabled>]
  aadmin principal set-attestation <agent|client> <external_id> <required|preferred|disabled>
  aadmin principal disable <agent|client> <external_id>
  aadmin principal list [agent|client|all]
  aadmin key add <agent|client> <external_id> <key_id> <public_key_hex>
  aadmin key rotate <agent|client> <external_id> <new_key_id> <new_public_key_hex>
  aadmin key revoke <agent|client> <external_id> <key_id>
  aadmin group create <group_id> [--display-name <name>]
  aadmin group add <group_id> <agent_id>
  aadmin group remove <group_id> <agent_id>
  aadmin group move <old_group_id> <new_group_id> <agent_id>
  aadmin group set-name <group_id> <display_name>
  aadmin group delete <group_id>
  aadmin group list

Environment:
  DATABASE_URL                   Required postgres URL
  DATABASE_MAX_CONNECTIONS       Optional, defaults to 10
  DATABASE_ACQUIRE_TIMEOUT_SECS  Optional, defaults to 5"
}

#[cfg(test)]
mod tests {
    use super::{CliParseOutcome, Command, PrincipalKind, parse_cli_args};
    use alaric_lib::protocol::PeerAttestationMode;

    #[test]
    fn parses_principal_add_agent() {
        let args = vec![
            "principal".to_string(),
            "add".to_string(),
            "agent".to_string(),
            "agent-a".to_string(),
            "--display-name".to_string(),
            "Agent A".to_string(),
        ];

        let parsed = parse_cli_args(args).expect("principal add should parse");
        let CliParseOutcome::Run(Command::PrincipalAdd {
            kind,
            external_id,
            display_name,
            attestation_mode,
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(kind, PrincipalKind::Agent);
        assert_eq!(external_id, "agent-a");
        assert_eq!(display_name.as_deref(), Some("Agent A"));
        assert_eq!(attestation_mode, None);
    }

    #[test]
    fn parses_principal_add_with_attestation_mode() {
        let args = vec![
            "principal".to_string(),
            "add".to_string(),
            "client".to_string(),
            "client-a".to_string(),
            "--attestation".to_string(),
            "required".to_string(),
        ];

        let parsed = parse_cli_args(args).expect("principal add should parse");
        let CliParseOutcome::Run(Command::PrincipalAdd {
            kind,
            external_id,
            attestation_mode,
            ..
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(kind, PrincipalKind::Client);
        assert_eq!(external_id, "client-a");
        assert_eq!(attestation_mode, Some(PeerAttestationMode::Required));
    }

    #[test]
    fn parses_principal_disable_client() {
        let args = vec![
            "principal".to_string(),
            "disable".to_string(),
            "client".to_string(),
            "client-a".to_string(),
        ];

        let parsed = parse_cli_args(args).expect("principal disable should parse");
        let CliParseOutcome::Run(Command::PrincipalDisable { kind, external_id }) = parsed else {
            panic!("unexpected command parse result");
        };
        assert_eq!(kind, PrincipalKind::Client);
        assert_eq!(external_id, "client-a");
    }

    #[test]
    fn parses_key_rotate() {
        let args = vec![
            "key".to_string(),
            "rotate".to_string(),
            "agent".to_string(),
            "agent-a".to_string(),
            "agent-a-v2".to_string(),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c".to_string(),
        ];

        let parsed = parse_cli_args(args).expect("key rotate should parse");
        let CliParseOutcome::Run(Command::KeyRotate {
            kind,
            external_id,
            new_key_id,
            ..
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(kind, PrincipalKind::Agent);
        assert_eq!(external_id, "agent-a");
        assert_eq!(new_key_id, "agent-a-v2");
    }

    #[test]
    fn rejects_unknown_kind() {
        let args = vec![
            "principal".to_string(),
            "add".to_string(),
            "server".to_string(),
            "server-a".to_string(),
        ];

        let err = parse_cli_args(args).expect_err("invalid kind should fail");
        assert!(err.contains("invalid principal kind"));
    }

    #[test]
    fn parses_principal_set_attestation() {
        let args = vec![
            "principal".to_string(),
            "set-attestation".to_string(),
            "agent".to_string(),
            "agent-a".to_string(),
            "disabled".to_string(),
        ];

        let parsed = parse_cli_args(args).expect("set-attestation should parse");
        let CliParseOutcome::Run(Command::PrincipalSetAttestation {
            kind,
            external_id,
            attestation_mode,
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(kind, PrincipalKind::Agent);
        assert_eq!(external_id, "agent-a");
        assert_eq!(attestation_mode, PeerAttestationMode::Disabled);
    }

    #[test]
    fn parses_group_create_with_display_name() {
        let args = vec![
            "group".to_string(),
            "create".to_string(),
            "ca-west-prod01".to_string(),
            "--display-name".to_string(),
            "CA West".to_string(),
        ];

        let parsed = parse_cli_args(args).expect("group create should parse");
        let CliParseOutcome::Run(Command::GroupCreate {
            group_id,
            display_name,
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(group_id, "ca-west-prod01");
        assert_eq!(display_name.as_deref(), Some("CA West"));
    }

    #[test]
    fn parses_group_add() {
        let args = vec![
            "group".to_string(),
            "add".to_string(),
            "ca-west-prod01".to_string(),
            "agent-a".to_string(),
        ];
        let parsed = parse_cli_args(args).expect("group add should parse");
        let CliParseOutcome::Run(Command::GroupAdd { group_id, agent_id }) = parsed else {
            panic!("unexpected command parse result");
        };
        assert_eq!(group_id, "ca-west-prod01");
        assert_eq!(agent_id, "agent-a");
    }

    #[test]
    fn parses_group_remove() {
        let args = vec![
            "group".to_string(),
            "remove".to_string(),
            "ca-west-prod01".to_string(),
            "agent-a".to_string(),
        ];
        let parsed = parse_cli_args(args).expect("group remove should parse");
        let CliParseOutcome::Run(Command::GroupRemove { group_id, agent_id }) = parsed else {
            panic!("unexpected command parse result");
        };
        assert_eq!(group_id, "ca-west-prod01");
        assert_eq!(agent_id, "agent-a");
    }

    #[test]
    fn parses_group_move() {
        let args = vec![
            "group".to_string(),
            "move".to_string(),
            "ca-west-prod01".to_string(),
            "ca-west-prod02".to_string(),
            "agent-a".to_string(),
        ];
        let parsed = parse_cli_args(args).expect("group move should parse");
        let CliParseOutcome::Run(Command::GroupMove {
            old_group_id,
            new_group_id,
            agent_id,
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(old_group_id, "ca-west-prod01");
        assert_eq!(new_group_id, "ca-west-prod02");
        assert_eq!(agent_id, "agent-a");
    }

    #[test]
    fn parses_group_set_name() {
        let args = vec![
            "group".to_string(),
            "set-name".to_string(),
            "ca-west-prod01".to_string(),
            "CA West Name".to_string(),
        ];
        let parsed = parse_cli_args(args).expect("group set-name should parse");
        let CliParseOutcome::Run(Command::GroupSetName {
            group_id,
            display_name,
        }) = parsed
        else {
            panic!("unexpected command parse result");
        };
        assert_eq!(group_id, "ca-west-prod01");
        assert_eq!(display_name, "CA West Name");
    }

    #[test]
    fn parses_group_list() {
        let args = vec!["group".to_string(), "list".to_string()];
        let parsed = parse_cli_args(args).expect("group list should parse");
        assert!(matches!(parsed, CliParseOutcome::Run(Command::GroupList)));
    }
}
