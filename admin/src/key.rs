use std::error::Error;

use alaric_lib::database::{Database, KeyAddOutcome, KeyRevokeOutcome, principals::PrincipalKind};
use clap::{Args, Subcommand, ValueEnum};

#[derive(Args, Debug)]
pub(super) struct KeyCommand {
    #[command(subcommand)]
    command: KeySubcommand,
}

#[derive(Subcommand, Debug)]
enum KeySubcommand {
    Add(AddCommand),
    Rotate(RotateCommand),
    Revoke(RevokeCommand),
}

#[derive(Args, Debug)]
struct AddCommand {
    #[arg(value_enum)]
    kind: PrincipalKindArg,
    external_id: String,
    key_id: String,
    public_key_hex: String,
}

#[derive(Args, Debug)]
struct RotateCommand {
    #[arg(value_enum)]
    kind: PrincipalKindArg,
    external_id: String,
    new_key_id: String,
    new_public_key_hex: String,
}

#[derive(Args, Debug)]
struct RevokeCommand {
    #[arg(value_enum)]
    kind: PrincipalKindArg,
    external_id: String,
    key_id: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PrincipalKindArg {
    Agent,
    Client,
}

impl From<PrincipalKindArg> for PrincipalKind {
    fn from(value: PrincipalKindArg) -> Self {
        match value {
            PrincipalKindArg::Agent => Self::Agent,
            PrincipalKindArg::Client => Self::Client,
        }
    }
}

pub(super) async fn run(
    database: &Database,
    command: KeyCommand,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command.command {
        KeySubcommand::Add(command) => {
            let kind = PrincipalKind::from(command.kind);
            let outcome = database
                .admin_add_key(
                    kind,
                    &command.external_id,
                    &command.key_id,
                    &command.public_key_hex,
                )
                .await?;

            match outcome {
                KeyAddOutcome::Added => {
                    println!(
                        "key '{}' added for {} '{}'",
                        command.key_id,
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
                KeyAddOutcome::Updated => {
                    println!(
                        "key '{}' updated for {} '{}'",
                        command.key_id,
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
                KeyAddOutcome::PrincipalNotFound => {
                    println!(
                        "{} '{}' not found",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
            }
        }
        KeySubcommand::Rotate(command) => {
            let kind = PrincipalKind::from(command.kind);
            let outcome = database
                .admin_rotate_key(
                    kind,
                    &command.external_id,
                    &command.new_key_id,
                    &command.new_public_key_hex,
                )
                .await?;

            let Some(outcome) = outcome else {
                println!(
                    "{} '{}' not found",
                    principal_kind_name(kind),
                    command.external_id
                );
                return Ok(());
            };

            println!(
                "key '{}' rotated for {} '{}', revoked {} other keys",
                command.new_key_id,
                principal_kind_name(kind),
                command.external_id,
                outcome.revoked_other_keys
            );
        }
        KeySubcommand::Revoke(command) => {
            let kind = PrincipalKind::from(command.kind);
            let outcome = database
                .admin_revoke_key(kind, &command.external_id, &command.key_id)
                .await?;

            match outcome {
                KeyRevokeOutcome::Revoked => {
                    println!(
                        "key '{}' revoked for {} with id '{}'",
                        command.key_id,
                        principal_kind_name(kind),
                        command.external_id,
                    );
                }
                KeyRevokeOutcome::AlreadyRevoked => {
                    println!(
                        "key '{}' already revoked for {} with id '{}'",
                        command.key_id,
                        principal_kind_name(kind),
                        command.external_id,
                    );
                }
                KeyRevokeOutcome::KeyNotFound => {
                    println!(
                        "key '{}' not found for {} with id '{}'",
                        command.key_id,
                        principal_kind_name(kind),
                        command.external_id,
                    );
                }
                KeyRevokeOutcome::PrincipalNotFound => {
                    println!(
                        "{} '{}' not found",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
            }
        }
    }

    Ok(())
}

const fn principal_kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Agent => "agent",
        PrincipalKind::Client => "client",
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::Cli;

    #[test]
    fn parses_key_add() {
        let cli = Cli::try_parse_from([
            "aadmin",
            "key",
            "add",
            "agent",
            "agent-default",
            "agent-v1",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ])
        .expect("key add should parse");
        assert!(matches!(
            cli.command,
            crate::Command::Key(super::KeyCommand { .. })
        ));
    }

    #[test]
    fn parses_key_revoke() {
        let cli = Cli::try_parse_from([
            "aadmin",
            "key",
            "revoke",
            "client",
            "client-local",
            "client-local-v1",
        ])
        .expect("key revoke should parse");
        assert!(matches!(
            cli.command,
            crate::Command::Key(super::KeyCommand { .. })
        ));
    }
}
