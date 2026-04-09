use std::error::Error;

use alaric_lib::{
    database::{
        AttestationSetOutcome, Database, PrincipalAddOutcome, PrincipalDisableOutcome,
        principals::PrincipalKind,
    },
    protocol::PeerAttestationMode,
};
use clap::{Args, Subcommand, ValueEnum};

#[derive(Args, Debug)]
pub(super) struct PrincipalCommand {
    #[command(subcommand)]
    command: PrincipalSubcommand,
}

#[derive(Subcommand, Debug)]
enum PrincipalSubcommand {
    Add(AddCommand),
    SetAttestation(SetAttestationCommand),
    Disable(DisableCommand),
    List(ListCommand),
}

#[derive(Args, Debug)]
struct AddCommand {
    #[arg(value_enum)]
    kind: PrincipalKindArg,
    external_id: String,

    #[arg(long = "display-name")]
    display_name: Option<String>,

    #[arg(long, value_enum)]
    attestation: Option<AttestationModeArg>,
}

#[derive(Args, Debug)]
struct SetAttestationCommand {
    #[arg(value_enum)]
    kind: PrincipalKindArg,
    external_id: String,

    #[arg(value_enum)]
    attestation: AttestationModeArg,
}

#[derive(Args, Debug)]
struct DisableCommand {
    #[arg(value_enum)]
    kind: PrincipalKindArg,
    external_id: String,
}

#[derive(Args, Debug)]
struct ListCommand {
    #[arg(value_enum)]
    kind: Option<PrincipalListKindArg>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PrincipalKindArg {
    Agent,
    Client,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PrincipalListKindArg {
    Agent,
    Client,
    All,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AttestationModeArg {
    Required,
    Preferred,
    Disabled,
}

impl From<PrincipalKindArg> for PrincipalKind {
    fn from(value: PrincipalKindArg) -> Self {
        match value {
            PrincipalKindArg::Agent => Self::Agent,
            PrincipalKindArg::Client => Self::Client,
        }
    }
}

impl From<AttestationModeArg> for PeerAttestationMode {
    fn from(value: AttestationModeArg) -> Self {
        match value {
            AttestationModeArg::Required => Self::Required,
            AttestationModeArg::Preferred => Self::Preferred,
            AttestationModeArg::Disabled => Self::Disabled,
        }
    }
}

pub(super) async fn run(
    database: &Database,
    command: PrincipalCommand,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command.command {
        PrincipalSubcommand::Add(command) => {
            let kind = PrincipalKind::from(command.kind);
            let attestation_mode = command.attestation.map(PeerAttestationMode::from);
            let outcome = database
                .admin_add_principal(
                    kind,
                    &command.external_id,
                    command.display_name.as_deref(),
                    attestation_mode,
                )
                .await?;

            match outcome {
                PrincipalAddOutcome::Added => {
                    println!(
                        "{} '{}' added",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
                PrincipalAddOutcome::Reenabled => {
                    println!(
                        "{} '{}' re-enabled",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
                PrincipalAddOutcome::AlreadyActive => {
                    println!(
                        "{} '{}' already active",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
            }
        }
        PrincipalSubcommand::SetAttestation(command) => {
            let kind = PrincipalKind::from(command.kind);
            let attestation_mode = PeerAttestationMode::from(command.attestation);
            let outcome = database
                .admin_set_principal_attestation(kind, &command.external_id, attestation_mode)
                .await?;

            match outcome {
                AttestationSetOutcome::Updated => {
                    println!(
                        "{} '{}' attestation updated to {}",
                        principal_kind_name(kind),
                        command.external_id,
                        attestation_mode_name(attestation_mode)
                    );
                }
                AttestationSetOutcome::NotFound => {
                    println!(
                        "{} '{}' not found",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
            }
        }
        PrincipalSubcommand::Disable(command) => {
            let kind = PrincipalKind::from(command.kind);
            let outcome = database
                .admin_disable_principal(kind, &command.external_id)
                .await?;

            match outcome {
                PrincipalDisableOutcome::Disabled => {
                    println!(
                        "{} '{}' disabled",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
                PrincipalDisableOutcome::AlreadyDisabled => {
                    println!(
                        "{} '{}' already disabled",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
                PrincipalDisableOutcome::NotFound => {
                    println!(
                        "{} '{}' not found",
                        principal_kind_name(kind),
                        command.external_id
                    );
                }
            }
        }
        PrincipalSubcommand::List(command) => {
            let kind = match command.kind {
                Some(PrincipalListKindArg::Agent) => Some(PrincipalKind::Agent),
                Some(PrincipalListKindArg::Client) => Some(PrincipalKind::Client),
                Some(PrincipalListKindArg::All) | None => None,
            };

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

                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    principal_kind_name(principal.kind),
                    principal.external_id,
                    status,
                    attestation_mode_name(principal.attestation_mode),
                    principal.active_key_count,
                    principal.key_count,
                    principal.display_name.unwrap_or_default(),
                    principal.created_at.to_rfc3339(),
                );
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

const fn attestation_mode_name(mode: PeerAttestationMode) -> &'static str {
    match mode {
        PeerAttestationMode::Required => "required",
        PeerAttestationMode::Preferred => "preferred",
        PeerAttestationMode::Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::Cli;

    #[test]
    fn parses_principal_add() {
        let cli = Cli::try_parse_from([
            "aadmin",
            "principal",
            "add",
            "agent",
            "agent-default",
            "--display-name",
            "Agent Default",
            "--attestation",
            "required",
        ])
        .expect("principal add should parse");
        assert!(matches!(
            cli.command,
            crate::Command::Principal(super::PrincipalCommand { .. })
        ));
    }

    #[test]
    fn parses_principal_list_all() {
        let cli = Cli::try_parse_from(["aadmin", "principal", "list", "all"])
            .expect("principal list all should parse");
        assert!(matches!(
            cli.command,
            crate::Command::Principal(super::PrincipalCommand { .. })
        ));
    }
}
