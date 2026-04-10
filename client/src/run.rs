use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    io::{self, Write},
    path::Path,
};

use alaric_lib::{
    protocol::{
        AgentGroupId, AgentId, AgentMessage, ClientId, ClientMessage, CommandId, HandshakeRequest,
        IdentityBundle, OutputStream, PeerAttestationInit, PeerAttestationMode,
        PeerAttestationPolicy, PeerAttestationResult, RequestId, Role, SecureChannel, SessionId,
        TrustedIdentityKeys, build_peer_attestation_proof, recv_secure_json, send_secure_json,
        verify_peer_attestation_proof,
    },
    security::noise::types::Keypair,
};
use clap::Args;
use tokio::net::TcpStream;

use crate::{DynError, session};

const CLIENT_IDENTITY_BUNDLE_PATH_ENV: &str = "CLIENT_IDENTITY_BUNDLE_PATH";
const CLIENT_PEER_ATTESTATION_POLICY_PATH_ENV: &str = "CLIENT_PEER_ATTESTATION_POLICY_PATH";
const CLIENT_TRUSTED_KEYS_PATH_ENV: &str = "CLIENT_TRUSTED_KEYS_PATH";
const DEFAULT_CLIENT_IDENTITY_BUNDLE_PATH: &str = "./identity-bundle.json";
const DEFAULT_CLIENT_TRUSTED_KEYS_PATH: &str = "./policy-keys.json";

#[derive(Args, Debug)]
pub(super) struct RunCommand {
    #[arg(long = "command-id")]
    command_id: Option<String>,

    #[arg(long = "arg", value_name = "NAME=VALUE", value_parser = parse_named_arg)]
    args: Vec<(String, String)>,

    #[arg(long = "target", value_name = "AGENT_ID")]
    targets: Vec<String>,

    #[arg(long = "group", value_name = "GROUP_ID")]
    groups: Vec<String>,
}

pub(super) async fn run_cmd(
    auth: &session::ClientAuth,
    command: RunCommand,
) -> Result<(), DynError> {
    let command_id = resolve_command_id(command.command_id)?;
    let args = command.args.into_iter().collect::<BTreeMap<_, _>>();

    let attestation_policy = load_attestation_policy()?;
    let identity_bundle = load_identity()?;
    let targets = resolve_targets(&command.targets, &command.groups, auth).await?;

    let multi_target = targets.len() > 1;
    let mut failed_targets = Vec::new();

    for target in targets {
        if multi_target {
            println!("target '{}'", target);
        }

        let outcome = run_for_target(
            auth,
            &target,
            &command_id,
            &args,
            &attestation_policy,
            identity_bundle.as_ref(),
            multi_target,
        )
        .await;

        if let Err(err) = outcome {
            println!("target '{}' failed: {err}", target);
            failed_targets.push(target.to_string());
        }
    }

    if failed_targets.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "command failed for {} target(s): {}",
            failed_targets.len(),
            failed_targets.join(", ")
        ))
        .into())
    }
}

async fn run_for_target(
    auth: &session::ClientAuth,
    target_agent_id: &AgentId,
    command_id: &CommandId,
    args: &BTreeMap<String, String>,
    attestation_policy: &PeerAttestationPolicy,
    identity_bundle: Option<&IdentityBundle>,
    with_target_prefix: bool,
) -> Result<(), DynError> {
    let request = HandshakeRequest::client(auth.client_id.clone(), target_agent_id.clone());
    let mut connection = session::connect_authenticated(&request, auth).await?;
    let mut secure =
        SecureChannel::handshake_xx_initiator(&mut connection.stream, Keypair::default_keypair())
            .await?;

    perform_peer_attestation(
        &mut secure,
        &mut connection.stream,
        &connection.session_id,
        &auth.client_id,
        target_agent_id,
        &auth.auth_key_id,
        &auth.auth_private_key,
        attestation_policy,
        identity_bundle,
    )
    .await?;

    let request_id = RequestId(1);
    send_secure_json(
        &mut secure,
        &mut connection.stream,
        &ClientMessage::Execute {
            request_id,
            command_id: command_id.clone(),
            args: args.clone(),
        },
    )
    .await?;

    loop {
        let message =
            recv_secure_json::<_, AgentMessage>(&mut secure, &mut connection.stream).await?;

        match message {
            AgentMessage::Started {
                request_id: message_request_id,
            } if message_request_id == request_id => {
                println!(
                    "command '{}' started for target '{}'",
                    command_id, target_agent_id
                );
            }
            AgentMessage::Output {
                request_id: message_request_id,
                stream,
                chunk,
            } if message_request_id == request_id => {
                print_output(target_agent_id, stream, &chunk, with_target_prefix)?;
            }
            AgentMessage::Completed {
                request_id: message_request_id,
                exit_code,
                timed_out,
                truncated,
            } if message_request_id == request_id => {
                println!(
                    "command '{}' completed for target '{}' (exit_code={}, timed_out={}, truncated={})",
                    command_id, target_agent_id, exit_code, timed_out, truncated,
                );

                if let Some(failure_message) =
                    completion_failure_message(exit_code, timed_out, truncated)
                {
                    return Err(io::Error::other(format!(
                        "command failed (request_id={}): {}",
                        request_id, failure_message
                    ))
                    .into());
                }

                break;
            }
            AgentMessage::Rejected {
                request_id: message_request_id,
                code,
                message,
            } if message_request_id == request_id => {
                return Err(io::Error::other(format!(
                    "command rejected (request_id={}, code={:?}): {}",
                    request_id, code, message
                ))
                .into());
            }
            _ => {}
        }
    }

    Ok(())
}

async fn resolve_targets(
    explicit_targets: &[String],
    groups: &[String],
    auth: &session::ClientAuth,
) -> Result<Vec<AgentId>, DynError> {
    let mut seen_targets = BTreeSet::new();
    let mut targets = Vec::new();

    for target in explicit_targets {
        let agent_id = AgentId::new(target.clone()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid --target '{target}': {err}"),
            )
        })?;

        if seen_targets.insert(agent_id.as_str().to_string()) {
            targets.push(agent_id);
        }
    }

    if !groups.is_empty() {
        let discovery = session::fetch_discovery(auth).await?;
        let group_members = discovery
            .groups
            .into_iter()
            .map(|group| (group.group_id.as_str().to_string(), group.members))
            .collect::<HashMap<_, _>>();

        for group in groups {
            let group_id = AgentGroupId::new(group.clone()).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid --group '{group}': {err}"),
                )
            })?;

            let Some(members) = group_members.get(group_id.as_str()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown agent group '{group_id}'"),
                )
                .into());
            };

            for member in members {
                if seen_targets.insert(member.as_str().to_string()) {
                    targets.push(member.clone());
                }
            }
        }
    }

    if targets.is_empty() {
        let fallback_target = AgentId::new(
            env::var("TARGET_AGENT_ID").unwrap_or_else(|_| "agent-default".to_string()),
        )
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid TARGET_AGENT_ID value: {err}"),
            )
        })?;
        targets.push(fallback_target);
    }

    Ok(targets)
}

fn resolve_command_id(value: Option<String>) -> Result<CommandId, DynError> {
    let command_id = value
        .or_else(|| env::var("COMMAND_ID").ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --command-id"))?;

    CommandId::new(command_id).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid command id provided via --command-id/COMMAND_ID: {err}"),
        )
        .into()
    })
}

fn parse_named_arg(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err(format!("invalid --arg value '{raw}'; expected NAME=VALUE"));
    };

    if name.is_empty() {
        return Err("argument name must not be empty".to_string());
    }

    Ok((name.to_string(), value.to_string()))
}

fn load_attestation_policy() -> Result<PeerAttestationPolicy, DynError> {
    let Some(path) = env::var(CLIENT_PEER_ATTESTATION_POLICY_PATH_ENV).ok() else {
        println!(
            "{} not set; using default peer attestation policy",
            CLIENT_PEER_ATTESTATION_POLICY_PATH_ENV
        );
        return Ok(PeerAttestationPolicy::default());
    };

    let policy = PeerAttestationPolicy::load_from_path(&path)?;
    println!("loaded peer attestation policy from {path}");
    Ok(policy)
}

fn load_identity() -> Result<Option<IdentityBundle>, DynError> {
    let configured_identity_bundle_path = env::var(CLIENT_IDENTITY_BUNDLE_PATH_ENV).ok();
    let identity_bundle_path = configured_identity_bundle_path
        .clone()
        .unwrap_or_else(|| DEFAULT_CLIENT_IDENTITY_BUNDLE_PATH.to_string());

    if configured_identity_bundle_path.is_none() && !Path::new(&identity_bundle_path).exists() {
        println!(
            "identity bundle '{}' not found; peer attestation may fall back based on policy",
            identity_bundle_path
        );
        return Ok(None);
    }

    let trusted_keys_path = env::var(CLIENT_TRUSTED_KEYS_PATH_ENV)
        .unwrap_or_else(|_| DEFAULT_CLIENT_TRUSTED_KEYS_PATH.to_string());
    let trusted_keys = TrustedIdentityKeys::load_from_path(&trusted_keys_path)?;

    let identity_bundle = IdentityBundle::load_from_path(&identity_bundle_path, &trusted_keys)?;
    println!(
        "loaded client identity bundle from {} (expires_at_unix={})",
        identity_bundle_path,
        identity_bundle.expires_at_unix()
    );

    Ok(Some(identity_bundle))
}

#[allow(clippy::too_many_arguments)]
async fn perform_peer_attestation(
    secure: &mut SecureChannel,
    stream: &mut TcpStream,
    session_id: &SessionId,
    client_id: &ClientId,
    target_agent_id: &AgentId,
    auth_key_id: &str,
    auth_private_key: &str,
    attestation_policy: &PeerAttestationPolicy,
    identity_bundle: Option<&IdentityBundle>,
) -> Result<(), DynError> {
    let mode = attestation_policy.resolve(client_id, target_agent_id);
    let handshake_hash = secure.handshake_hash();

    let mut client_proof = None;
    if mode != PeerAttestationMode::Disabled {
        if identity_bundle
            .and_then(|bundle| bundle.agent_identity_key(target_agent_id))
            .is_some()
        {
            client_proof = Some(build_peer_attestation_proof(
                session_id,
                handshake_hash,
                client_id,
                target_agent_id,
                Role::Client,
                auth_key_id,
                auth_private_key,
            )?);
        } else if mode.requires_attestation() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "peer attestation is required for client '{}' and agent '{}', but the identity bundle is missing key material for target '{}'",
                    client_id, target_agent_id, target_agent_id
                ),
            )
            .into());
        }
    }

    send_secure_json(
        secure,
        stream,
        &PeerAttestationInit {
            client_id: client_id.clone(),
            proof: client_proof,
        },
    )
    .await?;

    let result = recv_secure_json::<_, PeerAttestationResult>(secure, stream).await?;
    if !result.accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            result
                .message
                .unwrap_or_else(|| "peer attestation rejected by agent".to_string()),
        )
        .into());
    }

    let mut verified = false;
    if let Some(agent_proof) = result.agent_proof {
        let identity_bundle = identity_bundle.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent sent peer attestation proof, but no identity bundle is loaded",
            )
        })?;

        let Some(agent_identity) = identity_bundle.agent_identity_key(target_agent_id) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "identity bundle does not contain key material for target agent '{}'",
                    target_agent_id
                ),
            )
            .into());
        };

        verified = verify_peer_attestation_proof(
            &agent_proof,
            session_id,
            handshake_hash,
            client_id,
            target_agent_id,
            Role::Agent,
            &agent_identity.key_id,
            agent_identity.public_key,
        )?;

        if !verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "peer attestation failed while verifying agent '{}'",
                    target_agent_id
                ),
            )
            .into());
        }
    }

    if mode.requires_attestation() && !verified {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "peer attestation is required for client '{}' and agent '{}', but the session was not attested",
                client_id, target_agent_id
            ),
        )
        .into());
    }

    Ok(())
}

fn print_output(
    target_agent_id: &AgentId,
    stream: OutputStream,
    chunk: &str,
    with_target_prefix: bool,
) -> Result<(), io::Error> {
    if !with_target_prefix {
        match stream {
            OutputStream::Stdout => {
                print!("{chunk}");
                io::stdout().flush()?;
            }
            OutputStream::Stderr => {
                eprint!("{chunk}");
                io::stderr().flush()?;
            }
        }
        return Ok(());
    }

    let stream_label = match stream {
        OutputStream::Stdout => "stdout",
        OutputStream::Stderr => "stderr",
    };

    for segment in chunk.split_inclusive('\n') {
        match stream {
            OutputStream::Stdout => {
                print!("[{target_agent_id}:{stream_label}] {segment}");
                io::stdout().flush()?;
            }
            OutputStream::Stderr => {
                eprint!("[{target_agent_id}:{stream_label}] {segment}");
                io::stderr().flush()?;
            }
        }
    }

    if !chunk.ends_with('\n') {
        match stream {
            OutputStream::Stdout => io::stdout().flush()?,
            OutputStream::Stderr => io::stderr().flush()?,
        }
    }

    Ok(())
}

fn completion_failure_message(exit_code: i32, timed_out: bool, truncated: bool) -> Option<String> {
    let mut reasons = Vec::new();

    if exit_code != 0 {
        reasons.push(format!("exit_code={exit_code}"));
    }
    if timed_out {
        reasons.push("timed_out=true".to_string());
    }
    if truncated {
        reasons.push("truncated=true".to_string());
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::{completion_failure_message, parse_named_arg};

    #[test]
    fn parses_arg_pair() {
        assert_eq!(
            parse_named_arg("text=hello").expect("arg should parse"),
            ("text".to_string(), "hello".to_string())
        );
    }

    #[test]
    fn rejects_arg_without_name() {
        assert!(parse_named_arg("=hello").is_err());
    }

    #[test]
    fn completion_success_has_no_failure_message() {
        assert_eq!(completion_failure_message(0, false, false), None);
    }

    #[test]
    fn completion_failure_lists_reasons() {
        assert_eq!(
            completion_failure_message(2, true, true),
            Some("exit_code=2, timed_out=true, truncated=true".to_string())
        );
    }
}
