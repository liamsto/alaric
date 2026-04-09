use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    error::Error,
    io::{self, Write},
    path::Path,
};

use alaric_lib::{
    constants::DEFAULT_SERVER_PORT,
    protocol::{
        AgentGroupId, AgentId, AgentMessage, ClientId, ClientMessage, CommandId,
        HandshakeProofRequest, HandshakeRequest, HandshakeResponse, IdentityBundle,
        ListAgentsResponse, OutputStream, PeerAttestationInit, PeerAttestationMode,
        PeerAttestationPolicy, PeerAttestationResult, RequestId, Role, SecureChannel, SessionId,
        TrustedIdentityKeys, build_auth_proof_ed25519, build_peer_attestation_proof,
        read_json_frame, recv_secure_json, send_secure_json, verify_peer_attestation_proof,
        write_json_frame,
    },
    security::noise::types::Keypair,
};
use tokio::net::TcpStream;

const CLIENT_IDENTITY_BUNDLE_PATH_ENV: &str = "CLIENT_IDENTITY_BUNDLE_PATH";
const CLIENT_PEER_ATTESTATION_POLICY_PATH_ENV: &str = "CLIENT_PEER_ATTESTATION_POLICY_PATH";
const CLIENT_TRUSTED_KEYS_PATH_ENV: &str = "CLIENT_TRUSTED_KEYS_PATH";
const DEFAULT_CLIENT_IDENTITY_BUNDLE_PATH: &str = "./identity-bundle.json";
const DEFAULT_CLIENT_TRUSTED_KEYS_PATH: &str = "./policy-keys.json";

#[derive(Debug)]
struct RunCliArgs {
    command_id: CommandId,
    args: BTreeMap<String, String>,
    targets: Vec<AgentId>,
    groups: Vec<AgentGroupId>,
}

#[derive(Debug)]
struct AuthenticatedConnection {
    stream: TcpStream,
    session_id: SessionId,
}

#[derive(Debug)]
enum CliCommand {
    Run(RunCliArgs),
    ListAgents,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli_command = match parse_cli_args(env::args().skip(1)) {
        Ok(CliParseOutcome::Run(command)) => command,
        Ok(CliParseOutcome::PrintHelp) => {
            println!("{}", usage_text());
            return Ok(());
        }
        Err(err) => {
            return Err(format!("{}\n\n{}", err, usage_text()).into());
        }
    };

    let client_id = ClientId::new(
        env::var("CLIENT_ID").unwrap_or_else(|_| format!("client-{}", std::process::id())),
    )?;
    let auth_key_id = env::var("CLIENT_AUTH_KEY_ID")
        .map_err(|_| "CLIENT_AUTH_KEY_ID must be set for handshake authentication")?;
    let auth_private_key = env::var("CLIENT_AUTH_PRIVATE_KEY")
        .map_err(|_| "CLIENT_AUTH_PRIVATE_KEY must be set for handshake authentication")?;

    match cli_command {
        CliCommand::ListAgents => {
            let response = fetch_discovery(&client_id, &auth_key_id, &auth_private_key).await?;
            print_discovered_agents(&response);
            Ok(())
        }
        CliCommand::Run(run_args) => {
            let attestation_policy = load_attestation_policy()?;
            let identity_bundle = load_identity()?;
            let targets =
                resolve_targets(&run_args, &client_id, &auth_key_id, &auth_private_key).await?;
            let multi_target = targets.len() > 1;
            let mut failed_targets = Vec::new();
            for target in targets {
                if multi_target {
                    println!("==> target={}", target);
                }

                let command_result = run_cmd(
                    &client_id,
                    &target,
                    &run_args,
                    &auth_key_id,
                    &auth_private_key,
                    &attestation_policy,
                    identity_bundle.as_ref(),
                    multi_target,
                )
                .await;
                if let Err(err) = command_result {
                    println!("target {} failed: {}", target, err);
                    failed_targets.push(target.to_string());
                }
            }

            if failed_targets.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "command failed for {} target(s): {}",
                    failed_targets.len(),
                    failed_targets.join(", ")
                )
                .into())
            }
        }
    }
}

async fn resolve_targets(
    run_args: &RunCliArgs,
    client_id: &ClientId,
    auth_key_id: &str,
    auth_private_key: &str,
) -> Result<Vec<AgentId>, Box<dyn Error>> {
    let mut seen_targets = BTreeSet::new();
    let mut targets = Vec::new();

    for target in &run_args.targets {
        if seen_targets.insert(target.as_str().to_string()) {
            targets.push(target.clone());
        }
    }

    if !run_args.groups.is_empty() {
        let discovery = fetch_discovery(client_id, auth_key_id, auth_private_key).await?;
        let group_members = discovery
            .groups
            .into_iter()
            .map(|group| (group.group_id.as_str().to_string(), group.members))
            .collect::<HashMap<_, _>>();

        for group_id in &run_args.groups {
            let Some(members) = group_members.get(group_id.as_str()) else {
                return Err(format!("unknown agent group '{}'", group_id).into());
            };

            for member in members {
                if seen_targets.insert(member.as_str().to_string()) {
                    targets.push(member.clone());
                }
            }
        }
    }

    if targets.is_empty() {
        let target_agent_id = AgentId::new(
            env::var("TARGET_AGENT_ID").unwrap_or_else(|_| "agent-default".to_string()),
        )?;
        targets.push(target_agent_id);
    }

    Ok(targets)
}

async fn fetch_discovery(
    client_id: &ClientId,
    auth_key_id: &str,
    auth_private_key: &str,
) -> Result<ListAgentsResponse, Box<dyn Error>> {
    let request = HandshakeRequest::client_discovery(client_id.clone());
    let mut connection = connect_authenticated(&request, auth_key_id, auth_private_key).await?;
    let response = read_json_frame::<_, ListAgentsResponse>(&mut connection.stream).await?;
    Ok(response)
}

async fn run_cmd(
    client_id: &ClientId,
    target_agent_id: &AgentId,
    run_args: &RunCliArgs,
    auth_key_id: &str,
    auth_private_key: &str,
    attestation_policy: &PeerAttestationPolicy,
    identity_bundle: Option<&IdentityBundle>,
    multi_target: bool,
) -> Result<(), Box<dyn Error>> {
    let request = HandshakeRequest::client(client_id.clone(), target_agent_id.clone());
    let mut connection = connect_authenticated(&request, auth_key_id, auth_private_key).await?;
    let mut secure =
        SecureChannel::handshake_xx_initiator(&mut connection.stream, Keypair::default_keypair())
            .await?;
    perform_peer_attestation(
        &mut secure,
        &mut connection.stream,
        &connection.session_id,
        client_id,
        target_agent_id,
        auth_key_id,
        auth_private_key,
        attestation_policy,
        identity_bundle,
    )
    .await?;

    let request_id = RequestId(1);
    let execute = ClientMessage::Execute {
        request_id,
        command_id: run_args.command_id.clone(),
        args: run_args.args.clone(),
    };
    send_secure_json(&mut secure, &mut connection.stream, &execute).await?;

    loop {
        let message =
            recv_secure_json::<_, AgentMessage>(&mut secure, &mut connection.stream).await?;

        match message {
            AgentMessage::Started {
                request_id: message_request_id,
            } if message_request_id == request_id => {
                println!(
                    "command started (target_agent_id={}, request_id={})",
                    target_agent_id, request_id
                );
            }
            AgentMessage::Output {
                request_id: message_request_id,
                stream: output_stream,
                chunk,
            } if message_request_id == request_id => {
                print_output(target_agent_id, output_stream, &chunk, multi_target)?;
            }
            AgentMessage::Completed {
                request_id: message_request_id,
                exit_code,
                timed_out,
                truncated,
            } if message_request_id == request_id => {
                println!(
                    "command completed (target_agent_id={}, request_id={}, exit_code={}, timed_out={}, truncated={})",
                    target_agent_id, request_id, exit_code, timed_out, truncated
                );
                if let Some(failure_message) =
                    completion_failure_message(exit_code, timed_out, truncated)
                {
                    return Err(format!(
                        "command failed (request_id={}): {}",
                        request_id, failure_message
                    )
                    .into());
                }
                break;
            }
            AgentMessage::Rejected {
                request_id: message_request_id,
                code,
                message,
            } if message_request_id == request_id => {
                return Err(format!(
                    "command rejected (request_id={}, code={:?}): {}",
                    request_id, code, message
                )
                .into());
            }
            _ => {}
        }
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
                print!("{}", chunk);
                io::stdout().flush()?;
            }
            OutputStream::Stderr => {
                eprint!("{}", chunk);
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
                print!("[{}:{}] {}", target_agent_id, stream_label, segment);
                io::stdout().flush()?;
            }
            OutputStream::Stderr => {
                eprint!("[{}:{}] {}", target_agent_id, stream_label, segment);
                io::stderr().flush()?;
            }
        }
    }

    if !chunk.ends_with('\n') {
        match stream {
            OutputStream::Stdout => {
                io::stdout().flush()?;
            }
            OutputStream::Stderr => {
                io::stderr().flush()?;
            }
        }
    }

    Ok(())
}

async fn connect_authenticated(
    request: &HandshakeRequest,
    auth_key_id: &str,
    auth_private_key: &str,
) -> Result<AuthenticatedConnection, Box<dyn Error>> {
    let addr = format!("127.0.0.1:{}", DEFAULT_SERVER_PORT);
    let mut stream = TcpStream::connect(addr).await?;
    println!("connected to {}", stream.peer_addr()?);

    write_json_frame(&mut stream, request).await?;

    let initial = read_json_frame::<_, HandshakeResponse>(&mut stream).await?;
    let final_response = match initial {
        HandshakeResponse::Challenge(challenge) => {
            let proof =
                build_auth_proof_ed25519(request, &challenge, auth_key_id, auth_private_key)?;
            let proof_request = HandshakeProofRequest::new(proof);
            write_json_frame(&mut stream, &proof_request).await?;
            read_json_frame::<_, HandshakeResponse>(&mut stream).await?
        }
        other => other,
    };

    match final_response {
        HandshakeResponse::Accepted(accepted) => {
            let client_context = match request {
                HandshakeRequest::Client { client_id, .. } => client_id.to_string(),
                HandshakeRequest::ClientDiscovery { client_id, .. } => client_id.to_string(),
                HandshakeRequest::Agent { .. } => "<agent-request>".to_string(),
            };
            println!(
                "handshake accepted (client_id={}, {}, session_id={})",
                client_context,
                request_context(request),
                accepted.session_id
            );
            Ok(AuthenticatedConnection {
                stream,
                session_id: accepted.session_id,
            })
        }
        HandshakeResponse::Rejected(rejected) => Err(format!(
            "handshake rejected ({}): {:?}: {}",
            request_context(request),
            rejected.code,
            rejected.message
        )
        .into()),
        HandshakeResponse::Challenge(_) => {
            Err("unexpected second handshake challenge from server".into())
        }
    }
}

fn load_attestation_policy() -> Result<PeerAttestationPolicy, Box<dyn Error>> {
    let Some(path) = env::var(CLIENT_PEER_ATTESTATION_POLICY_PATH_ENV).ok() else {
        println!(
            "{} not set; using default peer attestation policy (default_mode=preferred)",
            CLIENT_PEER_ATTESTATION_POLICY_PATH_ENV
        );
        return Ok(PeerAttestationPolicy::default());
    };

    let policy = PeerAttestationPolicy::load_from_path(&path)?;
    println!("loaded peer attestation policy from {}", path);
    Ok(policy)
}

fn load_identity() -> Result<Option<IdentityBundle>, Box<dyn Error>> {
    let configured_identity_bundle_path = env::var(CLIENT_IDENTITY_BUNDLE_PATH_ENV).ok();
    let identity_bundle_path = configured_identity_bundle_path
        .clone()
        .unwrap_or_else(|| DEFAULT_CLIENT_IDENTITY_BUNDLE_PATH.to_string());
    if configured_identity_bundle_path.is_none() && !Path::new(&identity_bundle_path).exists() {
        println!(
            "identity bundle '{}' not found; peer attestation will fall back based on policy",
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
) -> Result<(), Box<dyn Error>> {
    let mode = attestation_policy.resolve(client_id, target_agent_id);
    let handshake_hash = secure.handshake_hash();
    let mut client_proof = None;
    if mode != PeerAttestationMode::Disabled {
        match identity_bundle
            .and_then(|bundle| bundle.agent_identity_key(target_agent_id))
            .is_some()
        {
            true => {
                client_proof = Some(build_peer_attestation_proof(
                    session_id,
                    handshake_hash,
                    client_id,
                    target_agent_id,
                    Role::Client,
                    auth_key_id,
                    auth_private_key,
                )?);
            }
            false if mode.requires_attestation() => {
                return Err(format!(
                    "peer attestation is required for client '{}' and agent '{}', but the identity bundle is missing key material for target '{}'",
                    client_id, target_agent_id, target_agent_id
                )
                .into());
            }
            false => {}
        }
    }

    let init = PeerAttestationInit {
        client_id: client_id.clone(),
        proof: client_proof,
    };
    send_secure_json(secure, stream, &init).await?;

    let result = recv_secure_json::<_, PeerAttestationResult>(secure, stream).await?;
    if !result.accepted {
        let message = result
            .message
            .unwrap_or_else(|| "peer attestation rejected by agent".to_string());
        return Err(message.into());
    }

    let mut verified = false;
    if let Some(agent_proof) = result.agent_proof {
        let identity_bundle = identity_bundle.ok_or_else(|| {
            "agent sent peer attestation proof, but no identity bundle is loaded".to_string()
        })?;
        let Some(agent_identity) = identity_bundle.agent_identity_key(target_agent_id) else {
            return Err(format!(
                "identity bundle does not contain key material for target agent '{}'",
                target_agent_id
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
            return Err(format!(
                "peer attestation failed while verifying agent '{}'",
                target_agent_id
            )
            .into());
        }
    }

    if mode.requires_attestation() && !verified {
        return Err(format!(
            "peer attestation is required for client '{}' and agent '{}', but the session was not attested",
            client_id, target_agent_id
        )
        .into());
    }

    Ok(())
}

enum CliParseOutcome {
    Run(CliCommand),
    PrintHelp,
}

fn parse_cli_args(args: impl IntoIterator<Item = String>) -> Result<CliParseOutcome, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|value| value == "--help" || value == "-h")
    {
        return Ok(CliParseOutcome::PrintHelp);
    }

    if args.first().is_some_and(|value| value == "list-agents") {
        if args.len() != 1 {
            return Err("list-agents does not take additional arguments".to_string());
        }
        return Ok(CliParseOutcome::Run(CliCommand::ListAgents));
    }

    if args.first().is_some_and(|value| value == "run")
        && args
            .get(1)
            .is_some_and(|value| value == "--help" || value == "-h")
    {
        return Ok(CliParseOutcome::PrintHelp);
    }

    let run_args = if args.first().is_some_and(|value| value == "run") {
        parse_run_args(args.iter().skip(1).cloned())?
    } else {
        parse_run_args(args)?
    };

    Ok(CliParseOutcome::Run(CliCommand::Run(run_args)))
}

fn parse_run_args(args: impl IntoIterator<Item = String>) -> Result<RunCliArgs, String> {
    let mut command_id = env::var("COMMAND_ID").ok();
    let mut parsed_args = BTreeMap::new();
    let mut targets = Vec::new();
    let mut groups = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--command-id" => {
                let Some(value) = iter.next() else {
                    return Err("--command-id requires a value".to_string());
                };
                if value.is_empty() {
                    return Err("--command-id must not be empty".to_string());
                }
                command_id = Some(value);
            }
            "--arg" => {
                let Some(value) = iter.next() else {
                    return Err("--arg requires a key=value value".to_string());
                };
                let Some((key, val)) = value.split_once('=') else {
                    return Err(format!(
                        "invalid --arg value '{}'; expected key=value",
                        value
                    ));
                };
                if key.is_empty() {
                    return Err("argument key must not be empty".to_string());
                }
                parsed_args.insert(key.to_string(), val.to_string());
            }
            "--target" => {
                let Some(value) = iter.next() else {
                    return Err("--target requires an agent id".to_string());
                };
                let target = AgentId::new(value)
                    .map_err(|err| format!("invalid --target value: {}", err))?;
                targets.push(target);
            }
            "--group" => {
                let Some(value) = iter.next() else {
                    return Err("--group requires a group id".to_string());
                };
                let group = AgentGroupId::new(value)
                    .map_err(|err| format!("invalid --group value: {}", err))?;
                groups.push(group);
            }
            _ => {
                return Err(format!("unknown argument '{}'", arg));
            }
        }
    }

    let command_id = command_id.ok_or_else(|| "missing --command-id".to_string())?;
    let command_id = CommandId::new(command_id).map_err(|err| {
        format!(
            "invalid command id provided via --command-id/COMMAND_ID: {}",
            err
        )
    })?;
    Ok(RunCliArgs {
        command_id,
        args: parsed_args,
        targets,
        groups,
    })
}

const fn usage_text() -> &'static str {
    "Usage:
  alaric-client list-agents
  alaric-client run --command-id <id> [--target <agent_id>]... [--group <group_id>]... [--arg name=value]...
  alaric-client --command-id <id> [--target <agent_id>]... [--group <group_id>]... [--arg name=value]...

Environment:
  CLIENT_ID               Optional client id (default: client-<pid>)
  TARGET_AGENT_ID         Optional single-target fallback when --target/--group are omitted (default: agent-default)
  CLIENT_AUTH_KEY_ID      Required handshake auth key id for this client id
  CLIENT_AUTH_PRIVATE_KEY Required Ed25519 private key hex for this client id
  CLIENT_PEER_ATTESTATION_POLICY_PATH Optional peer attestation policy JSON path
  CLIENT_TRUSTED_KEYS_PATH Optional trusted identity-signing keys path (default: ./policy-keys.json, used when loading identity bundle)
  CLIENT_IDENTITY_BUNDLE_PATH Optional signed identity bundle path (default: ./identity-bundle.json if present)
  COMMAND_ID              Optional fallback for --command-id"
}

fn request_context(request: &HandshakeRequest) -> String {
    match request {
        HandshakeRequest::Client {
            target_agent_id, ..
        } => format!("target={}", target_agent_id),
        HandshakeRequest::ClientDiscovery { .. } => "mode=discovery".to_string(),
        HandshakeRequest::Agent { .. } => "mode=agent".to_string(),
    }
}

fn print_discovered_agents(response: &ListAgentsResponse) {
    if response.agents.is_empty() {
        println!("no agents discovered");
    } else {
        println!("agent_id\tstatus\tstatus_age_secs\tcapabilities\ttags\tdisplay_name");
        for agent in &response.agents {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                agent.agent_id,
                agent.status.as_str(),
                agent.status_age_secs,
                agent.capabilities.join(","),
                agent.tags.join(","),
                agent.display_name.as_deref().unwrap_or("")
            );
        }
    }

    if response.groups.is_empty() {
        return;
    }

    println!();
    println!("group_id\tmembers\tdisplay_name");
    for group in &response.groups {
        let members = group
            .members
            .iter()
            .map(|member| member.as_str())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}",
            group.group_id,
            members,
            group.display_name.as_deref().unwrap_or("")
        );
    }
}

fn completion_failure_message(exit_code: i32, timed_out: bool, truncated: bool) -> Option<String> {
    let mut reasons = Vec::new();
    if exit_code != 0 {
        reasons.push(format!("exit_code={}", exit_code));
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
    use super::{CliCommand, CliParseOutcome, completion_failure_message, parse_cli_args};

    #[test]
    fn completion_success_has_no_failure_message() {
        assert_eq!(completion_failure_message(0, false, false), None);
    }

    #[test]
    fn non_zero_exit_reports_failure() {
        assert_eq!(
            completion_failure_message(2, false, false),
            Some("exit_code=2".to_string())
        );
    }

    #[test]
    fn timeout_and_truncation_are_reported() {
        assert_eq!(
            completion_failure_message(0, true, true),
            Some("timed_out=true, truncated=true".to_string())
        );
    }

    #[test]
    fn parse_list_agents_command() {
        let parsed = parse_cli_args(["list-agents".to_string()]).expect("list-agents should parse");
        assert!(matches!(
            parsed,
            CliParseOutcome::Run(CliCommand::ListAgents)
        ));
    }

    #[test]
    fn parse_legacy_run_command() {
        let parsed = parse_cli_args([
            "--command-id".to_string(),
            "echo_text".to_string(),
            "--arg".to_string(),
            "text=hello".to_string(),
        ])
        .expect("legacy run args should parse");

        assert!(matches!(parsed, CliParseOutcome::Run(CliCommand::Run(_))));
    }

    #[test]
    fn parse_run_command_with_targets_and_groups() {
        let parsed = parse_cli_args([
            "run".to_string(),
            "--command-id".to_string(),
            "echo_text".to_string(),
            "--target".to_string(),
            "agent-a".to_string(),
            "--group".to_string(),
            "ca-west-prod01".to_string(),
        ])
        .expect("multi-target run args should parse");

        let CliParseOutcome::Run(CliCommand::Run(run_args)) = parsed else {
            panic!("unexpected parse outcome");
        };

        assert_eq!(run_args.targets.len(), 1);
        assert_eq!(run_args.targets[0].as_str(), "agent-a");
        assert_eq!(run_args.groups.len(), 1);
        assert_eq!(run_args.groups[0].as_str(), "ca-west-prod01");
    }
}
