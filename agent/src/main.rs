use std::error::Error;

use std::{collections::BTreeSet, env, path::Path, time::Duration};

use alaric_agent::{policy::Policy, session::run_secure_session};
use alaric_lib::constants::DEFAULT_SERVER_PORT;
use alaric_lib::protocol::{
    AgentId, HandshakeProofRequest, HandshakeRequest, HandshakeResponse, IdentityBundle,
    PeerAttestationPolicy, TrustedIdentityKeys, build_auth_proof_ed25519, read_json_frame,
    write_json_frame,
};
use alaric_lib::security::noise::types::Keypair;
use tokio::{net::TcpStream, time::sleep};
use tracing::{error, info};

mod signal;

const AGENT_TAGS_ENV: &str = "AGENT_TAGS";
const AGENT_IDENTITY_BUNDLE_PATH_ENV: &str = "AGENT_IDENTITY_BUNDLE_PATH";
const AGENT_PEER_ATTESTATION_POLICY_PATH_ENV: &str = "AGENT_PEER_ATTESTATION_POLICY_PATH";
const AGENT_POLICY_KEYS_PATH_ENV: &str = "AGENT_POLICY_KEYS_PATH";
const DEFAULT_AGENT_IDENTITY_BUNDLE_PATH: &str = "./identity-bundle.json";
const DEFAULT_AGENT_POLICY_KEYS_PATH: &str = "./policy-keys.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let shutdown = signal::shutdown_signal();
    tokio::pin!(shutdown);

    let addr = format!("127.0.0.1:{}", DEFAULT_SERVER_PORT);
    let agent_id = AgentId::new(env::var("AGENT_ID").unwrap_or_else(|_| "agent-default".into()))?;
    let auth_key_id = env::var("AGENT_AUTH_KEY_ID")
        .map_err(|_| "AGENT_AUTH_KEY_ID must be set for handshake authentication")?;
    let auth_private_key = env::var("AGENT_AUTH_PRIVATE_KEY")
        .map_err(|_| "AGENT_AUTH_PRIVATE_KEY must be set for handshake authentication")?;
    let policy_path =
        env::var("AGENT_POLICY_PATH").unwrap_or_else(|_| "./agent-policy.json".to_string());
    let policy = Policy::load(&policy_path)?;
    info!("loaded policy from {}", policy_path);
    let attestation_policy = load_agent_peer_attestation_policy()?;
    let identity_bundle = load_agent_identity_bundle()?;

    loop {
        let connect_result = tokio::select! {
            result = TcpStream::connect(&addr) => result,
            _ = &mut shutdown => {
                info!("shutdown signal received before connect, exiting");
                break;
            }
        };

        match connect_result {
            Ok(stream) => {
                tokio::select! {
                    result = connection_loop(
                        stream,
                        agent_id.clone(),
                        &auth_key_id,
                        &auth_private_key,
                        &attestation_policy,
                        &identity_bundle,
                        &policy,
                    ) => {
                        if let Err(err) = result {
                            error!("connection error: {}", err);
                        }
                    }
                    _ = &mut shutdown => {
                        info!("shutdown signal received, closing active connection");
                        break;
                    }
                }
            }
            Err(err) => {
                error!("connect failed: {}", err);
            }
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = &mut shutdown => {
                info!("shutdown signal received, exiting");
                break;
            }
        }
    }

    Ok(())
}

async fn connection_loop(
    mut stream: TcpStream,
    agent_id: AgentId,
    auth_key_id: &str,
    auth_private_key: &str,
    attestation_policy: &PeerAttestationPolicy,
    identity_bundle: &Option<IdentityBundle>,
    policy: &Policy,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("connected to {}", stream.peer_addr()?);
    let request = agent_handshake_request(agent_id.clone(), policy);
    write_json_frame(&mut stream, &request).await?;

    let challenge = match read_json_frame::<_, HandshakeResponse>(&mut stream).await? {
        HandshakeResponse::Challenge(challenge) => challenge,
        HandshakeResponse::Rejected(rejected) => {
            let rejected_code = format!("{:?}", rejected.code);
            return Err(format!(
                "handshake rejected for agent {} ({}): {}",
                agent_id, rejected_code, rejected.message
            )
            .into());
        }
        HandshakeResponse::Accepted(accepted) => {
            info!(
                "handshake accepted (agent_id={}, session_id={})",
                agent_id, accepted.session_id
            );
            run_secure_session(
                &mut stream,
                policy,
                Keypair::default_keypair(),
                accepted.session_id,
                &agent_id,
                auth_key_id,
                auth_private_key,
                attestation_policy,
                identity_bundle.as_ref(),
            )
            .await?;
            return Ok(());
        }
    };

    let proof = build_auth_proof_ed25519(&request, &challenge, auth_key_id, auth_private_key)?;
    write_json_frame(&mut stream, &HandshakeProofRequest::new(proof)).await?;

    let session_id = match read_json_frame::<_, HandshakeResponse>(&mut stream).await? {
        HandshakeResponse::Accepted(accepted) => {
            info!(
                "handshake accepted (agent_id={}, session_id={})",
                agent_id, accepted.session_id
            );
            accepted.session_id
        }
        HandshakeResponse::Rejected(rejected) => {
            let rejected_code = format!("{:?}", rejected.code);
            return Err(format!(
                "handshake rejected for agent {} ({}): {}",
                agent_id, rejected_code, rejected.message
            )
            .into());
        }
        HandshakeResponse::Challenge(_) => {
            return Err("unexpected second handshake challenge from server".into());
        }
    };

    run_secure_session(
        &mut stream,
        policy,
        Keypair::default_keypair(),
        session_id,
        &agent_id,
        auth_key_id,
        auth_private_key,
        attestation_policy,
        identity_bundle.as_ref(),
    )
    .await?;
    Ok(())
}

fn load_agent_peer_attestation_policy() -> Result<PeerAttestationPolicy, Box<dyn Error>> {
    let Some(path) = env::var(AGENT_PEER_ATTESTATION_POLICY_PATH_ENV).ok() else {
        info!(
            "{} not set; using default peer attestation policy (default_mode=preferred)",
            AGENT_PEER_ATTESTATION_POLICY_PATH_ENV
        );
        return Ok(PeerAttestationPolicy::default());
    };

    let policy = PeerAttestationPolicy::load_from_path(&path)?;
    info!("loaded peer attestation policy from {}", path);
    Ok(policy)
}

fn load_agent_identity_bundle() -> Result<Option<IdentityBundle>, Box<dyn Error>> {
    let configured_identity_bundle_path = env::var(AGENT_IDENTITY_BUNDLE_PATH_ENV).ok();
    let identity_bundle_path = configured_identity_bundle_path
        .clone()
        .unwrap_or_else(|| DEFAULT_AGENT_IDENTITY_BUNDLE_PATH.to_string());
    if configured_identity_bundle_path.is_none() && !Path::new(&identity_bundle_path).exists() {
        info!(
            "identity bundle '{}' not found; peer attestation will fall back based on policy",
            identity_bundle_path
        );
        return Ok(None);
    }

    let trusted_keys_path = env::var(AGENT_POLICY_KEYS_PATH_ENV)
        .unwrap_or_else(|_| DEFAULT_AGENT_POLICY_KEYS_PATH.to_string());
    let trusted_keys = TrustedIdentityKeys::load_from_path(&trusted_keys_path)?;

    let identity_bundle = IdentityBundle::load_from_path(&identity_bundle_path, &trusted_keys)?;
    info!(
        "loaded agent identity bundle from {} (expires_at_unix={})",
        identity_bundle_path,
        identity_bundle.expires_at_unix()
    );
    Ok(Some(identity_bundle))
}

fn agent_handshake_request(agent_id: AgentId, policy: &Policy) -> HandshakeRequest {
    let mut request = HandshakeRequest::agent(agent_id);
    let capabilities = collect_capabilities(policy);
    let tags = parse_csv_values(env::var(AGENT_TAGS_ENV).ok());

    if let HandshakeRequest::Agent { metadata, .. } = &mut request {
        if !capabilities.is_empty() {
            metadata.insert("capabilities".to_string(), capabilities.join(","));
        }
        if !tags.is_empty() {
            metadata.insert("tags".to_string(), tags.join(","));
        }
    }

    request
}

fn collect_capabilities(policy: &Policy) -> Vec<String> {
    let mut capabilities = BTreeSet::new();
    for command in &policy.commands {
        let command_id = command.id.trim();
        if !command_id.is_empty() {
            capabilities.insert(command_id.to_string());
        }
    }
    capabilities.into_iter().collect()
}

fn parse_csv_values(raw: Option<String>) -> Vec<String> {
    let mut values = BTreeSet::new();
    if let Some(raw) = raw {
        for value in raw.split(',') {
            let value = value.trim();
            if !value.is_empty() {
                values.insert(value.to_string());
            }
        }
    }
    values.into_iter().collect()
}
