use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use alaric_lib::protocol::{IdentityPrincipal, sign_identity_bundle_ed25519};
use serde::Deserialize;

const DEFAULT_AUTH_CONFIG_PATH: &str = "./server-auth.json";
const DEFAULT_OUTPUT_PATH: &str = "./identity-bundle.json";
const DEFAULT_EXPIRES_IN_SECS: u64 = 60 * 60 * 24 * 365;
const SIGNING_KEY_ID_ENV: &str = "IDENTITY_BUNDLE_SIGNING_KEY_ID";
const SIGNING_PRIVATE_KEY_ENV: &str = "IDENTITY_BUNDLE_SIGNING_PRIVATE_KEY";
const EXPIRES_AT_ENV: &str = "IDENTITY_BUNDLE_EXPIRES_AT_UNIX";

#[derive(Debug, Deserialize)]
struct AuthConfigFile {
    version: u16,
    #[serde(default)]
    agents: BTreeMap<String, AuthConfigIdentity>,
    #[serde(default)]
    clients: BTreeMap<String, AuthConfigIdentity>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigIdentity {
    key_id: String,
    public_key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let auth_config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_AUTH_CONFIG_PATH.to_string());
    let output_path = env::args()
        .nth(2)
        .unwrap_or_else(|| DEFAULT_OUTPUT_PATH.to_string());

    let signing_key_id =
        env::var(SIGNING_KEY_ID_ENV).map_err(|_| format!("{} must be set", SIGNING_KEY_ID_ENV))?;
    let signing_private_key = env::var(SIGNING_PRIVATE_KEY_ENV)
        .map_err(|_| format!("{} must be set", SIGNING_PRIVATE_KEY_ENV))?;

    let expires_at_unix = match env::var(EXPIRES_AT_ENV) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|err| format!("invalid {} '{}': {}", EXPIRES_AT_ENV, raw, err))?,
        Err(_) => current_unix_timestamp()?.saturating_add(DEFAULT_EXPIRES_IN_SECS),
    };

    let raw = fs::read_to_string(&auth_config_path)?;
    let auth_config: AuthConfigFile = serde_json::from_str(&raw)?;
    if auth_config.version != 2 {
        return Err(format!(
            "unsupported auth config version {}; expected 2",
            auth_config.version
        )
        .into());
    }

    let agents = auth_config
        .agents
        .into_iter()
        .map(|(external_id, identity)| {
            (
                external_id,
                IdentityPrincipal {
                    key_id: identity.key_id,
                    public_key: identity.public_key,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let clients = auth_config
        .clients
        .into_iter()
        .map(|(external_id, identity)| {
            (
                external_id,
                IdentityPrincipal {
                    key_id: identity.key_id,
                    public_key: identity.public_key,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let signed_bundle = sign_identity_bundle_ed25519(
        expires_at_unix,
        agents,
        clients,
        &signing_key_id,
        &signing_private_key,
    )?;
    let serialized = serde_json::to_string_pretty(&signed_bundle)?;
    fs::write(&output_path, format!("{serialized}\n"))?;

    eprintln!("wrote signed identity bundle to {}", output_path);
    eprintln!("expires_at_unix={}", expires_at_unix);
    Ok(())
}

fn current_unix_timestamp() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
