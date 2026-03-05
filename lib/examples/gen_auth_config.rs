use std::{collections::BTreeMap, env, error::Error, fs};

use hacl_star::ed25519;
use rand::random;
use serde::Serialize;

const AUTH_CONFIG_VERSION_V2: u16 = 2;
const DEFAULT_OUTPUT_PATH: &str = "./server-auth.json";
const DEFAULT_AGENT_ID: &str = "agent-default";
const DEFAULT_AGENT_KEY_ID: &str = "agent-default-v1";
const DEFAULT_CLIENT_ID: &str = "client-local";
const DEFAULT_CLIENT_KEY_ID: &str = "client-local-v1";

#[derive(Debug, Serialize)]
struct AuthConfigFile {
    version: u16,
    agents: BTreeMap<String, AuthConfigIdentity>,
    clients: BTreeMap<String, AuthConfigIdentity>,
}

#[derive(Debug, Serialize)]
struct AuthConfigIdentity {
    key_id: String,
    public_key: String,
}

fn generate_keypair_hex() -> (String, String) {
    let secret_key = random::<[u8; ed25519::SECRET_LENGTH]>();
    let public_key = ed25519::SecretKey(secret_key).get_public();
    (hex::encode(secret_key), hex::encode(public_key.0))
}

fn main() -> Result<(), Box<dyn Error>> {
    let output_path = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_OUTPUT_PATH.to_string());

    let (agent_private_key, agent_public_key) = generate_keypair_hex();
    let (client_private_key, client_public_key) = generate_keypair_hex();

    let config = AuthConfigFile {
        version: AUTH_CONFIG_VERSION_V2,
        agents: BTreeMap::from([(
            DEFAULT_AGENT_ID.to_string(),
            AuthConfigIdentity {
                key_id: DEFAULT_AGENT_KEY_ID.to_string(),
                public_key: agent_public_key,
            },
        )]),
        clients: BTreeMap::from([(
            DEFAULT_CLIENT_ID.to_string(),
            AuthConfigIdentity {
                key_id: DEFAULT_CLIENT_KEY_ID.to_string(),
                public_key: client_public_key,
            },
        )]),
    };

    let serialized = serde_json::to_string_pretty(&config)?;
    fs::write(&output_path, format!("{serialized}\n"))?;

    eprintln!("wrote handshake auth config to {output_path}");
    eprintln!(
        "source this output in terminals that run the agent/client, for example: source ./.dev-auth.env"
    );

    println!("export AGENT_AUTH_KEY_ID={DEFAULT_AGENT_KEY_ID}");
    println!("export AGENT_AUTH_PRIVATE_KEY={agent_private_key}");
    println!("export CLIENT_AUTH_KEY_ID={DEFAULT_CLIENT_KEY_ID}");
    println!("export CLIENT_AUTH_PRIVATE_KEY={client_private_key}");

    Ok(())
}
