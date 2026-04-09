use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use hacl_star::ed25519::{self, PublicKey};
use serde::{Deserialize, Serialize};

use super::{AgentId, ClientId};

const IDENTITY_BUNDLE_SIGNING_CONTEXT_V1: &str = "alaric-identity-bundle-v1";
pub const IDENTITY_BUNDLE_VERSION_V1: u16 = 1;
pub const IDENTITY_BUNDLE_SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPrincipal {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBundleSignature {
    pub key_id: String,
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIdentityBundle {
    pub bundle_version: u16,
    pub expires_at_unix: u64,
    #[serde(default)]
    pub agents: BTreeMap<String, IdentityPrincipal>,
    #[serde(default)]
    pub clients: BTreeMap<String, IdentityPrincipal>,
    pub signature: IdentityBundleSignature,
}

#[derive(Debug, Serialize)]
struct IdentityBundleSigningPayload<'a> {
    context: &'static str,
    bundle_version: u16,
    expires_at_unix: u64,
    key_id: &'a str,
    algorithm: &'a str,
    agents: &'a BTreeMap<String, IdentityPrincipal>,
    clients: &'a BTreeMap<String, IdentityPrincipal>,
}

#[derive(Debug, Clone)]
pub struct IdentityPublicKey {
    pub key_id: String,
    pub public_key: [u8; ed25519::PUBLIC_LENGTH],
}

#[derive(Debug, Clone)]
pub struct IdentityBundle {
    expires_at_unix: u64,
    agents: HashMap<AgentId, IdentityPublicKey>,
    clients: HashMap<ClientId, IdentityPublicKey>,
}

#[derive(Clone)]
pub struct TrustedIdentityKeys {
    keys: HashMap<String, PublicKey>,
}

#[derive(Debug)]
pub enum IdentityBundleError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Invalid(String),
}

impl fmt::Display for IdentityBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityBundleError::Io { path, source } => {
                write!(
                    f,
                    "failed to read identity bundle file '{}': {}",
                    path.display(),
                    source
                )
            }
            IdentityBundleError::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse identity bundle file '{}': {}",
                    path.display(),
                    source
                )
            }
            IdentityBundleError::Invalid(message) => {
                write!(f, "invalid identity bundle: {}", message)
            }
        }
    }
}

impl Error for IdentityBundleError {}

impl TrustedIdentityKeys {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, IdentityBundleError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| IdentityBundleError::Io {
            path: path.clone(),
            source,
        })?;
        Self::from_json_map(&raw).map_err(|err| {
            IdentityBundleError::Invalid(format!("{} (in '{}')", err, path.display()))
        })
    }

    pub fn from_json_map(raw: &str) -> Result<Self, IdentityBundleError> {
        let entries: BTreeMap<String, String> = serde_json::from_str(raw).map_err(|source| {
            IdentityBundleError::Invalid(format!(
                "failed to parse trusted identity keys JSON: {}",
                source
            ))
        })?;

        if entries.is_empty() {
            return Err(IdentityBundleError::Invalid(
                "trusted identity keys must contain at least one entry".to_string(),
            ));
        }

        let mut keys = HashMap::new();
        for (key_id, encoded_key) in entries {
            if key_id.trim().is_empty() {
                return Err(IdentityBundleError::Invalid(
                    "trusted identity key id must not be empty".to_string(),
                ));
            }

            let key_bytes = decode_hex_array::<{ ed25519::PUBLIC_LENGTH }>(
                &format!("trusted identity key '{}'", key_id),
                &encoded_key,
            )?;
            keys.insert(key_id, ed25519::PublicKey(key_bytes));
        }

        Ok(Self { keys })
    }

    fn get(&self, key_id: &str) -> Option<&PublicKey> {
        self.keys.get(key_id)
    }
}

impl IdentityBundle {
    pub fn load_from_path(
        path: impl AsRef<Path>,
        trusted_keys: &TrustedIdentityKeys,
    ) -> Result<Self, IdentityBundleError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| IdentityBundleError::Io {
            path: path.clone(),
            source,
        })?;

        let signed: SignedIdentityBundle =
            serde_json::from_str(&raw).map_err(|source| IdentityBundleError::Parse {
                path: path.clone(),
                source,
            })?;
        let now_unix = current_unix_timestamp()?;
        Self::from_signed_bundle_at(signed, trusted_keys, now_unix)
    }

    pub fn from_signed_json(
        raw: &str,
        trusted_keys: &TrustedIdentityKeys,
    ) -> Result<Self, IdentityBundleError> {
        let signed: SignedIdentityBundle = serde_json::from_str(raw).map_err(|source| {
            IdentityBundleError::Invalid(format!(
                "failed to parse signed identity bundle: {}",
                source
            ))
        })?;
        let now_unix = current_unix_timestamp()?;
        Self::from_signed_bundle_at(signed, trusted_keys, now_unix)
    }

    fn from_signed_bundle_at(
        signed: SignedIdentityBundle,
        trusted_keys: &TrustedIdentityKeys,
        now_unix: u64,
    ) -> Result<Self, IdentityBundleError> {
        validate_signature(&signed, trusted_keys, now_unix)?;

        let mut agents = HashMap::new();
        for (agent_id, identity) in signed.agents {
            let agent_id = AgentId::new(agent_id.clone()).map_err(|err| {
                IdentityBundleError::Invalid(format!(
                    "invalid agent id '{}' in identity bundle: {}",
                    agent_id, err
                ))
            })?;
            let label = format!("agent '{}'", agent_id);
            let identity_key = parse_principal_identity_key(&identity, &label)?;
            agents.insert(agent_id, identity_key);
        }

        let mut clients = HashMap::new();
        for (client_id, identity) in signed.clients {
            let client_id = ClientId::new(client_id.clone()).map_err(|err| {
                IdentityBundleError::Invalid(format!(
                    "invalid client id '{}' in identity bundle: {}",
                    client_id, err
                ))
            })?;
            let label = format!("client '{}'", client_id);
            let identity_key = parse_principal_identity_key(&identity, &label)?;
            clients.insert(client_id, identity_key);
        }

        Ok(Self {
            expires_at_unix: signed.expires_at_unix,
            agents,
            clients,
        })
    }

    #[must_use]
    pub fn agent_identity_key(&self, agent_id: &AgentId) -> Option<&IdentityPublicKey> {
        self.agents.get(agent_id)
    }

    #[must_use]
    pub fn client_identity_key(&self, client_id: &ClientId) -> Option<&IdentityPublicKey> {
        self.clients.get(client_id)
    }

    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

pub fn sign_identity_bundle_ed25519(
    expires_at_unix: u64,
    agents: BTreeMap<String, IdentityPrincipal>,
    clients: BTreeMap<String, IdentityPrincipal>,
    signer_key_id: &str,
    signer_private_key_hex: &str,
) -> Result<SignedIdentityBundle, IdentityBundleError> {
    if signer_key_id.trim().is_empty() {
        return Err(IdentityBundleError::Invalid(
            "identity bundle signature key_id must not be empty".to_string(),
        ));
    }

    let mut signed = SignedIdentityBundle {
        bundle_version: IDENTITY_BUNDLE_VERSION_V1,
        expires_at_unix,
        agents,
        clients,
        signature: IdentityBundleSignature {
            key_id: signer_key_id.to_string(),
            algorithm: IDENTITY_BUNDLE_SIGNATURE_ALGORITHM_ED25519.to_string(),
            value: String::new(),
        },
    };

    let payload = signing_payload(&signed)?;
    let private_key = decode_hex_array::<{ ed25519::SECRET_LENGTH }>(
        "identity bundle signing private key",
        signer_private_key_hex,
    )?;
    let signature = ed25519::SecretKey(private_key).signature(&payload);
    signed.signature.value = hex::encode(signature.0);
    Ok(signed)
}

fn validate_signature(
    signed: &SignedIdentityBundle,
    trusted_keys: &TrustedIdentityKeys,
    now_unix: u64,
) -> Result<(), IdentityBundleError> {
    if signed.bundle_version != IDENTITY_BUNDLE_VERSION_V1 {
        return Err(IdentityBundleError::Invalid(format!(
            "unsupported identity bundle version {}; expected {}",
            signed.bundle_version, IDENTITY_BUNDLE_VERSION_V1
        )));
    }

    if signed.expires_at_unix <= now_unix {
        return Err(IdentityBundleError::Invalid(format!(
            "identity bundle has expired (expires_at_unix={}, now_unix={})",
            signed.expires_at_unix, now_unix
        )));
    }

    if signed.signature.key_id.trim().is_empty() {
        return Err(IdentityBundleError::Invalid(
            "identity bundle signature key_id must not be empty".to_string(),
        ));
    }

    if signed.signature.algorithm != IDENTITY_BUNDLE_SIGNATURE_ALGORITHM_ED25519 {
        return Err(IdentityBundleError::Invalid(format!(
            "unsupported identity bundle signature algorithm '{}'; expected '{}'",
            signed.signature.algorithm, IDENTITY_BUNDLE_SIGNATURE_ALGORITHM_ED25519
        )));
    }

    let Some(public_key) = trusted_keys.get(&signed.signature.key_id) else {
        return Err(IdentityBundleError::Invalid(format!(
            "no trusted identity signing key configured for key_id '{}'",
            signed.signature.key_id
        )));
    };

    let signature_bytes = decode_hex_array::<{ ed25519::SIG_LENGTH }>(
        "identity bundle signature",
        &signed.signature.value,
    )?;
    let payload = signing_payload(signed)?;
    let signature = ed25519::Signature(signature_bytes);
    if !public_key.clone().verify(&payload, &signature) {
        return Err(IdentityBundleError::Invalid(
            "identity bundle signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn signing_payload(signed: &SignedIdentityBundle) -> Result<Vec<u8>, IdentityBundleError> {
    serde_json::to_vec(&IdentityBundleSigningPayload {
        context: IDENTITY_BUNDLE_SIGNING_CONTEXT_V1,
        bundle_version: signed.bundle_version,
        expires_at_unix: signed.expires_at_unix,
        key_id: &signed.signature.key_id,
        algorithm: &signed.signature.algorithm,
        agents: &signed.agents,
        clients: &signed.clients,
    })
    .map_err(|source| {
        IdentityBundleError::Invalid(format!(
            "failed to serialize identity bundle signing payload: {}",
            source
        ))
    })
}

fn parse_principal_identity_key(
    identity: &IdentityPrincipal,
    field_prefix: &str,
) -> Result<IdentityPublicKey, IdentityBundleError> {
    if identity.key_id.trim().is_empty() {
        return Err(IdentityBundleError::Invalid(format!(
            "{} key_id must not be empty",
            field_prefix
        )));
    }

    let public_key = decode_hex_array::<{ ed25519::PUBLIC_LENGTH }>(
        &format!("{} public key", field_prefix),
        &identity.public_key,
    )?;
    Ok(IdentityPublicKey {
        key_id: identity.key_id.clone(),
        public_key,
    })
}

fn decode_hex_array<const N: usize>(
    field: &str,
    value: &str,
) -> Result<[u8; N], IdentityBundleError> {
    let bytes = hex::decode(value).map_err(|source| {
        IdentityBundleError::Invalid(format!("{} is not valid hex: {}", field, source))
    })?;

    if bytes.len() != N {
        return Err(IdentityBundleError::Invalid(format!(
            "{} must be {} bytes (got {})",
            field,
            N,
            bytes.len()
        )));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn current_unix_timestamp() -> Result<u64, IdentityBundleError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| {
            IdentityBundleError::Invalid(format!(
                "system clock is set before unix epoch: {}",
                source
            ))
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        time::{SystemTime, UNIX_EPOCH},
    };

    use hacl_star::ed25519;
    use serde_json::json;

    use super::{
        IdentityBundle, IdentityPrincipal, TrustedIdentityKeys, sign_identity_bundle_ed25519,
    };

    const SIGNING_KEY_ID: &str = "control-plane-v1";
    const SIGNING_SECRET_KEY: [u8; ed25519::SECRET_LENGTH] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    fn trusted_keys() -> TrustedIdentityKeys {
        let public_key = ed25519::SecretKey(SIGNING_SECRET_KEY).get_public();
        let trusted = json!({
            SIGNING_KEY_ID: hex::encode(public_key.0)
        });
        TrustedIdentityKeys::from_json_map(&trusted.to_string()).expect("trusted keys should parse")
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs()
    }

    fn sample_agents() -> BTreeMap<String, IdentityPrincipal> {
        BTreeMap::from([(
            "agent-default".to_string(),
            IdentityPrincipal {
                key_id: "agent-default-v1".to_string(),
                public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    .to_string(),
            },
        )])
    }

    fn sample_clients() -> BTreeMap<String, IdentityPrincipal> {
        BTreeMap::from([(
            "client-local".to_string(),
            IdentityPrincipal {
                key_id: "client-local-v1".to_string(),
                public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
                    .to_string(),
            },
        )])
    }

    #[test]
    fn signs_and_verifies_bundle() {
        let trusted_keys = trusted_keys();
        let now = now_unix();
        let signed = sign_identity_bundle_ed25519(
            now + 300,
            sample_agents(),
            sample_clients(),
            SIGNING_KEY_ID,
            &hex::encode(SIGNING_SECRET_KEY),
        )
        .expect("bundle signing should succeed");
        let signed_json = serde_json::to_string(&signed).expect("signed bundle should serialize");

        let bundle = IdentityBundle::from_signed_json(&signed_json, &trusted_keys)
            .expect("signed bundle should verify");
        assert!(
            bundle
                .agent_identity_key(
                    &super::AgentId::new("agent-default").expect("agent id should be valid"),
                )
                .is_some()
        );
        assert!(
            bundle
                .client_identity_key(
                    &super::ClientId::new("client-local").expect("client id should be valid"),
                )
                .is_some()
        );
        assert!(bundle.expires_at_unix() > now);
    }

    #[test]
    fn rejects_unknown_signing_key() {
        let trusted_keys = trusted_keys();
        let now = now_unix();
        let mut signed = sign_identity_bundle_ed25519(
            now + 300,
            sample_agents(),
            sample_clients(),
            SIGNING_KEY_ID,
            &hex::encode(SIGNING_SECRET_KEY),
        )
        .expect("bundle signing should succeed");
        signed.signature.key_id = "unknown-key".to_string();
        let signed_json = serde_json::to_string(&signed).expect("signed bundle should serialize");

        let err = IdentityBundle::from_signed_json(&signed_json, &trusted_keys)
            .expect_err("unknown signing key should fail");
        assert!(err.to_string().contains("no trusted identity signing key"));
    }

    #[test]
    fn rejects_expired_bundle() {
        let trusted_keys = trusted_keys();
        let now = now_unix();
        let signed = sign_identity_bundle_ed25519(
            now.saturating_sub(1),
            sample_agents(),
            sample_clients(),
            SIGNING_KEY_ID,
            &hex::encode(SIGNING_SECRET_KEY),
        )
        .expect("bundle signing should succeed");
        let signed_json = serde_json::to_string(&signed).expect("signed bundle should serialize");

        let err = IdentityBundle::from_signed_json(&signed_json, &trusted_keys)
            .expect_err("expired bundle should fail");
        assert!(err.to_string().contains("expired"));
    }
}
