use std::{
    collections::BTreeMap,
    collections::HashSet,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use hacl_star::ed25519::{self, PublicKey};
use regex::Regex;
use serde::{Deserialize, Serialize};

const POLICY_VERSION_V1: u16 = 1;
const POLICY_BUNDLE_VERSION_V1: u16 = 1;
const POLICY_SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";
const POLICY_KEYS_PATH_ENV: &str = "AGENT_POLICY_KEYS_PATH";
const DEFAULT_POLICY_KEYS_PATH: &str = "./policy-keys.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u16,
    pub default_timeout_secs: u64,
    pub max_output_bytes: usize,
    pub commands: Vec<CommandSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub id: String,
    pub program: String,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    #[serde(default)]
    pub arg_specs: Vec<ArgSpec>,
    pub timeout_secs: Option<u64>,
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    pub validation: Option<ValidationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationRule {
    Regex { pattern: String },
    Enum { values: Vec<String> },
}

#[derive(Debug, Clone, Deserialize)]
struct SignedPolicyBundle {
    bundle_version: u16,
    expires_at_unix: u64,
    policy: Policy,
    signature: PolicySignature,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicySignature {
    key_id: String,
    algorithm: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct PolicySigningPayload<'a> {
    bundle_version: u16,
    expires_at_unix: u64,
    key_id: &'a str,
    algorithm: &'a str,
    policy: &'a Policy,
}

#[derive(Clone)]
pub struct TrustedPolicyKeys {
    keys: BTreeMap<String, PublicKey>,
}

#[derive(Debug)]
pub enum PolicyError {
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

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Io { path, source } => {
                write!(
                    f,
                    "failed to read policy file '{}': {}",
                    path.display(),
                    source
                )
            }
            PolicyError::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse policy file '{}': {}",
                    path.display(),
                    source
                )
            }
            PolicyError::Invalid(message) => write!(f, "invalid policy: {}", message),
        }
    }
}

impl Error for PolicyError {}

impl TrustedPolicyKeys {
    pub fn load_default() -> Result<Self, PolicyError> {
        let path = std::env::var(POLICY_KEYS_PATH_ENV)
            .unwrap_or_else(|_| DEFAULT_POLICY_KEYS_PATH.to_string());
        Self::load_from_path(path)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| PolicyError::Io {
            path: path.clone(),
            source,
        })?;
        Self::from_json_map(&raw)
            .map_err(|err| PolicyError::Invalid(format!("{} (in '{}')", err, path.display())))
    }

    pub fn from_json_map(raw: &str) -> Result<Self, PolicyError> {
        let entries: BTreeMap<String, String> = serde_json::from_str(raw).map_err(|source| {
            PolicyError::Invalid(format!("failed to parse trusted keys JSON: {}", source))
        })?;

        if entries.is_empty() {
            return Err(PolicyError::Invalid(
                "trusted keys must contain at least one entry".to_string(),
            ));
        }

        let mut keys = BTreeMap::new();
        for (key_id, encoded_key) in entries {
            if key_id.trim().is_empty() {
                return Err(PolicyError::Invalid(
                    "trusted key id must not be empty".to_string(),
                ));
            }

            let key_bytes = decode_hex_array::<{ ed25519::PUBLIC_LENGTH }>(
                &format!("trusted key '{}'", key_id),
                &encoded_key,
            )?;
            keys.insert(key_id, ed25519::PublicKey(key_bytes));
        }

        Ok(Self { keys })
    }

    fn get(&self, key_id: &str) -> Option<&ed25519::PublicKey> {
        self.keys.get(key_id)
    }
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let trusted_keys = TrustedPolicyKeys::load_default()?;
        Self::load_with_keys(path, &trusted_keys)
    }

    pub fn load_with_keys(
        path: impl AsRef<Path>,
        trusted_keys: &TrustedPolicyKeys,
    ) -> Result<Self, PolicyError> {
        let now_unix = current_unix_timestamp()?;
        Self::load_with_keys_at(path, trusted_keys, now_unix)
    }

    fn load_with_keys_at(
        path: impl AsRef<Path>,
        trusted_keys: &TrustedPolicyKeys,
        now_unix: u64,
    ) -> Result<Self, PolicyError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| PolicyError::Io {
            path: path.clone(),
            source,
        })?;

        let bundle: SignedPolicyBundle = match serde_json::from_str(&raw) {
            Ok(bundle) => bundle,
            Err(source) => {
                if serde_json::from_str::<Policy>(&raw).is_ok() {
                    return Err(PolicyError::Invalid(
                        "unsigned policy bundles are rejected; expected a signed bundle envelope"
                            .to_string(),
                    ));
                }

                return Err(PolicyError::Parse {
                    path: path.clone(),
                    source,
                });
            }
        };

        validate_bundle(&bundle, trusted_keys, now_unix)?;
        bundle.policy.validate()?;

        Ok(bundle.policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION_V1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {}; expected {}",
                self.version, POLICY_VERSION_V1
            )));
        }

        if self.default_timeout_secs == 0 {
            return Err(PolicyError::Invalid(
                "default_timeout_secs must be greater than 0".to_string(),
            ));
        }

        if self.max_output_bytes == 0 {
            return Err(PolicyError::Invalid(
                "max_output_bytes must be greater than 0".to_string(),
            ));
        }

        if self.commands.is_empty() {
            return Err(PolicyError::Invalid(
                "commands must include at least one entry".to_string(),
            ));
        }

        let mut command_ids = HashSet::new();
        for command in &self.commands {
            if command.id.trim().is_empty() {
                return Err(PolicyError::Invalid(
                    "command id must not be empty".to_string(),
                ));
            }
            if command.program.trim().is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' has an empty program field",
                    command.id
                )));
            }
            if !command_ids.insert(command.id.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate command id '{}'",
                    command.id
                )));
            }

            if matches!(command.timeout_secs, Some(0)) {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' timeout_secs must be greater than 0",
                    command.id
                )));
            }
            if matches!(command.max_output_bytes, Some(0)) {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' max_output_bytes must be greater than 0",
                    command.id
                )));
            }

            let mut arg_names = HashSet::new();
            for arg in &command.arg_specs {
                if arg.name.trim().is_empty() {
                    return Err(PolicyError::Invalid(format!(
                        "command '{}' contains an empty argument name",
                        command.id
                    )));
                }
                if !arg_names.insert(arg.name.as_str()) {
                    return Err(PolicyError::Invalid(format!(
                        "command '{}' contains duplicate arg spec '{}'",
                        command.id, arg.name
                    )));
                }

                if let Some(rule) = &arg.validation {
                    validate_rule(command, arg, rule)?;
                }
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn command_by_id(&self, id: &str) -> Option<&CommandSpec> {
        self.commands.iter().find(|command| command.id == id)
    }
}

impl CommandSpec {
    #[must_use]
    pub fn effective_timeout_secs(&self, policy_default: u64) -> u64 {
        self.timeout_secs.unwrap_or(policy_default)
    }

    #[must_use]
    pub fn effective_max_output_bytes(&self, policy_default: usize) -> usize {
        self.max_output_bytes.unwrap_or(policy_default)
    }

    #[must_use]
    pub fn arg_spec(&self, name: &str) -> Option<&ArgSpec> {
        self.arg_specs.iter().find(|arg| arg.name == name)
    }
}

fn validate_bundle(
    bundle: &SignedPolicyBundle,
    trusted_keys: &TrustedPolicyKeys,
    now_unix: u64,
) -> Result<(), PolicyError> {
    if bundle.bundle_version != POLICY_BUNDLE_VERSION_V1 {
        return Err(PolicyError::Invalid(format!(
            "unsupported policy bundle version {}; expected {}",
            bundle.bundle_version, POLICY_BUNDLE_VERSION_V1
        )));
    }

    if bundle.expires_at_unix <= now_unix {
        return Err(PolicyError::Invalid(format!(
            "policy bundle has expired (expires_at_unix={}, now_unix={})",
            bundle.expires_at_unix, now_unix
        )));
    }

    if bundle.signature.key_id.trim().is_empty() {
        return Err(PolicyError::Invalid(
            "policy signature key_id must not be empty".to_string(),
        ));
    }

    if bundle.signature.algorithm != POLICY_SIGNATURE_ALGORITHM_ED25519 {
        return Err(PolicyError::Invalid(format!(
            "unsupported policy signature algorithm '{}'; expected '{}'",
            bundle.signature.algorithm, POLICY_SIGNATURE_ALGORITHM_ED25519
        )));
    }

    let Some(public_key) = trusted_keys.get(&bundle.signature.key_id) else {
        return Err(PolicyError::Invalid(format!(
            "no trusted policy key configured for key_id '{}'",
            bundle.signature.key_id
        )));
    };

    let signature_bytes =
        decode_hex_array::<{ ed25519::SIG_LENGTH }>("policy signature", &bundle.signature.value)?;

    let payload = serde_json::to_vec(&PolicySigningPayload {
        bundle_version: bundle.bundle_version,
        expires_at_unix: bundle.expires_at_unix,
        key_id: &bundle.signature.key_id,
        algorithm: &bundle.signature.algorithm,
        policy: &bundle.policy,
    })
    .map_err(|source| {
        PolicyError::Invalid(format!(
            "failed to serialize policy signing payload for verification: {}",
            source
        ))
    })?;

    let signature = ed25519::Signature(signature_bytes);
    if !public_key.clone().verify(&payload, &signature) {
        return Err(PolicyError::Invalid(
            "policy signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn decode_hex_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N], PolicyError> {
    let bytes = hex::decode(value).map_err(|source| {
        PolicyError::Invalid(format!("{} is not valid hex: {}", field, source))
    })?;

    if bytes.len() != N {
        return Err(PolicyError::Invalid(format!(
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

fn current_unix_timestamp() -> Result<u64, PolicyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| {
            PolicyError::Invalid(format!("system clock is set before unix epoch: {}", source))
        })
}

fn validate_rule(
    command: &CommandSpec,
    arg: &ArgSpec,
    rule: &ValidationRule,
) -> Result<(), PolicyError> {
    match rule {
        ValidationRule::Regex { pattern } => {
            let wrapped_pattern = format!("^(?:{})$", pattern);
            Regex::new(&wrapped_pattern).map_err(|err| {
                PolicyError::Invalid(format!(
                    "command '{}' arg '{}' has invalid regex '{}': {}",
                    command.id, arg.name, pattern, err
                ))
            })?;
        }
        ValidationRule::Enum { values } => {
            if values.is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' arg '{}' enum must include at least one value",
                    command.id, arg.name
                )));
            }

            if values.iter().any(|value| value.is_empty()) {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' arg '{}' enum contains an empty value",
                    command.id, arg.name
                )));
            }

            let mut seen = HashSet::new();
            for value in values {
                if !seen.insert(value) {
                    return Err(PolicyError::Invalid(format!(
                        "command '{}' arg '{}' enum contains duplicate value '{}'",
                        command.id, arg.name, value
                    )));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use hacl_star::ed25519;
    use serde_json::json;

    use super::{
        ArgSpec, CommandSpec, POLICY_SIGNATURE_ALGORITHM_ED25519, Policy, PolicyError,
        PolicySigningPayload, TrustedPolicyKeys, ValidationRule,
    };

    const TEST_KEY_ID: &str = "control-plane-v1";
    const TEST_SECRET_KEY: [u8; ed25519::SECRET_LENGTH] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const NOW_UNIX: u64 = 1_800_000_000;

    fn temp_file_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("alaric-policy-{}-{}.json", label, nanos))
    }

    fn write_temp_file(contents: &str, label: &str) -> std::path::PathBuf {
        let path = temp_file_path(label);
        fs::write(&path, contents).expect("write policy fixture");
        path
    }

    fn test_policy() -> Policy {
        let policy = Policy {
            version: 1,
            default_timeout_secs: 5,
            max_output_bytes: 2048,
            commands: vec![CommandSpec {
                id: "echo".to_string(),
                program: "/bin/echo".to_string(),
                fixed_args: Vec::new(),
                arg_specs: vec![ArgSpec {
                    name: "text".to_string(),
                    required: true,
                    validation: Some(ValidationRule::Regex {
                        pattern: ".+".to_string(),
                    }),
                }],
                timeout_secs: None,
                max_output_bytes: None,
            }],
        };
        policy.validate().expect("fixture policy should validate");
        policy
    }

    fn trusted_keys() -> TrustedPolicyKeys {
        let public_key = ed25519::SecretKey(TEST_SECRET_KEY).get_public();
        let trusted = json!({
            TEST_KEY_ID: hex::encode(public_key.0)
        });
        TrustedPolicyKeys::from_json_map(&trusted.to_string()).expect("trusted keys should parse")
    }

    fn sign_bundle(policy: &Policy, key_id: &str, expires_at_unix: u64, algorithm: &str) -> String {
        let payload = serde_json::to_vec(&PolicySigningPayload {
            bundle_version: 1,
            expires_at_unix,
            key_id,
            algorithm,
            policy,
        })
        .expect("payload should serialize");
        let signature = ed25519::SecretKey(TEST_SECRET_KEY).signature(&payload);
        hex::encode(signature.0)
    }

    fn signed_bundle_json(
        policy: &Policy,
        key_id: &str,
        bundle_version: u16,
        expires_at_unix: u64,
        algorithm: &str,
        signature_hex: &str,
    ) -> String {
        json!({
            "bundle_version": bundle_version,
            "expires_at_unix": expires_at_unix,
            "policy": policy,
            "signature": {
                "key_id": key_id,
                "algorithm": algorithm,
                "value": signature_hex
            }
        })
        .to_string()
    }

    #[test]
    fn loads_valid_signed_bundle() {
        let policy = test_policy();
        let trusted_keys = trusted_keys();
        let signature = sign_bundle(
            &policy,
            TEST_KEY_ID,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
        );
        let bundle = signed_bundle_json(
            &policy,
            TEST_KEY_ID,
            1,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
            &signature,
        );
        let path = write_temp_file(&bundle, "signed-valid");

        let loaded = Policy::load_with_keys_at(&path, &trusted_keys, NOW_UNIX)
            .expect("signed policy should load");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.commands.len(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unsigned_bundle() {
        let trusted_keys = trusted_keys();
        let plain = json!({
            "version": 1,
            "default_timeout_secs": 5,
            "max_output_bytes": 2048,
            "commands": []
        })
        .to_string();
        let path = write_temp_file(&plain, "unsigned");

        let err = Policy::load_with_keys_at(&path, &trusted_keys, NOW_UNIX)
            .expect_err("unsigned policy should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unknown_signature_key_id() {
        let policy = test_policy();
        let trusted_keys = trusted_keys();
        let signature = sign_bundle(
            &policy,
            "unknown-key",
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
        );
        let bundle = signed_bundle_json(
            &policy,
            "unknown-key",
            1,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
            &signature,
        );
        let path = write_temp_file(&bundle, "unknown-kid");

        let err = Policy::load_with_keys_at(&path, &trusted_keys, NOW_UNIX)
            .expect_err("unknown key id should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_tampered_signature() {
        let policy = test_policy();
        let trusted_keys = trusted_keys();
        let mut signature = sign_bundle(
            &policy,
            TEST_KEY_ID,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
        );
        signature.replace_range(..2, "00");
        let bundle = signed_bundle_json(
            &policy,
            TEST_KEY_ID,
            1,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
            &signature,
        );
        let path = write_temp_file(&bundle, "bad-signature");

        let err = Policy::load_with_keys_at(&path, &trusted_keys, NOW_UNIX)
            .expect_err("tampered signature should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_expired_bundle() {
        let policy = test_policy();
        let trusted_keys = trusted_keys();
        let signature = sign_bundle(
            &policy,
            TEST_KEY_ID,
            NOW_UNIX - 1,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
        );
        let bundle = signed_bundle_json(
            &policy,
            TEST_KEY_ID,
            1,
            NOW_UNIX - 1,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
            &signature,
        );
        let path = write_temp_file(&bundle, "expired");

        let err = Policy::load_with_keys_at(&path, &trusted_keys, NOW_UNIX)
            .expect_err("expired bundle should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unsupported_bundle_version() {
        let policy = test_policy();
        let trusted_keys = trusted_keys();
        let signature = sign_bundle(
            &policy,
            TEST_KEY_ID,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
        );
        let bundle = signed_bundle_json(
            &policy,
            TEST_KEY_ID,
            2,
            NOW_UNIX + 300,
            POLICY_SIGNATURE_ALGORITHM_ED25519,
            &signature,
        );
        let path = write_temp_file(&bundle, "bad-version");

        let err = Policy::load_with_keys_at(&path, &trusted_keys, NOW_UNIX)
            .expect_err("unsupported bundle version should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn trusted_keys_rejects_invalid_key_length() {
        let raw = serde_json::to_string(&BTreeMap::from([(TEST_KEY_ID, "00".repeat(31))]))
            .expect("json serialization should succeed");
        let err = match TrustedPolicyKeys::from_json_map(&raw) {
            Ok(_) => panic!("key length should be invalid"),
            Err(err) => err,
        };
        assert!(matches!(err, PolicyError::Invalid(_)));
    }
}
