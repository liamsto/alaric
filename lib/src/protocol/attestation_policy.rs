use std::{
    collections::HashMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{AgentId, ClientId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "attestation_mode", rename_all = "snake_case")]
pub enum PeerAttestationMode {
    Required,
    #[default]
    Preferred,
    Disabled,
}

impl PeerAttestationMode {
    pub const fn requires_attestation(self) -> bool {
        matches!(self, Self::Required)
    }

    pub const fn strictest(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Preferred => 1,
            Self::Required => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrincipalAttestationModes {
    #[serde(default)]
    pub agents: HashMap<AgentId, PeerAttestationMode>,
    #[serde(default)]
    pub clients: HashMap<ClientId, PeerAttestationMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairAttestationMode {
    pub client_id: ClientId,
    pub agent_id: AgentId,
    pub mode: PeerAttestationMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PeerAttestationPolicyConfig {
    #[serde(default)]
    pub default_mode: PeerAttestationMode,
    #[serde(default)]
    pub principal_modes: PrincipalAttestationModes,
    #[serde(default)]
    pub pair_modes: Vec<PairAttestationMode>,
}

#[derive(Debug, Clone)]
pub struct PeerAttestationPolicy {
    default_mode: PeerAttestationMode,
    client_modes: HashMap<ClientId, PeerAttestationMode>,
    agent_modes: HashMap<AgentId, PeerAttestationMode>,
    pair_modes: HashMap<(ClientId, AgentId), PeerAttestationMode>,
}

impl Default for PeerAttestationPolicy {
    fn default() -> Self {
        Self {
            default_mode: PeerAttestationMode::Preferred,
            client_modes: HashMap::new(),
            agent_modes: HashMap::new(),
            pair_modes: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub enum PeerAttestationPolicyError {
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

impl fmt::Display for PeerAttestationPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAttestationPolicyError::Io { path, source } => {
                write!(
                    f,
                    "failed to read peer attestation policy '{}': {}",
                    path.display(),
                    source
                )
            }
            PeerAttestationPolicyError::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse peer attestation policy '{}': {}",
                    path.display(),
                    source
                )
            }
            PeerAttestationPolicyError::Invalid(message) => {
                write!(f, "invalid peer attestation policy: {}", message)
            }
        }
    }
}

impl Error for PeerAttestationPolicyError {}

impl PeerAttestationPolicy {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, PeerAttestationPolicyError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| PeerAttestationPolicyError::Io {
            path: path.clone(),
            source,
        })?;
        let config: PeerAttestationPolicyConfig =
            serde_json::from_str(&raw).map_err(|source| PeerAttestationPolicyError::Parse {
                path: path.clone(),
                source,
            })?;
        Self::from_config(config)
    }

    pub fn from_json(raw: &str) -> Result<Self, PeerAttestationPolicyError> {
        let config: PeerAttestationPolicyConfig = serde_json::from_str(raw).map_err(|source| {
            PeerAttestationPolicyError::Invalid(format!("failed to parse JSON: {}", source))
        })?;
        Self::from_config(config)
    }

    pub fn from_config(
        config: PeerAttestationPolicyConfig,
    ) -> Result<Self, PeerAttestationPolicyError> {
        let mut pair_modes = HashMap::new();
        for pair_mode in config.pair_modes {
            let key = (pair_mode.client_id, pair_mode.agent_id);
            if pair_modes.insert(key.clone(), pair_mode.mode).is_some() {
                return Err(PeerAttestationPolicyError::Invalid(format!(
                    "duplicate pair override for client '{}' and agent '{}'",
                    key.0, key.1
                )));
            }
        }

        Ok(Self {
            default_mode: config.default_mode,
            client_modes: config.principal_modes.clients.into_iter().collect(),
            agent_modes: config.principal_modes.agents.into_iter().collect(),
            pair_modes,
        })
    }

    pub const fn default_mode(&self) -> PeerAttestationMode {
        self.default_mode
    }

    pub fn resolve(&self, client_id: &ClientId, agent_id: &AgentId) -> PeerAttestationMode {
        if let Some(mode) = self.pair_modes.get(&(client_id.clone(), agent_id.clone())) {
            return *mode;
        }

        let client_mode = self.client_modes.get(client_id).copied();
        let agent_mode = self.agent_modes.get(agent_id).copied();

        match (client_mode, agent_mode) {
            (Some(client_mode), Some(agent_mode)) => client_mode.strictest(agent_mode),
            (Some(client_mode), None) => client_mode,
            (None, Some(agent_mode)) => agent_mode,
            (None, None) => self.default_mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PairAttestationMode, PeerAttestationMode, PeerAttestationPolicy,
        PeerAttestationPolicyConfig, PrincipalAttestationModes,
    };
    use crate::protocol::{AgentId, ClientId};

    #[test]
    fn default_policy_is_preferred() {
        let policy = PeerAttestationPolicy::default();
        let client_id = ClientId::new("client-default").expect("client id should be valid");
        let agent_id = AgentId::new("agent-default").expect("agent id should be valid");
        assert_eq!(
            policy.resolve(&client_id, &agent_id),
            PeerAttestationMode::Preferred
        );
    }

    #[test]
    fn pair_override_takes_precedence() {
        let policy = PeerAttestationPolicy::from_config(PeerAttestationPolicyConfig {
            default_mode: PeerAttestationMode::Preferred,
            principal_modes: PrincipalAttestationModes {
                clients: std::collections::HashMap::from([(
                    ClientId::new("client-a").expect("client id should be valid"),
                    PeerAttestationMode::Disabled,
                )]),
                agents: std::collections::HashMap::new(),
            },
            pair_modes: vec![PairAttestationMode {
                client_id: ClientId::new("client-a").expect("client id should be valid"),
                agent_id: AgentId::new("agent-a").expect("agent id should be valid"),
                mode: PeerAttestationMode::Required,
            }],
        })
        .expect("policy should build");

        let client_id = ClientId::new("client-a").expect("client id should be valid");
        let agent_id = AgentId::new("agent-a").expect("agent id should be valid");
        assert_eq!(
            policy.resolve(&client_id, &agent_id),
            PeerAttestationMode::Required
        );
    }

    #[test]
    fn principal_overrides_combine_by_strictest_mode() {
        let policy = PeerAttestationPolicy::from_config(PeerAttestationPolicyConfig {
            default_mode: PeerAttestationMode::Disabled,
            principal_modes: PrincipalAttestationModes {
                clients: std::collections::HashMap::from([(
                    ClientId::new("client-a").expect("client id should be valid"),
                    PeerAttestationMode::Preferred,
                )]),
                agents: std::collections::HashMap::from([(
                    AgentId::new("agent-a").expect("agent id should be valid"),
                    PeerAttestationMode::Required,
                )]),
            },
            pair_modes: Vec::new(),
        })
        .expect("policy should build");

        let client_id = ClientId::new("client-a").expect("client id should be valid");
        let agent_id = AgentId::new("agent-a").expect("agent id should be valid");
        assert_eq!(
            policy.resolve(&client_id, &agent_id),
            PeerAttestationMode::Required
        );
    }
}
