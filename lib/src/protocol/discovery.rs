use serde::{Deserialize, Serialize};

use super::{AgentGroupId, AgentId, PROTOCOL_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPresenceStatus {
    Online,
    Offline,
}

impl AgentPresenceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDiscoveryEntry {
    pub agent_id: AgentId,
    pub display_name: Option<String>,
    pub capabilities: Vec<String>,
    pub tags: Vec<String>,
    pub status: AgentPresenceStatus,
    pub status_age_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGroupDiscoveryEntry {
    pub group_id: AgentGroupId,
    pub display_name: Option<String>,
    pub members: Vec<AgentId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListAgentsResponse {
    pub protocol_version: u16,
    pub generated_at_unix: u64,
    pub agents: Vec<AgentDiscoveryEntry>,
    #[serde(default)]
    pub groups: Vec<AgentGroupDiscoveryEntry>,
}

impl ListAgentsResponse {
    pub fn new(
        generated_at_unix: u64,
        agents: Vec<AgentDiscoveryEntry>,
        groups: Vec<AgentGroupDiscoveryEntry>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            generated_at_unix,
            agents,
            groups,
        }
    }
}
