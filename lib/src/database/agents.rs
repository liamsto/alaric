use serde_json::Value;
use sqlx::{
    prelude::FromRow,
    types::{
        Json, Uuid,
        chrono::{DateTime, Utc},
    },
};

use crate::protocol::SessionId;

#[derive(Debug, Clone, FromRow)]
pub struct AgentPresence {
    pub principal_id: Uuid,
    pub connected_session_id: Option<SessionId>,
    pub connected_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub last_seen_at: DateTime<Utc>,
    pub disconnect_reason: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub metadata: Json<Value>,
}
