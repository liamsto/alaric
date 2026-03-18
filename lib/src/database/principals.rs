use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    prelude::FromRow,
    types::{
        Json, Uuid,
        chrono::{DateTime, Utc},
    },
};

use crate::protocol::PeerAttestationMode;

// principals (
//   id                       UUID PRIMARY KEY,
//   kind                     principal_kind NOT NULL,
//   external_id              TEXT NOT NULL,          -- AgentId/ClientId string
//   display_name             TEXT,
//   metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb,
//   attestation_mode         attestation_mode NOT NULL DEFAULT 'preferred',
//   created_at               TIMESTAMPTZ NOT NULL,
//   disabled_at              TIMESTAMPTZ,
//   UNIQUE (kind, external_id)
// );
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "principal_kind", rename_all = "snake_case")]
pub enum PrincipalKind {
    Agent,
    Client,
}

#[derive(Debug, Clone, FromRow)]
pub struct Principal {
    pub id: Uuid,
    pub kind: PrincipalKind,
    pub external_id: String,
    pub display_name: Option<String>,
    pub metadata: Json<Value>,
    pub attestation_mode: PeerAttestationMode,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "key_algorithm", rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, FromRow)]
pub struct PrincipalKey {
    pub id: Uuid,
    pub principal_id: Uuid,
    pub key_id: String,
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
