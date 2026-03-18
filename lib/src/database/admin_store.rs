use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use sqlx::{
    Executor, FromRow,
    types::{
        Uuid,
        chrono::{DateTime, Utc},
    },
};

use crate::{
    database::{
        Database,
        principals::{KeyAlgorithm, PrincipalKind},
    },
    protocol::{AgentGroupId, AgentId, ClientId, decode_ed25519_public_key},
};

#[derive(Debug)]
pub enum AdminStoreError {
    Sqlx(sqlx::Error),
    InvalidPrincipalId(String),
    InvalidGroupId(String),
    UnknownAgentGroupMembers(Vec<String>),
    InvalidKeyId,
    InvalidPublicKey(String),
}

impl fmt::Display for AdminStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminStoreError::Sqlx(source) => write!(f, "database error: {}", source),
            AdminStoreError::InvalidPrincipalId(message) => {
                write!(f, "invalid principal id: {}", message)
            }
            AdminStoreError::InvalidGroupId(message) => {
                write!(f, "invalid agent group id: {}", message)
            }
            AdminStoreError::UnknownAgentGroupMembers(members) => write!(
                f,
                "unknown or disabled agent group members: {}",
                members.join(", ")
            ),
            AdminStoreError::InvalidKeyId => f.write_str("key_id must not be empty"),
            AdminStoreError::InvalidPublicKey(message) => {
                write!(f, "invalid Ed25519 public key: {}", message)
            }
        }
    }
}

impl Error for AdminStoreError {}

impl From<sqlx::Error> for AdminStoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalAddOutcome {
    Added,
    Reenabled,
    AlreadyActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalDisableOutcome {
    Disabled,
    AlreadyDisabled,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAddOutcome {
    Added,
    Updated,
    PrincipalNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRevokeOutcome {
    Revoked,
    AlreadyRevoked,
    KeyNotFound,
    PrincipalNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRotateOutcome {
    pub replaced_existing_key: bool,
    pub revoked_other_keys: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupUpsertOutcome {
    Created,
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupCreateOutcome {
    Created,
    AlreadyExists,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupMemberAddOutcome {
    Added,
    AlreadyMember,
    GroupNotFound,
    AgentNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupMemberRemoveOutcome {
    Removed,
    NotMember,
    GroupNotFound,
    AgentNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupMoveOutcome {
    Moved {
        removed_from_old_group: bool,
        added_to_new_group: bool,
    },
    SourceGroupNotFound,
    DestinationGroupNotFound,
    AgentNotFound,
    SameGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupSetNameOutcome {
    Updated,
    GroupNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGroupDeleteOutcome {
    Deleted,
    NotFound,
}

#[derive(Debug, Clone, FromRow)]
pub struct PrincipalListEntry {
    pub kind: PrincipalKind,
    pub external_id: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub key_count: i64,
    pub active_key_count: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct AgentGroupListEntry {
    pub external_id: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub member_agent_ids: Vec<String>,
}

#[derive(Debug, FromRow)]
struct PrincipalStateRow {
    id: Uuid,
    disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct PrincipalIdRow {
    id: Uuid,
}

#[derive(Debug, FromRow)]
struct KeyRevocationRow {
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct AgentGroupStateRow {
    id: Uuid,
}

#[derive(Debug, FromRow)]
struct AgentMemberIdRow {
    id: Uuid,
    external_id: String,
}

impl Database {
    pub async fn admin_create_agent_group(
        &self,
        group_id: &str,
        display_name: Option<&str>,
    ) -> Result<AgentGroupCreateOutcome, AdminStoreError> {
        validate_group_id(group_id)?;

        let result = sqlx::query(
            r#"
            INSERT INTO agent_groups (external_id, display_name, metadata)
            VALUES ($1, $2, '{}'::jsonb)
            ON CONFLICT (external_id) DO NOTHING
            "#,
        )
        .bind(group_id)
        .bind(display_name)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            Ok(AgentGroupCreateOutcome::AlreadyExists)
        } else {
            Ok(AgentGroupCreateOutcome::Created)
        }
    }

    pub async fn admin_add_agent_to_group(
        &self,
        group_id: &str,
        agent_id: &str,
    ) -> Result<AgentGroupMemberAddOutcome, AdminStoreError> {
        validate_group_id(group_id)?;
        AgentId::new(agent_id)
            .map_err(|err| AdminStoreError::InvalidPrincipalId(err.to_string()))?;

        let mut tx = self.pool().begin().await?;
        let Some(group) = find_agent_group_state(&mut *tx, group_id).await? else {
            tx.commit().await?;
            return Ok(AgentGroupMemberAddOutcome::GroupNotFound);
        };

        let Some(agent) = find_principal_state(&mut *tx, PrincipalKind::Agent, agent_id).await?
        else {
            tx.commit().await?;
            return Ok(AgentGroupMemberAddOutcome::AgentNotFound);
        };
        if agent.disabled_at.is_some() {
            tx.commit().await?;
            return Ok(AgentGroupMemberAddOutcome::AgentNotFound);
        }

        let insert_result = sqlx::query(
            r#"
            INSERT INTO agent_group_members (group_id, agent_principal_id)
            VALUES ($1, $2)
            ON CONFLICT (group_id, agent_principal_id) DO NOTHING
            "#,
        )
        .bind(group.id)
        .bind(agent.id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        if insert_result.rows_affected() == 0 {
            Ok(AgentGroupMemberAddOutcome::AlreadyMember)
        } else {
            Ok(AgentGroupMemberAddOutcome::Added)
        }
    }

    pub async fn admin_remove_agent_from_group(
        &self,
        group_id: &str,
        agent_id: &str,
    ) -> Result<AgentGroupMemberRemoveOutcome, AdminStoreError> {
        validate_group_id(group_id)?;
        AgentId::new(agent_id)
            .map_err(|err| AdminStoreError::InvalidPrincipalId(err.to_string()))?;

        let mut tx = self.pool().begin().await?;
        let Some(group) = find_agent_group_state(&mut *tx, group_id).await? else {
            tx.commit().await?;
            return Ok(AgentGroupMemberRemoveOutcome::GroupNotFound);
        };

        let Some(agent) = find_principal_state(&mut *tx, PrincipalKind::Agent, agent_id).await?
        else {
            tx.commit().await?;
            return Ok(AgentGroupMemberRemoveOutcome::AgentNotFound);
        };
        if agent.disabled_at.is_some() {
            tx.commit().await?;
            return Ok(AgentGroupMemberRemoveOutcome::AgentNotFound);
        }

        let delete_result = sqlx::query(
            r#"
            DELETE FROM agent_group_members
            WHERE group_id = $1
              AND agent_principal_id = $2
            "#,
        )
        .bind(group.id)
        .bind(agent.id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        if delete_result.rows_affected() == 0 {
            Ok(AgentGroupMemberRemoveOutcome::NotMember)
        } else {
            Ok(AgentGroupMemberRemoveOutcome::Removed)
        }
    }

    pub async fn admin_move_agent_between_groups(
        &self,
        old_group_id: &str,
        new_group_id: &str,
        agent_id: &str,
    ) -> Result<AgentGroupMoveOutcome, AdminStoreError> {
        validate_group_id(old_group_id)?;
        validate_group_id(new_group_id)?;
        AgentId::new(agent_id)
            .map_err(|err| AdminStoreError::InvalidPrincipalId(err.to_string()))?;

        if old_group_id == new_group_id {
            return Ok(AgentGroupMoveOutcome::SameGroup);
        }

        let mut tx = self.pool().begin().await?;
        let Some(old_group) = find_agent_group_state(&mut *tx, old_group_id).await? else {
            tx.commit().await?;
            return Ok(AgentGroupMoveOutcome::SourceGroupNotFound);
        };
        let Some(new_group) = find_agent_group_state(&mut *tx, new_group_id).await? else {
            tx.commit().await?;
            return Ok(AgentGroupMoveOutcome::DestinationGroupNotFound);
        };

        let Some(agent) = find_principal_state(&mut *tx, PrincipalKind::Agent, agent_id).await?
        else {
            tx.commit().await?;
            return Ok(AgentGroupMoveOutcome::AgentNotFound);
        };
        if agent.disabled_at.is_some() {
            tx.commit().await?;
            return Ok(AgentGroupMoveOutcome::AgentNotFound);
        }

        let removed_from_old_group = sqlx::query(
            r#"
            DELETE FROM agent_group_members
            WHERE group_id = $1
              AND agent_principal_id = $2
            "#,
        )
        .bind(old_group.id)
        .bind(agent.id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            != 0;

        let added_to_new_group = sqlx::query(
            r#"
            INSERT INTO agent_group_members (group_id, agent_principal_id)
            VALUES ($1, $2)
            ON CONFLICT (group_id, agent_principal_id) DO NOTHING
            "#,
        )
        .bind(new_group.id)
        .bind(agent.id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            != 0;

        tx.commit().await?;
        Ok(AgentGroupMoveOutcome::Moved {
            removed_from_old_group,
            added_to_new_group,
        })
    }

    pub async fn admin_set_agent_group_name(
        &self,
        group_id: &str,
        display_name: &str,
    ) -> Result<AgentGroupSetNameOutcome, AdminStoreError> {
        validate_group_id(group_id)?;

        let result = sqlx::query(
            r#"
            UPDATE agent_groups
            SET display_name = $2
            WHERE external_id = $1
            "#,
        )
        .bind(group_id)
        .bind(display_name)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            Ok(AgentGroupSetNameOutcome::GroupNotFound)
        } else {
            Ok(AgentGroupSetNameOutcome::Updated)
        }
    }

    pub async fn admin_add_principal(
        &self,
        kind: PrincipalKind,
        external_id: &str,
        display_name: Option<&str>,
    ) -> Result<PrincipalAddOutcome, AdminStoreError> {
        validate_principal_id(kind, external_id)?;

        let mut tx = self.pool().begin().await?;
        let existing = find_principal_state(&mut *tx, kind, external_id).await?;

        match existing {
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO principals (kind, external_id, display_name, metadata)
                    VALUES ($1, $2, $3, '{}'::jsonb)
                    "#,
                )
                .bind(kind)
                .bind(external_id)
                .bind(display_name)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(PrincipalAddOutcome::Added)
            }
            Some(existing) if existing.disabled_at.is_some() => {
                sqlx::query(
                    r#"
                    UPDATE principals
                    SET disabled_at = NULL,
                        display_name = COALESCE($2, display_name)
                    WHERE id = $1
                    "#,
                )
                .bind(existing.id)
                .bind(display_name)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(PrincipalAddOutcome::Reenabled)
            }
            Some(existing) => {
                if display_name.is_some() {
                    sqlx::query(
                        r#"
                        UPDATE principals
                        SET display_name = $2
                        WHERE id = $1
                        "#,
                    )
                    .bind(existing.id)
                    .bind(display_name)
                    .execute(&mut *tx)
                    .await?;
                }
                tx.commit().await?;
                Ok(PrincipalAddOutcome::AlreadyActive)
            }
        }
    }

    pub async fn admin_disable_principal(
        &self,
        kind: PrincipalKind,
        external_id: &str,
    ) -> Result<PrincipalDisableOutcome, AdminStoreError> {
        validate_principal_id(kind, external_id)?;

        let mut tx = self.pool().begin().await?;
        let existing = find_principal_state(&mut *tx, kind, external_id).await?;
        let outcome = match existing {
            None => PrincipalDisableOutcome::NotFound,
            Some(state) if state.disabled_at.is_some() => PrincipalDisableOutcome::AlreadyDisabled,
            Some(state) => {
                sqlx::query(
                    r#"
                    UPDATE principals
                    SET disabled_at = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(state.id)
                .execute(&mut *tx)
                .await?;
                PrincipalDisableOutcome::Disabled
            }
        };

        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn admin_list_principals(
        &self,
        kind: Option<PrincipalKind>,
    ) -> Result<Vec<PrincipalListEntry>, AdminStoreError> {
        let principals = if let Some(kind) = kind {
            sqlx::query_as::<_, PrincipalListEntry>(
                r#"
                SELECT
                    p.kind,
                    p.external_id,
                    p.display_name,
                    p.created_at,
                    p.disabled_at,
                    COALESCE(k.key_count, 0) AS key_count,
                    COALESCE(k.active_key_count, 0) AS active_key_count
                FROM principals AS p
                LEFT JOIN LATERAL (
                    SELECT
                        COUNT(*)::BIGINT AS key_count,
                        COUNT(*) FILTER (
                            WHERE pk.revoked_at IS NULL
                              AND pk.valid_from <= NOW()
                              AND (pk.valid_to IS NULL OR pk.valid_to >= NOW())
                        )::BIGINT AS active_key_count
                    FROM principal_keys AS pk
                    WHERE pk.principal_id = p.id
                ) AS k ON TRUE
                WHERE p.kind = $1
                ORDER BY p.kind, p.external_id
                "#,
            )
            .bind(kind)
            .fetch_all(self.pool())
            .await?
        } else {
            sqlx::query_as::<_, PrincipalListEntry>(
                r#"
                SELECT
                    p.kind,
                    p.external_id,
                    p.display_name,
                    p.created_at,
                    p.disabled_at,
                    COALESCE(k.key_count, 0) AS key_count,
                    COALESCE(k.active_key_count, 0) AS active_key_count
                FROM principals AS p
                LEFT JOIN LATERAL (
                    SELECT
                        COUNT(*)::BIGINT AS key_count,
                        COUNT(*) FILTER (
                            WHERE pk.revoked_at IS NULL
                              AND pk.valid_from <= NOW()
                              AND (pk.valid_to IS NULL OR pk.valid_to >= NOW())
                        )::BIGINT AS active_key_count
                    FROM principal_keys AS pk
                    WHERE pk.principal_id = p.id
                ) AS k ON TRUE
                ORDER BY p.kind, p.external_id
                "#,
            )
            .fetch_all(self.pool())
            .await?
        };

        Ok(principals)
    }

    pub async fn admin_add_key(
        &self,
        kind: PrincipalKind,
        external_id: &str,
        key_id: &str,
        public_key_hex: &str,
    ) -> Result<KeyAddOutcome, AdminStoreError> {
        validate_principal_id(kind, external_id)?;
        if key_id.trim().is_empty() {
            return Err(AdminStoreError::InvalidKeyId);
        }
        let public_key = decode_ed25519_public_key(public_key_hex)
            .map_err(|err| AdminStoreError::InvalidPublicKey(err.to_string()))?
            .to_vec();

        let mut tx = self.pool().begin().await?;
        let Some(principal_id) = find_principal_id(&mut *tx, kind, external_id).await? else {
            tx.commit().await?;
            return Ok(KeyAddOutcome::PrincipalNotFound);
        };

        let existing_key_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
            FROM principal_keys
            WHERE principal_id = $1
              AND key_id = $2
            LIMIT 1
            "#,
        )
        .bind(principal_id)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO principal_keys (
                principal_id,
                key_id,
                algorithm,
                public_key,
                valid_from
            )
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (principal_id, key_id) DO UPDATE
            SET algorithm = EXCLUDED.algorithm,
                public_key = EXCLUDED.public_key,
                valid_from = NOW(),
                valid_to = NULL,
                revoked_at = NULL
            "#,
        )
        .bind(principal_id)
        .bind(key_id)
        .bind(KeyAlgorithm::Ed25519)
        .bind(public_key)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(match existing_key_id {
            Some(_) => KeyAddOutcome::Updated,
            None => KeyAddOutcome::Added,
        })
    }

    pub async fn admin_rotate_key(
        &self,
        kind: PrincipalKind,
        external_id: &str,
        new_key_id: &str,
        new_public_key_hex: &str,
    ) -> Result<Option<KeyRotateOutcome>, AdminStoreError> {
        validate_principal_id(kind, external_id)?;
        if new_key_id.trim().is_empty() {
            return Err(AdminStoreError::InvalidKeyId);
        }
        let new_public_key = decode_ed25519_public_key(new_public_key_hex)
            .map_err(|err| AdminStoreError::InvalidPublicKey(err.to_string()))?
            .to_vec();

        let mut tx = self.pool().begin().await?;
        let Some(principal_id) = find_principal_id(&mut *tx, kind, external_id).await? else {
            tx.commit().await?;
            return Ok(None);
        };

        let existing = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
            FROM principal_keys
            WHERE principal_id = $1
              AND key_id = $2
            LIMIT 1
            "#,
        )
        .bind(principal_id)
        .bind(new_key_id)
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO principal_keys (
                principal_id,
                key_id,
                algorithm,
                public_key,
                valid_from
            )
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (principal_id, key_id) DO UPDATE
            SET algorithm = EXCLUDED.algorithm,
                public_key = EXCLUDED.public_key,
                valid_from = NOW(),
                valid_to = NULL,
                revoked_at = NULL
            "#,
        )
        .bind(principal_id)
        .bind(new_key_id)
        .bind(KeyAlgorithm::Ed25519)
        .bind(new_public_key)
        .execute(&mut *tx)
        .await?;

        let revoked = sqlx::query(
            r#"
            UPDATE principal_keys
            SET revoked_at = NOW(),
                valid_to = COALESCE(valid_to, NOW())
            WHERE principal_id = $1
              AND key_id <> $2
              AND revoked_at IS NULL
            "#,
        )
        .bind(principal_id)
        .bind(new_key_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some(KeyRotateOutcome {
            replaced_existing_key: existing.is_some(),
            revoked_other_keys: revoked.rows_affected(),
        }))
    }

    pub async fn admin_revoke_key(
        &self,
        kind: PrincipalKind,
        external_id: &str,
        key_id: &str,
    ) -> Result<KeyRevokeOutcome, AdminStoreError> {
        validate_principal_id(kind, external_id)?;
        if key_id.trim().is_empty() {
            return Err(AdminStoreError::InvalidKeyId);
        }

        let mut tx = self.pool().begin().await?;
        let Some(principal_id) = find_principal_id(&mut *tx, kind, external_id).await? else {
            tx.commit().await?;
            return Ok(KeyRevokeOutcome::PrincipalNotFound);
        };

        let key = sqlx::query_as::<_, KeyRevocationRow>(
            r#"
            SELECT revoked_at
            FROM principal_keys
            WHERE principal_id = $1
              AND key_id = $2
            LIMIT 1
            "#,
        )
        .bind(principal_id)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await?;

        let outcome = match key {
            None => KeyRevokeOutcome::KeyNotFound,
            Some(key) if key.revoked_at.is_some() => KeyRevokeOutcome::AlreadyRevoked,
            Some(_) => {
                sqlx::query(
                    r#"
                    UPDATE principal_keys
                    SET revoked_at = NOW(),
                        valid_to = COALESCE(valid_to, NOW())
                    WHERE principal_id = $1
                      AND key_id = $2
                    "#,
                )
                .bind(principal_id)
                .bind(key_id)
                .execute(&mut *tx)
                .await?;
                KeyRevokeOutcome::Revoked
            }
        };

        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn admin_upsert_agent_group(
        &self,
        group_id: &str,
        display_name: Option<&str>,
        member_agent_ids: &[String],
    ) -> Result<AgentGroupUpsertOutcome, AdminStoreError> {
        validate_group_id(group_id)?;

        let mut deduped_members = BTreeSet::new();
        for member in member_agent_ids {
            AgentId::new(member)
                .map_err(|err| AdminStoreError::InvalidPrincipalId(err.to_string()))?;
            deduped_members.insert(member.to_string());
        }
        let member_agent_ids = deduped_members.into_iter().collect::<Vec<_>>();

        let mut tx = self.pool().begin().await?;
        let existing = find_agent_group_state(&mut *tx, group_id).await?;

        let (group_uuid, outcome) = if let Some(existing) = existing {
            if let Some(display_name) = display_name {
                sqlx::query(
                    r#"
                    UPDATE agent_groups
                    SET display_name = $2
                    WHERE id = $1
                    "#,
                )
                .bind(existing.id)
                .bind(display_name)
                .execute(&mut *tx)
                .await?;
            }
            (existing.id, AgentGroupUpsertOutcome::Updated)
        } else {
            let row = sqlx::query_as::<_, AgentGroupStateRow>(
                r#"
                INSERT INTO agent_groups (external_id, display_name, metadata)
                VALUES ($1, $2, '{}'::jsonb)
                RETURNING id
                "#,
            )
            .bind(group_id)
            .bind(display_name)
            .fetch_one(&mut *tx)
            .await?;
            (row.id, AgentGroupUpsertOutcome::Created)
        };

        let resolved_member_rows = if member_agent_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as::<_, AgentMemberIdRow>(
                r#"
                SELECT id, external_id
                FROM principals
                WHERE kind = 'agent'
                  AND disabled_at IS NULL
                  AND external_id = ANY($1::text[])
                ORDER BY external_id
                "#,
            )
            .bind(&member_agent_ids)
            .fetch_all(&mut *tx)
            .await?
        };

        if resolved_member_rows.len() != member_agent_ids.len() {
            let resolved = resolved_member_rows
                .iter()
                .map(|row| (row.external_id.clone(), row.id))
                .collect::<BTreeMap<_, _>>();
            let unknown_members = member_agent_ids
                .into_iter()
                .filter(|member| !resolved.contains_key(member))
                .collect::<Vec<_>>();
            return Err(AdminStoreError::UnknownAgentGroupMembers(unknown_members));
        }

        sqlx::query(
            r#"
            DELETE FROM agent_group_members
            WHERE group_id = $1
            "#,
        )
        .bind(group_uuid)
        .execute(&mut *tx)
        .await?;

        for member in resolved_member_rows {
            sqlx::query(
                r#"
                INSERT INTO agent_group_members (group_id, agent_principal_id)
                VALUES ($1, $2)
                ON CONFLICT (group_id, agent_principal_id) DO NOTHING
                "#,
            )
            .bind(group_uuid)
            .bind(member.id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn admin_delete_agent_group(
        &self,
        group_id: &str,
    ) -> Result<AgentGroupDeleteOutcome, AdminStoreError> {
        validate_group_id(group_id)?;

        let result = sqlx::query(
            r#"
            DELETE FROM agent_groups
            WHERE external_id = $1
            "#,
        )
        .bind(group_id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            Ok(AgentGroupDeleteOutcome::NotFound)
        } else {
            Ok(AgentGroupDeleteOutcome::Deleted)
        }
    }

    pub async fn admin_list_agent_groups(
        &self,
    ) -> Result<Vec<AgentGroupListEntry>, AdminStoreError> {
        let groups = sqlx::query_as::<_, AgentGroupListEntry>(
            r#"
            SELECT
                g.external_id,
                g.display_name,
                g.created_at,
                COALESCE(
                    ARRAY_AGG(p.external_id ORDER BY p.external_id)
                        FILTER (WHERE p.external_id IS NOT NULL),
                    ARRAY[]::text[]
                ) AS member_agent_ids
            FROM agent_groups AS g
            LEFT JOIN agent_group_members AS gm
                ON gm.group_id = g.id
            LEFT JOIN principals AS p
                ON p.id = gm.agent_principal_id
               AND p.kind = 'agent'
               AND p.disabled_at IS NULL
            GROUP BY g.id, g.external_id, g.display_name, g.created_at
            ORDER BY g.external_id
            "#,
        )
        .fetch_all(self.pool())
        .await?;

        Ok(groups)
    }
}

fn validate_principal_id(kind: PrincipalKind, external_id: &str) -> Result<(), AdminStoreError> {
    match kind {
        PrincipalKind::Agent => AgentId::new(external_id).map(|_| ()),
        PrincipalKind::Client => ClientId::new(external_id).map(|_| ()),
    }
    .map_err(|err| AdminStoreError::InvalidPrincipalId(err.to_string()))
}

fn validate_group_id(external_id: &str) -> Result<(), AdminStoreError> {
    AgentGroupId::new(external_id)
        .map(|_| ())
        .map_err(|err| AdminStoreError::InvalidGroupId(err.to_string()))
}

async fn find_principal_state<'a, E>(
    executor: E,
    kind: PrincipalKind,
    external_id: &str,
) -> Result<Option<PrincipalStateRow>, sqlx::Error>
where
    E: Executor<'a, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, PrincipalStateRow>(
        r#"
        SELECT id, disabled_at
        FROM principals
        WHERE kind = $1
          AND external_id = $2
        LIMIT 1
        "#,
    )
    .bind(kind)
    .bind(external_id)
    .fetch_optional(executor)
    .await
}

async fn find_principal_id<'a, E>(
    executor: E,
    kind: PrincipalKind,
    external_id: &str,
) -> Result<Option<Uuid>, sqlx::Error>
where
    E: Executor<'a, Database = sqlx::Postgres>,
{
    let row = sqlx::query_as::<_, PrincipalIdRow>(
        r#"
        SELECT id
        FROM principals
        WHERE kind = $1
          AND external_id = $2
        LIMIT 1
        "#,
    )
    .bind(kind)
    .bind(external_id)
    .fetch_optional(executor)
    .await?;

    Ok(row.map(|row| row.id))
}

async fn find_agent_group_state<'a, E>(
    executor: E,
    external_id: &str,
) -> Result<Option<AgentGroupStateRow>, sqlx::Error>
where
    E: Executor<'a, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, AgentGroupStateRow>(
        r#"
        SELECT id
        FROM agent_groups
        WHERE external_id = $1
        LIMIT 1
        "#,
    )
    .bind(external_id)
    .fetch_optional(executor)
    .await
}
