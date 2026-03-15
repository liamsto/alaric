use std::{error::Error, fmt};

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
    protocol::{AgentId, ClientId, decode_ed25519_public_key},
};

#[derive(Debug)]
pub enum AdminStoreError {
    Sqlx(sqlx::Error),
    InvalidPrincipalId(String),
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

impl Database {
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
}

fn validate_principal_id(kind: PrincipalKind, external_id: &str) -> Result<(), AdminStoreError> {
    let result = match kind {
        PrincipalKind::Agent => AgentId::new(external_id).map(|_| ()),
        PrincipalKind::Client => ClientId::new(external_id).map(|_| ()),
    }
    .map_err(|err| AdminStoreError::InvalidPrincipalId(err.to_string()));

    result
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
