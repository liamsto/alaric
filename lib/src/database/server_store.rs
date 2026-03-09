use std::net::SocketAddr;

use sqlx::types::{Uuid, ipnetwork::IpNetwork};

use crate::{
    database::{
        Database,
        command_runs::{CommandRejectionCode, CommandRunReport, CommandRunResult},
        principals::PrincipalKind,
        sessions::HandshakeRejectionCode,
    },
    protocol::{AgentId, ClientId, HandshakeErrorCode, HandshakeRequest, SessionId},
};

#[derive(Debug, Clone)]
pub struct ActivePrincipalKey {
    pub principal_id: Uuid,
    pub kind: PrincipalKind,
    pub external_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneLogsResult {
    pub command_runs_deleted: i64,
    pub session_logs_deleted: i64,
}

#[derive(Debug)]
pub enum ServerStoreError {
    Sqlx(sqlx::Error),
    InvalidPublicKeyLength {
        external_id: String,
        expected: usize,
        actual: usize,
    },
    RequestIdOutOfRange(u64),
}

impl std::fmt::Display for ServerStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerStoreError::Sqlx(source) => write!(f, "database error: {}", source),
            ServerStoreError::InvalidPublicKeyLength {
                external_id,
                expected,
                actual,
            } => write!(
                f,
                "principal '{}' has invalid public key length: expected {}, got {}",
                external_id, expected, actual
            ),
            ServerStoreError::RequestIdOutOfRange(value) => write!(
                f,
                "request id {} exceeds the supported BIGINT range for postgres",
                value
            ),
        }
    }
}

impl std::error::Error for ServerStoreError {}

impl From<sqlx::Error> for ServerStoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

#[derive(Debug)]
struct ActivePrincipalKeyRow {
    principal_id: Uuid,
    kind: PrincipalKind,
    external_id: String,
    key_id: String,
    public_key: Vec<u8>,
}

#[derive(Debug)]
struct PrincipalIdRow {
    id: Uuid,
}

#[derive(Debug)]
#[allow(dead_code)]
struct SessionIdRow {
    session_id: Uuid,
}

#[derive(Debug)]
struct PruneLogsRow {
    command_runs_deleted: Option<i64>,
    session_logs_deleted: Option<i64>,
}

impl Database {
    pub async fn load_active_principal_keys(
        &self,
    ) -> Result<Vec<ActivePrincipalKey>, ServerStoreError> {
        let rows = sqlx::query_as!(
            ActivePrincipalKeyRow,
            r#"
            SELECT
                p.id AS principal_id,
                p.kind AS "kind: PrincipalKind",
                p.external_id,
                pk.key_id,
                pk.public_key
            FROM principals AS p
            INNER JOIN principal_keys AS pk
                ON pk.principal_id = p.id
            WHERE p.disabled_at IS NULL
              AND pk.revoked_at IS NULL
              AND pk.valid_from <= NOW()
              AND (pk.valid_to IS NULL OR pk.valid_to >= NOW())
            ORDER BY p.kind, p.external_id, pk.valid_from DESC
            "#
        )
        .fetch_all(self.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            if row.public_key.len() != 32 {
                return Err(ServerStoreError::InvalidPublicKeyLength {
                    external_id: row.external_id,
                    expected: 32,
                    actual: row.public_key.len(),
                });
            }

            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&row.public_key);
            out.push(ActivePrincipalKey {
                principal_id: row.principal_id,
                kind: row.kind,
                external_id: row.external_id,
                key_id: row.key_id,
                public_key,
            });
        }
        Ok(out)
    }

    pub async fn record_session_rejection(
        &self,
        session_id: SessionId,
        request: Option<&HandshakeRequest>,
        code: HandshakeErrorCode,
        message: &str,
        peer: SocketAddr,
    ) -> Result<(), ServerStoreError> {
        let (client_peer_ip, client_peer_port) = split_peer_addr(peer);
        let rejection_code: HandshakeRejectionCode = code.into();

        let (client_external_id, target_agent_external_id, paired_agent_external_id) = match request
        {
            Some(HandshakeRequest::Client {
                client_id,
                target_agent_id,
                ..
            }) => (
                Some(client_id.as_str().to_string()),
                Some(target_agent_id.as_str().to_string()),
                None,
            ),
            Some(HandshakeRequest::Agent { agent_id, .. }) => (
                None,
                Some(agent_id.as_str().to_string()),
                Some(agent_id.as_str().to_string()),
            ),
            None => (None, None, None),
        };

        let client_principal_id =
            resolve_principal_id(self, PrincipalKind::Client, client_external_id.as_deref())
                .await?;
        let target_agent_principal_id = resolve_principal_id(
            self,
            PrincipalKind::Agent,
            target_agent_external_id.as_deref(),
        )
        .await?;
        let paired_agent_principal_id = resolve_principal_id(
            self,
            PrincipalKind::Agent,
            paired_agent_external_id.as_deref(),
        )
        .await?;

        let _ = sqlx::query_as!(
            SessionIdRow,
            r#"
            INSERT INTO session_log (
                session_id,
                client_principal_id,
                target_agent_principal_id,
                paired_agent_principal_id,
                outcome,
                rejection_code,
                error_message,
                client_peer_ip,
                client_peer_port,
                opened_at,
                completed_at
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                'rejected',
                $5,
                $6,
                $7::inet,
                $8,
                NOW(),
                NOW()
            )
            ON CONFLICT (session_id) DO UPDATE
            SET outcome = EXCLUDED.outcome,
                rejection_code = EXCLUDED.rejection_code,
                error_message = EXCLUDED.error_message,
                completed_at = NOW()
            RETURNING session_id
            "#,
            session_id.as_uuid(),
            client_principal_id,
            target_agent_principal_id,
            paired_agent_principal_id,
            rejection_code as HandshakeRejectionCode,
            message,
            client_peer_ip,
            client_peer_port,
        )
        .fetch_one(self.pool())
        .await?;
        Ok(())
    }

    pub async fn record_agent_waiting(
        &self,
        session_id: SessionId,
        agent_id: &AgentId,
        peer: SocketAddr,
    ) -> Result<(), ServerStoreError> {
        let agent_principal_id =
            resolve_principal_id(self, PrincipalKind::Agent, Some(agent_id.as_str())).await?;
        let (agent_peer_ip, agent_peer_port) = split_peer_addr(peer);

        let _ = sqlx::query_as!(
            SessionIdRow,
            r#"
            INSERT INTO session_log (
                session_id,
                target_agent_principal_id,
                outcome,
                agent_peer_ip,
                agent_peer_port,
                opened_at
            )
            VALUES ($1, $2, 'accepted', $3::inet, $4, NOW())
            ON CONFLICT (session_id) DO UPDATE
            SET target_agent_principal_id = EXCLUDED.target_agent_principal_id,
                outcome = EXCLUDED.outcome,
                agent_peer_ip = EXCLUDED.agent_peer_ip,
                agent_peer_port = EXCLUDED.agent_peer_port,
                opened_at = NOW()
            RETURNING session_id
            "#,
            session_id.as_uuid(),
            agent_principal_id,
            agent_peer_ip,
            agent_peer_port,
        )
        .fetch_one(self.pool())
        .await?;

        if let Some(agent_principal_id) = agent_principal_id {
            let _ = sqlx::query_as!(
                PrincipalIdRow,
                r#"
                INSERT INTO agent_presence (
                    principal_id,
                    connected_session_id,
                    connected_at,
                    disconnected_at,
                    last_seen_at,
                    disconnect_reason,
                    metadata
                )
                VALUES ($1, $2, NOW(), NULL, NOW(), NULL, '{}'::jsonb)
                ON CONFLICT (principal_id) DO UPDATE
                SET connected_session_id = EXCLUDED.connected_session_id,
                    connected_at = NOW(),
                    disconnected_at = NULL,
                    last_seen_at = NOW(),
                    disconnect_reason = NULL
                RETURNING principal_id AS id
                "#,
                agent_principal_id,
                session_id.as_uuid(),
            )
            .fetch_one(self.pool())
            .await?;
        }

        Ok(())
    }

    pub async fn record_client_pairing(
        &self,
        session_id: SessionId,
        client_id: &ClientId,
        target_agent_id: &AgentId,
        peer: SocketAddr,
    ) -> Result<(), ServerStoreError> {
        let client_principal_id =
            resolve_principal_id(self, PrincipalKind::Client, Some(client_id.as_str())).await?;
        let target_agent_principal_id =
            resolve_principal_id(self, PrincipalKind::Agent, Some(target_agent_id.as_str()))
                .await?;
        let (client_peer_ip, client_peer_port) = split_peer_addr(peer);

        let _ = sqlx::query_as!(
            SessionIdRow,
            r#"
            UPDATE session_log
            SET client_principal_id = $2,
                target_agent_principal_id = $3,
                paired_agent_principal_id = $3,
                client_peer_ip = $4::inet,
                client_peer_port = $5,
                paired_at = NOW()
            WHERE session_id = $1
            RETURNING session_id
            "#,
            session_id.as_uuid(),
            client_principal_id,
            target_agent_principal_id,
            client_peer_ip,
            client_peer_port,
        )
        .fetch_one(self.pool())
        .await?;
        Ok(())
    }

    pub async fn record_agent_disconnected(
        &self,
        session_id: SessionId,
        agent_id: &AgentId,
        reason: &str,
    ) -> Result<(), ServerStoreError> {
        let _ = sqlx::query_as!(
            SessionIdRow,
            r#"
            UPDATE session_log
            SET completed_at = NOW(),
                error_code = COALESCE(error_code, 'agent_disconnected'),
                error_message = COALESCE(error_message, $2),
                outcome = CASE
                    WHEN paired_at IS NULL THEN 'error'::session_log_outcome
                    ELSE outcome
                END
            WHERE session_id = $1
            RETURNING session_id
            "#,
            session_id.as_uuid(),
            reason,
        )
        .fetch_optional(self.pool())
        .await?;

        if let Some(agent_principal_id) =
            resolve_principal_id(self, PrincipalKind::Agent, Some(agent_id.as_str())).await?
        {
            let _ = sqlx::query_as!(
                PrincipalIdRow,
                r#"
                INSERT INTO agent_presence (
                    principal_id,
                    connected_session_id,
                    disconnected_at,
                    last_seen_at,
                    disconnect_reason,
                    metadata
                )
                VALUES ($1, NULL, NOW(), NOW(), $2, '{}'::jsonb)
                ON CONFLICT (principal_id) DO UPDATE
                SET connected_session_id = NULL,
                    disconnected_at = NOW(),
                    last_seen_at = NOW(),
                    disconnect_reason = EXCLUDED.disconnect_reason
                RETURNING principal_id AS id
                "#,
                agent_principal_id,
                reason,
            )
            .fetch_one(self.pool())
            .await?;
        }

        Ok(())
    }

    pub async fn record_session_completed(
        &self,
        session_id: SessionId,
    ) -> Result<(), ServerStoreError> {
        let _ = sqlx::query_as!(
            SessionIdRow,
            r#"
            UPDATE session_log
            SET completed_at = NOW()
            WHERE session_id = $1
            RETURNING session_id
            "#,
            session_id.as_uuid(),
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(())
    }

    pub async fn upsert_command_run_report(
        &self,
        report: &CommandRunReport,
    ) -> Result<(), ServerStoreError> {
        let request_id = i64::try_from(report.request_id.0)
            .map_err(|_| ServerStoreError::RequestIdOutOfRange(report.request_id.0))?;
        let command_id = report.command_id.as_str().to_string();

        match &report.result {
            CommandRunResult::Completed {
                exit_code,
                timed_out,
                truncated,
            } => {
                let _ = sqlx::query_as!(
                    SessionIdRow,
                    r#"
                    INSERT INTO command_runs (
                        run_id,
                        session_id,
                        request_id,
                        command_id,
                        outcome,
                        exit_code,
                        timed_out,
                        truncated,
                        started_at,
                        completed_at,
                        reported_at
                    )
                    VALUES ($1, $2, $3, $4, 'completed', $5, $6, $7, $8, $9, NOW())
                    ON CONFLICT (session_id, request_id) DO UPDATE
                    SET run_id = EXCLUDED.run_id,
                        command_id = EXCLUDED.command_id,
                        outcome = EXCLUDED.outcome,
                        exit_code = EXCLUDED.exit_code,
                        timed_out = EXCLUDED.timed_out,
                        truncated = EXCLUDED.truncated,
                        rejection_code = NULL,
                        error_code = NULL,
                        error_message = NULL,
                        started_at = EXCLUDED.started_at,
                        completed_at = EXCLUDED.completed_at,
                        reported_at = NOW()
                    RETURNING session_id
                    "#,
                    report.run_id,
                    report.session_id.as_uuid(),
                    request_id,
                    command_id,
                    exit_code,
                    timed_out,
                    truncated,
                    report.started_at,
                    report.completed_at,
                )
                .fetch_one(self.pool())
                .await?;
            }
            CommandRunResult::Rejected { code, message } => {
                let rejection_code: CommandRejectionCode = (*code).into();
                let _ = sqlx::query_as!(
                    SessionIdRow,
                    r#"
                    INSERT INTO command_runs (
                        run_id,
                        session_id,
                        request_id,
                        command_id,
                        outcome,
                        rejection_code,
                        error_message,
                        started_at,
                        completed_at,
                        reported_at
                    )
                    VALUES ($1, $2, $3, $4, 'rejected', $5, $6, $7, $8, NOW())
                    ON CONFLICT (session_id, request_id) DO UPDATE
                    SET run_id = EXCLUDED.run_id,
                        command_id = EXCLUDED.command_id,
                        outcome = EXCLUDED.outcome,
                        exit_code = NULL,
                        timed_out = NULL,
                        truncated = NULL,
                        rejection_code = EXCLUDED.rejection_code,
                        error_code = NULL,
                        error_message = EXCLUDED.error_message,
                        started_at = EXCLUDED.started_at,
                        completed_at = EXCLUDED.completed_at,
                        reported_at = NOW()
                    RETURNING session_id
                    "#,
                    report.run_id,
                    report.session_id.as_uuid(),
                    request_id,
                    command_id,
                    rejection_code as CommandRejectionCode,
                    message,
                    report.started_at,
                    report.completed_at,
                )
                .fetch_one(self.pool())
                .await?;
            }
            CommandRunResult::Error { code, message } => {
                let _ = sqlx::query_as!(
                    SessionIdRow,
                    r#"
                    INSERT INTO command_runs (
                        run_id,
                        session_id,
                        request_id,
                        command_id,
                        outcome,
                        error_code,
                        error_message,
                        started_at,
                        completed_at,
                        reported_at
                    )
                    VALUES ($1, $2, $3, $4, 'error', $5, $6, $7, $8, NOW())
                    ON CONFLICT (session_id, request_id) DO UPDATE
                    SET run_id = EXCLUDED.run_id,
                        command_id = EXCLUDED.command_id,
                        outcome = EXCLUDED.outcome,
                        exit_code = NULL,
                        timed_out = NULL,
                        truncated = NULL,
                        rejection_code = NULL,
                        error_code = EXCLUDED.error_code,
                        error_message = EXCLUDED.error_message,
                        started_at = EXCLUDED.started_at,
                        completed_at = EXCLUDED.completed_at,
                        reported_at = NOW()
                    RETURNING session_id
                    "#,
                    report.run_id,
                    report.session_id.as_uuid(),
                    request_id,
                    command_id,
                    code,
                    message,
                    report.started_at,
                    report.completed_at,
                )
                .fetch_one(self.pool())
                .await?;
            }
        }

        Ok(())
    }

    pub async fn prune_phase1_logs(&self) -> Result<PruneLogsResult, ServerStoreError> {
        let retention_days = i32::from(self.log_retention_days().get());
        let row = sqlx::query_as!(
            PruneLogsRow,
            r#"
            SELECT
                command_runs_deleted,
                session_logs_deleted
            FROM prune_phase1_logs($1)
            "#,
            retention_days,
        )
        .fetch_one(self.pool())
        .await?;

        Ok(PruneLogsResult {
            command_runs_deleted: row.command_runs_deleted.unwrap_or(0),
            session_logs_deleted: row.session_logs_deleted.unwrap_or(0),
        })
    }
}

fn split_peer_addr(peer: SocketAddr) -> (IpNetwork, i32) {
    (IpNetwork::from(peer.ip()), i32::from(peer.port()))
}

async fn resolve_principal_id(
    database: &Database,
    kind: PrincipalKind,
    external_id: Option<&str>,
) -> Result<Option<Uuid>, ServerStoreError> {
    let Some(external_id) = external_id else {
        return Ok(None);
    };

    let row = sqlx::query_as!(
        PrincipalIdRow,
        r#"
        SELECT id
        FROM principals
        WHERE kind = $1
          AND external_id = $2
          AND disabled_at IS NULL
        LIMIT 1
        "#,
        kind as PrincipalKind,
        external_id,
    )
    .fetch_optional(database.pool())
    .await?;

    Ok(row.map(|row| row.id))
}
