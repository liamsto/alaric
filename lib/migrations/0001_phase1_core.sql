CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE principal_kind AS ENUM ('agent', 'client');
CREATE TYPE key_algorithm AS ENUM ('ed25519');
CREATE TYPE session_log_outcome AS ENUM ('accepted', 'rejected', 'error');
CREATE TYPE handshake_rejection_code AS ENUM (
    'unsupported_protocol_version',
    'invalid_request',
    'agent_id_in_use',
    'agent_unavailable',
    'unauthorized',
    'internal_error'
);
CREATE TYPE command_run_outcome AS ENUM ('completed', 'rejected', 'error');
CREATE TYPE command_rejection_code AS ENUM (
    'unknown_command',
    'invalid_args',
    'policy_error',
    'execution_error',
    'timeout',
    'output_limit'
);

CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind principal_kind NOT NULL,
    external_id TEXT NOT NULL,
    display_name TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ,
    UNIQUE (kind, external_id),
    CHECK (jsonb_typeof(metadata) = 'object'),
    CHECK (char_length(external_id) BETWEEN 3 AND 64),
    CHECK (external_id ~ '^[A-Za-z0-9._-]+$')
);

CREATE TABLE principal_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    algorithm key_algorithm NOT NULL,
    public_key BYTEA NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (principal_id, key_id),
    CHECK (char_length(key_id) > 0),
    CHECK (octet_length(public_key) > 0),
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

CREATE TABLE session_log (
    session_id UUID PRIMARY KEY,
    client_principal_id UUID REFERENCES principals(id) ON DELETE SET NULL,
    target_agent_principal_id UUID REFERENCES principals(id) ON DELETE SET NULL,
    paired_agent_principal_id UUID REFERENCES principals(id) ON DELETE SET NULL,
    outcome session_log_outcome NOT NULL,
    rejection_code handshake_rejection_code,
    error_code TEXT,
    error_message TEXT,
    client_peer_ip INET,
    client_peer_port INTEGER,
    agent_peer_ip INET,
    agent_peer_port INTEGER,
    opened_at TIMESTAMPTZ NOT NULL,
    paired_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CHECK (client_peer_port IS NULL OR client_peer_port BETWEEN 1 AND 65535),
    CHECK (agent_peer_port IS NULL OR agent_peer_port BETWEEN 1 AND 65535),
    CHECK ((outcome = 'rejected' AND rejection_code IS NOT NULL) OR (outcome <> 'rejected' AND rejection_code IS NULL)),
    CHECK (paired_at IS NULL OR paired_at >= opened_at),
    CHECK (completed_at IS NULL OR completed_at >= opened_at)
);

CREATE TABLE agent_presence (
    principal_id UUID PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    connected_session_id UUID REFERENCES session_log(session_id) ON DELETE SET NULL,
    connected_at TIMESTAMPTZ,
    disconnected_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL,
    disconnect_reason TEXT,
    lease_expires_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (jsonb_typeof(metadata) = 'object'),
    CHECK (disconnected_at IS NULL OR connected_at IS NULL OR disconnected_at >= connected_at)
);

CREATE TABLE command_runs (
    run_id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES session_log(session_id) ON DELETE CASCADE,
    request_id BIGINT NOT NULL,
    command_id TEXT NOT NULL,
    outcome command_run_outcome NOT NULL,
    exit_code INTEGER,
    timed_out BOOLEAN,
    truncated BOOLEAN,
    rejection_code command_rejection_code,
    error_code TEXT,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (session_id, request_id),
    CHECK (request_id >= 0),
    CHECK (char_length(command_id) BETWEEN 1 AND 128),
    CHECK (command_id ~ '^[A-Za-z0-9._-]+$'),
    CHECK (
        (
            outcome = 'completed'
            AND exit_code IS NOT NULL
            AND timed_out IS NOT NULL
            AND truncated IS NOT NULL
            AND rejection_code IS NULL
            AND error_code IS NULL
        )
        OR (
            outcome = 'rejected'
            AND exit_code IS NULL
            AND timed_out IS NULL
            AND truncated IS NULL
            AND rejection_code IS NOT NULL
            AND error_code IS NULL
        )
        OR (
            outcome = 'error'
            AND exit_code IS NULL
            AND timed_out IS NULL
            AND truncated IS NULL
            AND rejection_code IS NULL
            AND error_code IS NOT NULL
        )
    ),
    CHECK (completed_at >= started_at),
    CHECK (reported_at >= completed_at)
);

CREATE INDEX idx_session_log_opened_at ON session_log(opened_at);
CREATE INDEX idx_session_log_completed_at ON session_log(completed_at);
CREATE INDEX idx_session_log_outcome ON session_log(outcome);

CREATE INDEX idx_command_runs_completed_at ON command_runs(completed_at);
CREATE INDEX idx_command_runs_session_request ON command_runs(session_id, request_id);

CREATE OR REPLACE FUNCTION prune_phase1_logs(retention_days INTEGER DEFAULT 60)
RETURNS TABLE(command_runs_deleted BIGINT, session_logs_deleted BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    cutoff TIMESTAMPTZ;
BEGIN
    IF retention_days < 30 OR retention_days > 90 THEN
        RAISE EXCEPTION 'retention_days must be between 30 and 90';
    END IF;

    cutoff := NOW() - make_interval(days => retention_days);

    WITH deleted_runs AS (
        DELETE FROM command_runs
        WHERE completed_at < cutoff
        RETURNING 1
    )
    SELECT COUNT(*) INTO command_runs_deleted FROM deleted_runs;

    WITH deleted_sessions AS (
        DELETE FROM session_log
        WHERE completed_at IS NOT NULL
          AND completed_at < cutoff
        RETURNING 1
    )
    SELECT COUNT(*) INTO session_logs_deleted FROM deleted_sessions;

    RETURN QUERY SELECT command_runs_deleted, session_logs_deleted;
END;
$$;
