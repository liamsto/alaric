CREATE TABLE agent_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL UNIQUE,
    display_name TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (jsonb_typeof(metadata) = 'object'),
    CHECK (char_length(external_id) BETWEEN 3 AND 64),
    CHECK (external_id ~ '^[A-Za-z0-9._-]+$')
);

CREATE TABLE agent_group_members (
    group_id UUID NOT NULL REFERENCES agent_groups(id) ON DELETE CASCADE,
    agent_principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, agent_principal_id)
);

CREATE INDEX idx_agent_group_members_agent_principal_id
    ON agent_group_members(agent_principal_id);
