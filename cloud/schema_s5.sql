-- S5: Enterprise agents

CREATE TABLE IF NOT EXISTS agents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    agent_uuid TEXT NOT NULL UNIQUE,       -- генерируется при активации
    name TEXT NOT NULL DEFAULT 'agent',
    status TEXT NOT NULL DEFAULT 'active', -- active|revoked
    version TEXT,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_keys (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,                  -- "gscagt_xxxx…" для отображения
    agent_id BIGINT REFERENCES agents(id), -- NULL до активации
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_keys_prefix
    ON agent_keys(prefix);

CREATE TABLE IF NOT EXISTS agent_ingests (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL REFERENCES agents(id),
    repo TEXT NOT NULL,
    findings_count INT NOT NULL DEFAULT 0,
    chains_count INT NOT NULL DEFAULT 0,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ingests_tenant
    ON agent_ingests(tenant_id, ingested_at);

-- Findings от агентов: scan_id NULL (нет cloud-scan),
-- добавляем agent_source для идентификации
ALTER TABLE findings ADD COLUMN IF NOT EXISTS agent_id BIGINT
    REFERENCES agents(id);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source TEXT
    NOT NULL DEFAULT 'cloud';   -- cloud|agent