-- S2: GitHub App + глубокие подсистемы (всё tenant-scoped)

CREATE TABLE IF NOT EXISTS github_installs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    installation_id BIGINT NOT NULL UNIQUE,
    org_login TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE repos ADD COLUMN IF NOT EXISTS gh_repo_id BIGINT;
ALTER TABLE repos ADD COLUMN IF NOT EXISTS install_id BIGINT
    REFERENCES github_installs(id);

-- История находок для мутаций/авто-resolve
ALTER TABLE findings ADD COLUMN IF NOT EXISTS pattern_fingerprint TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS normalized_snippet TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_by TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_rule_res
    ON findings(tenant_id, rule_id, resolved_at);

-- Метаданные скана (PR number, head_sha, etc.)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS metadata JSONB;

CREATE TABLE IF NOT EXISTS chains (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    chain_key TEXT NOT NULL,
    finding_keys JSONB NOT NULL,
    composed_severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    narrative TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, chain_key)
);

CREATE TABLE IF NOT EXISTS mutation_alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    finding_key TEXT NOT NULL,
    parent_key TEXT NOT NULL,
    kind TEXT NOT NULL,               -- mutation|recurrence
    similarity REAL NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, finding_key, parent_key)
);

CREATE TABLE IF NOT EXISTS overrides (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    repo_id BIGINT NOT NULL REFERENCES repos(id),
    pr_number INT NOT NULL,
    finding_key TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, repo_id, pr_number, finding_key)
);

CREATE TABLE IF NOT EXISTS published_comments (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    repo_id BIGINT NOT NULL REFERENCES repos(id),
    pr_number INT NOT NULL,
    comment_id BIGINT NOT NULL,
    head_sha TEXT,
    finding_keys JSONB,
    truncated INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, repo_id, pr_number)
);

CREATE TABLE IF NOT EXISTS publication_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT,
    repo_id BIGINT,
    pr_number INT,
    event TEXT NOT NULL,   -- published|updated|redaction_blocked|override|bypass
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS для новых тенант-таблиц
ALTER TABLE chains            ENABLE ROW LEVEL SECURITY;
ALTER TABLE mutation_alerts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE overrides         ENABLE ROW LEVEL SECURITY;
ALTER TABLE published_comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY t_chains   ON chains
    USING (tenant_id = current_setting('app.tenant_id')::bigint);
CREATE POLICY t_mutations ON mutation_alerts
    USING (tenant_id = current_setting('app.tenant_id')::bigint);
CREATE POLICY t_overrides ON overrides
    USING (tenant_id = current_setting('app.tenant_id')::bigint);
CREATE POLICY t_pubcomments ON published_comments
    USING (tenant_id = current_setting('app.tenant_id')::bigint);

ALTER TABLE chains            FORCE ROW LEVEL SECURITY;
ALTER TABLE mutation_alerts   FORCE ROW LEVEL SECURITY;
ALTER TABLE overrides         FORCE ROW LEVEL SECURITY;
ALTER TABLE published_comments FORCE ROW LEVEL SECURITY;