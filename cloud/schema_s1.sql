-- S1: минимальный multi-tenant контур
CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    scan_limit_month INT NOT NULL DEFAULT 50,
    llm_budget_month INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,            -- "gsc_xxxx…" для отображения в UI
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS repos (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    clone_url TEXT NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS scans (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    repo_id BIGINT REFERENCES repos(id),
    profile TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'queued',   -- queued|running|done|error
    findings_total INT, blocking_count INT,
    llm_calls INT, duration_sec REAL,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    scan_id BIGINT NOT NULL REFERENCES scans(id),
    finding_key TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT, confidence REAL,
    file TEXT, line INT,
    snippet TEXT, poc TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- GSC-005: композитная уникальность (tenant_id, finding_key) на уровне БД —
-- гарантирует, что finding_key не «перескакивает» между тенантами.
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_tenant_key ON findings(tenant_id, finding_key);

CREATE TABLE IF NOT EXISTS verdicts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    finding_key TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL,            -- tp|fp|fixed
    reason TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usage (
    tenant_id BIGINT NOT NULL,
    period DATE NOT NULL,             -- первый день месяца
    scans INT NOT NULL DEFAULT 0,
    llm_calls INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, period)
);

-- Row-Level Security: второй рубеж после tenant_id в запросах.
-- GSC-005: FORCE ROW LEVEL SECURITY — RLS обязателен даже для table owner /
-- superuser, иначе «второй рубеж» молча обходится владельцем таблиц.
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans    ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE verdicts FORCE ROW LEVEL SECURITY;
ALTER TABLE scans    FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_findings ON findings
    USING (tenant_id = current_setting('app.tenant_id')::bigint);
CREATE POLICY tenant_verdicts ON verdicts
    USING (tenant_id = current_setting('app.tenant_id')::bigint);
CREATE POLICY tenant_scans ON scans
    USING (tenant_id = current_setting('app.tenant_id')::bigint);