-- S1 runtime (server.py SaaS MVP) — PostgreSQL-порт ensure_cloud_schema (SQLite).
--
-- ⚠️ НЕ путать с schema_s1..s5 (enterprise-задел): у тех ДРУГАЯ структура —
-- findings.scan_id NOT NULL, scans вместо scan_jobs, users/memberships, verdicts.
-- server.py работает на ЭТОЙ схеме; enterprise-слой мигрируется отдельно (S3+).
--
-- RLS здесь не включается намеренно: server.py пока ходит через один глобальный
-- backend (tenant_id=0) и скоупит tenant_id явно в WHERE. RLS — отдельный этап
-- (per-request/per-tenant backend), см. enterprise/tenancy.py.

CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    github_user TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    scans_used INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    target TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'audit',
    status TEXT NOT NULL DEFAULT 'queued',
    findings_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant ON scan_jobs(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS findings (
    finding_key TEXT,
    rule_id TEXT,
    title TEXT,
    severity TEXT DEFAULT 'UNKNOWN',
    confidence REAL DEFAULT 0.85,
    file TEXT,
    line INTEGER,
    snippet TEXT,
    tenant_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, finding_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(tenant_id, severity);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    github_user TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
