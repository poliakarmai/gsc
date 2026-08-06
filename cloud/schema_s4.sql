-- S4: audit log, SSO, deletion requests

-- Part 1: Audit log with hash chain
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    actor TEXT NOT NULL,                -- login или "system"
    action TEXT NOT NULL,               -- login|sso.login|scan.completed|
                                        -- verdict|override|billing.plan_changed|
                                        -- policy.updated|member.added|data.deletion_requested
    resource_type TEXT,                 -- finding|scan|repo|tenant|key
    resource_id TEXT,
    detail JSONB,
    prev_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
    ON audit_events(tenant_id, created_at);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY t_audit ON audit_events
    USING (tenant_id = current_setting('app.tenant_id')::bigint);


-- Part 2: SSO support
ALTER TABLE users ALTER COLUMN github_id DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_sso_subject
    ON users(sso_subject) WHERE sso_subject IS NOT NULL;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS sso_issuer_url TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS sso_client_id TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS sso_domains JSONB
    NOT NULL DEFAULT '[]';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS sso_required BOOLEAN
    NOT NULL DEFAULT false;


-- Part 3: Data lifecycle
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_source TEXT
    NOT NULL DEFAULT 'free';        -- free|stripe|marketplace

CREATE TABLE IF NOT EXISTS data_deletion_requests (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    requested_by TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending|completed
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    execute_at TIMESTAMPTZ NOT NULL,          -- +30 дней grace
    completed_at TIMESTAMPTZ
);

-- Audit log: tamper-evident (INSERT+SELECT only, no UPDATE/DELETE)
REVOKE UPDATE, DELETE ON audit_events FROM gsc_app;
GRANT INSERT, SELECT ON audit_events TO gsc_app;