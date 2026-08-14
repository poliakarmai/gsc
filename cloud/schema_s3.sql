-- S3: пользователи, членства, биллинг

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    github_id BIGINT NOT NULL UNIQUE,
    login TEXT NOT NULL,
    email TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS memberships (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    role TEXT NOT NULL DEFAULT 'developer',   -- owner|security|developer
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, tenant_id)
);

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS billing_email TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS seat_count INT NOT NULL DEFAULT 1;

ALTER TABLE usage ADD COLUMN IF NOT EXISTS llm_calls_blocked INT
    NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS stripe_events (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,        -- идемпотентность webhook'ов
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- S-08: invite-only onboarding — dashboard access requires an admin-issued invite
CREATE TABLE IF NOT EXISTS invites (
    id BIGSERIAL PRIMARY KEY,
    email TEXT,
    github_login TEXT,
    tenant_id BIGINT REFERENCES tenants(id),
    role TEXT NOT NULL DEFAULT 'developer',
    status TEXT NOT NULL DEFAULT 'pending',   -- pending|accepted|revoked
    created_by BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE INDEX IF NOT EXISTS idx_invites_login ON invites(github_login);