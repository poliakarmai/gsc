-- Test: SQL schema — sequential IDs, missing tenant isolation
-- Meta-inspired: auto-increment PK enables ticket ID enumeration

-- VULN: Auto-increment PK enables enumeration
CREATE TABLE support_tickets (
    id BIGSERIAL PRIMARY KEY,  -- GS007: SERIAL/BIGSERIAL
    user_id INTEGER NOT NULL,
    subject TEXT
);

-- VULN: User-scoped query without tenant filter (cross-org access)
SELECT * FROM tickets WHERE user_id = $1;  -- GS007: missing tenant isolation

-- OK: Has tenant isolation
SELECT * FROM tickets WHERE tenant_id = $1 AND user_id = $2;
