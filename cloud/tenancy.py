"""SaaS S1 — Multi-tenant foundation: api_keys, tenant isolation (v1.1)."""
import hashlib, hmac, secrets
from typing import Optional, Tuple

def generate_api_key() -> Tuple[str, str]:
    raw = "gsk_" + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()

def verify_api_key(db, raw_key: str) -> Optional[int]:
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    row = db.fetchone("SELECT tenant_id FROM api_keys WHERE key_hash=? AND revoked_at IS NULL", (h,))
    return row["tenant_id"] if row else None

def scoped_query(sql: str, tenant_id: int) -> Tuple[str, tuple]:
    if "WHERE" in sql.upper():
        return sql + " AND tenant_id = ?", (tenant_id,)
    return sql + " WHERE tenant_id = ?", (tenant_id,)
