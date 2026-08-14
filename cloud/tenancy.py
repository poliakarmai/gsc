"""SaaS S1 — legacy multi-tenant helpers (DEPRECATED).

GSC due-diligence шаг 4 («один auth contour»): этот контур дублирует
cloud/auth.py и НЕ подключён к живому server.py (SaaS MVP). Канонический auth —
cloud/auth.py (auth_tenant, prefix lookup, prefix `gsk_`). generate_api_key
делегирует туда; verify_api_key/scoped_query оставлены для обратной
совместимости с tests/test_cloud_s1.py и маркированы deprecated.
"""
import hashlib
from typing import Optional, Tuple


def generate_api_key() -> Tuple[str, str]:
    """Единая реализация — cloud.auth.generate_api_key (prefix `gsk_`)."""
    from cloud.auth import generate_api_key as _gen
    return _gen()


def verify_api_key(db, raw_key: str) -> Optional[int]:
    """DEPRECATED: legacy hash-lookup. Канонически — cloud.auth.auth_tenant
    (prefix lookup + compare_digest), как в server.py."""
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    row = db.fetchone("SELECT tenant_id FROM api_keys WHERE key_hash=? AND revoked_at IS NULL", (h,))
    return row["tenant_id"] if row else None


def scoped_query(sql: str, tenant_id: int) -> Tuple[str, tuple]:
    """DEPRECATED: legacy tenant-scope helper. server.py скоупит tenant явно в WHERE."""
    if "WHERE" in sql.upper():
        return sql + " AND tenant_id = ?", (tenant_id,)
    return sql + " WHERE tenant_id = ?", (tenant_id,)
