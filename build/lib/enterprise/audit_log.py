"""Tamper-evident audit log with hash chain for GSC Enterprise (v0.38)."""
import hashlib, json
from datetime import datetime, timezone
from typing import Dict, List, Optional

GENESIS = "0" * 64

class AuditLog:
    def __init__(self, db): self.db = db

    def _last_hash(self, tid: str) -> str:
        r = self.db.fetchone("SELECT entry_hash FROM enterprise_audit WHERE tenant_id=? ORDER BY id DESC LIMIT 1", (tid,))
        return r["entry_hash"] if r else GENESIS

    def _hash(self, prev: str, entry: Dict) -> str:
        return hashlib.sha256((prev + json.dumps(entry, sort_keys=True, separators=(",",":"), ensure_ascii=False)).encode()).hexdigest()

    def record(self, tenant_id: str, user_id: str, action: str, resource_type: str = None, resource_id: str = None, detail: str = None):
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "tenant_id": tenant_id, "user_id": user_id,
                 "action": action, "resource_type": resource_type, "resource_id": resource_id, "detail": detail}
        prev = self._last_hash(tenant_id)
        h = self._hash(prev, entry)
        self.db.execute("""INSERT INTO enterprise_audit (ts,tenant_id,user_id,action,resource_type,resource_id,detail,prev_hash,entry_hash)
            VALUES (?,?,?,?,?,?,?,?,?)""", (entry["ts"], tenant_id, user_id, action, resource_type, resource_id, detail, prev, h))

    def verify_chain(self, tid: str) -> bool:
        rows = self.db.query("SELECT * FROM enterprise_audit WHERE tenant_id=? ORDER BY id", (tid,))
        prev = GENESIS
        for r in rows:
            entry = {"ts": r["ts"], "tenant_id": r["tenant_id"], "user_id": r["user_id"], "action": r["action"],
                     "resource_type": r["resource_type"], "resource_id": r["resource_id"], "detail": r["detail"]}
            if self._hash(prev, entry) != r["entry_hash"] or r["prev_hash"] != prev: return False
            prev = r["entry_hash"]
        return True
