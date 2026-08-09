"""Multi-tenancy with PostgreSQL Row-Level Security for GSC Enterprise (v0.38)."""
from typing import Dict

TABLES = ["findings","feedback","chains","overrides","secret_sightings","dast_findings"]

class TenantContext:
    def __init__(self, conn, tenant_id: str): self.conn = conn; self.tid = tenant_id
    def __enter__(self): self.conn.execute("BEGIN"); self.conn.execute("SELECT set_config('app.tenant_id',%s,true)", (self.tid,)); return self.conn
    def __exit__(self, e, *a): self.conn.execute("COMMIT" if e is None else "ROLLBACK")

def apply_rls(conn):
    for t in TABLES:
        conn.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        conn.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        conn.execute(f"CREATE POLICY tenant_isolation_{t} ON {t} USING (tenant_id = current_setting('app.tenant_id')::TEXT)")
    conn.commit()
