"""SaaS S1 — /api/v2 multi-tenant endpoints (v1.1)."""
from typing import Tuple
from cloud.tenancy import verify_api_key, scoped_query

def handle_scan_v2(db, api_key: str, target: str, profile: str) -> Tuple[dict, int]:
    tid = verify_api_key(db, api_key)
    if tid is None: return {"error": "unauthorized"}, 401
    from gsc_external import ExternalScanner
    scanner = ExternalScanner(target, profile=profile)
    report = scanner.scan()
    for f in report.get("findings", []):
        f["tenant_id"] = tid
        db.execute("""INSERT OR REPLACE INTO findings (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id)
            VALUES (?,?,?,?,?,?,?,?,?)""", (f.get("finding_key",""),f.get("rule_id",""),f.get("title",""),
            f.get("severity",""),f.get("confidence",0.85),f.get("file",""),f.get("line",0),f.get("snippet",""),tid))
    return {"findings": len(report.get("findings", [])), "tenant_id": tid}, 200

def handle_findings_v2(db, api_key: str) -> Tuple[dict, int]:
    tid = verify_api_key(db, api_key)
    if tid is None: return {"error": "unauthorized"}, 401
    sql, params = scoped_query("SELECT * FROM findings", tid)
    rows = db.query(sql, params)
    return {"findings": [dict(r) for r in rows]}, 200
