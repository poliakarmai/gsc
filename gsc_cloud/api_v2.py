"""SaaS S1 — legacy ``/api/v2`` handlers.

Multi-tenant endpoints kept for the S1 smoke tests
(``tests/test_cloud_s1.py``) and for callers that still POST to the
``/api/v2/scan`` and ``/api/v2/findings`` paths. The live SaaS MVP
also exposes ``/api/v2`` routes via ``gsc_cloud.server``; this module
is the standalone variant driven by ``verify_api_key`` /
``scoped_query`` from :mod:`gsc_cloud.auth` (canonical auth helpers).
"""
from typing import Tuple, Optional

from gsc_cloud.auth import verify_api_key, scoped_query


def handle_scan_v2(db, api_key: str, target: str, profile: str) -> Tuple[dict, int]:
    tid = verify_api_key(api_key, db)
    if tid is None:
        return {"error": "unauthorized"}, 401
    from gsc_external import ExternalScanner
    scanner = ExternalScanner(target, profile=profile)
    report = scanner.scan()
    for f in report.get("findings", []):
        f["tenant_id"] = tid
        db.execute("""INSERT OR REPLACE INTO findings (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id)
            VALUES (?,?,?,?,?,?,?,?,?)""", (f.get("finding_key",""),f.get("rule_id",""),f.get("title",""),
            f.get("severity",""),f.get("confidence",0.85),f.get("file",""),f.get("line",0),f.get("snippet",""),tid))
    return {"findings": len(report.get("findings", [])), "tenant_id": tid}, 200


def handle_findings_v2(db, api_key: str, severity: str = None, rule_id: str = None, limit: int = 50) -> Tuple[dict, int]:
    tid = verify_api_key(api_key, db)
    if tid is None:
        return {"error": "unauthorized"}, 401
    sql, params = scoped_query("SELECT * FROM findings", tid)
    # Optional filters
    if severity:
        sql += " AND severity = ?"
        params = (*params, severity)
    if rule_id:
        sql += " AND rule_id = ?"
        params = (*params, rule_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params = (*params, limit)
    rows = db.query(sql, params)
    return {"findings": [dict(r) for r in rows]}, 200
