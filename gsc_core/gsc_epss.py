#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC EPSS Exploitability v1.0 (v0.32).

Enriches SCA (GS030) findings with EPSS probability of exploitation.
Prioritisation by real risk: severity × epss × reachability.
Not paper CVSS severity.

EPSS API: https://api.first.org/data/v1/epss (free, no key required).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100
HTTP_TIMEOUT = 30
CACHE_TTL_HOURS = 24

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
EPSS_ACTIVE_THRESHOLD = 0.7
EPSS_PERCENTILE_KEV = 0.99
EPSS_LOW_THRESHOLD = 0.05


# ── CVE extraction ─────────────────────────────────────────
def extract_cve_id(sca_metadata: dict) -> Optional[str]:
    """Extract CVE from OSV vuln_id + aliases. None if PYSEC/GHSA-only."""
    candidates = [sca_metadata.get("vuln_id", "")]
    candidates.extend(sca_metadata.get("aliases", []) or [])
    for c in candidates:
        if not c:
            continue
        m = _CVE_RE.search(c)
        if m:
            return m.group(0).upper()
    return None


# ── EPSS Client ────────────────────────────────────────────
class EpssClient:
    def __init__(self, db=None, timeout: int = HTTP_TIMEOUT):
        self.db = db
        self.timeout = timeout

    def query(self, cve_ids: List[str]) -> Dict[str, dict]:
        """Query EPSS API with batch + cache. Returns {CVE: {epss, percentile, date}}."""
        results = {}
        to_query = []
        for cve in cve_ids:
            if not cve:
                continue
            cached = self._cache_get(cve) if self.db else None
            if cached is not None:
                results[cve] = cached
            else:
                to_query.append(cve)

        for i in range(0, len(to_query), EPSS_BATCH_SIZE):
            batch = to_query[i:i + EPSS_BATCH_SIZE]
            try:
                import urllib.request as request
                url = f"{EPSS_API}?cve={','.join(batch)}"
                with request.urlopen(url, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read())
            except Exception:
                continue

            for item in payload.get("data", []):
                cve = (item.get("cve") or "").upper()
                if not cve:
                    continue
                try:
                    entry = {"epss": float(item.get("epss", 0)),
                             "percentile": float(item.get("percentile", 0)),
                             "date": item.get("date", "")}
                except (TypeError, ValueError):
                    continue
                results[cve] = entry
                if self.db:
                    self._cache_put(cve, entry)
        return results

    def _cache_get(self, cve: str) -> Optional[dict]:
        row = self.db.conn.execute(
            "SELECT epss, percentile, epss_date, fetched_at FROM epss_cache WHERE cve_id = ?",
            (cve,)).fetchone()
        if not row:
            return None
        fresh = self.db.conn.execute(
            "SELECT 1 AS ok WHERE datetime(?, '+' || ? || ' hours') > datetime('now')",
            (row["fetched_at"], CACHE_TTL_HOURS)).fetchone()
        if not fresh:
            return None
        return {"epss": row["epss"], "percentile": row["percentile"], "date": row["epss_date"]}

    def _cache_put(self, cve: str, entry: dict):
        self.db.conn.execute(
            "INSERT OR REPLACE INTO epss_cache (cve_id, epss, percentile, epss_date, fetched_at) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            (cve, entry["epss"], entry["percentile"], entry["date"]))
        self.db.conn.commit()


# ── Risk scoring ───────────────────────────────────────────
def estimate_reachability(finding: dict) -> float:
    sca = finding.get("metadata", {}).get("sca", {})
    return 0.5 if sca.get("is_dev_dependency") else 1.0


def compute_risk(severity: str, epss_score: float, reachability: float = 1.0) -> dict:
    """risk = severity_weight × epss × reachability."""
    weight = SEVERITY_WEIGHT.get(severity, 0.5)
    epss_score = max(0.0, min(1.0, epss_score))
    reachability = max(0.0, min(1.0, reachability))
    risk = weight * epss_score * reachability
    level = "critical" if risk >= 0.7 else "high" if risk >= 0.4 else \
            "medium" if risk >= 0.15 else "low"
    return {"score": round(risk, 3), "level": level,
            "formula": f"sev({weight}) × epss({epss_score:.2f}) × reach({reachability})"}


# ── Enrichment ─────────────────────────────────────────────
def enrich_sca_findings(findings: List[dict], db=None) -> List[dict]:
    """Enrich GS030 findings with EPSS + contextual risk."""
    client = EpssClient(db=db)
    cve_ids = []
    for f in findings:
        if not f.get("rule_id", "").startswith("GS030"):
            continue
        cve = extract_cve_id(f.get("metadata", {}).get("sca", {}))
        if cve:
            cve_ids.append(cve)
    if not cve_ids:
        return findings

    epss_data = client.query(list(set(cve_ids)))

    for f in findings:
        if not f.get("rule_id", "").startswith("GS030"):
            continue
        sca = f.get("metadata", {}).get("sca", {})
        cve = extract_cve_id(sca)
        if not cve or cve not in epss_data:
            continue
        entry = epss_data[cve]
        reach = estimate_reachability(f)
        risk = compute_risk(f.get("severity", "MEDIUM"), entry["epss"], reach)

        meta = f.setdefault("metadata", {})
        meta["epss"] = {"cve": cve, "score": entry["epss"],
                        "percentile": entry["percentile"], "date": entry["date"]}
        meta["risk"] = risk

        if entry["percentile"] >= EPSS_PERCENTILE_KEV or entry["epss"] >= EPSS_ACTIVE_THRESHOLD:
            meta["exploit_signal"] = "actively_exploited"
            f["confidence"] = min(0.99, f.get("confidence", 0.9) + 0.05)
        elif entry["epss"] < EPSS_LOW_THRESHOLD:
            meta["exploit_signal"] = "low_exploit_probability"
            meta["priority_note"] = "low EPSS — schedule, not emergency"
    return findings


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC EPSS exploitability lookup")
    p.add_argument("--cve", help="Lookup single CVE (e.g. CVE-2021-44228)")
    p.add_argument("--enrich-report", help="Enrich scan.json with EPSS")
    p.add_argument("--output", "-o", help="Save enriched report")
    args = p.parse_args()

    sys.path.insert(0, str(Path(__file__).parent))
    from gsc_core.gsc_db import GSCDatabase

    if args.cve:
        with GSCDatabase() as db:
            client = EpssClient(db=db)
            data = client.query([args.cve.upper()])
            e = data.get(args.cve.upper())
            if e:
                print(f"{args.cve.upper()}: epss={e['epss']:.4f} "
                      f"percentile={e['percentile']:.4f} ({e['date']})")
            else:
                print(f"No EPSS data for {args.cve.upper()}")
        return

    if args.enrich_report:
        with open(args.enrich_report) as f:
            report = json.load(f)
        findings = enrich_sca_findings(report.get("findings", []))
        report["findings"] = findings
        active = [f for f in findings
                  if f.get("metadata", {}).get("exploit_signal") == "actively_exploited"]
        print(f"Actively exploited: {len(active)}")
        for f in active[:10]:
            e = f["metadata"].get("epss", {})
            r = f["metadata"].get("risk", {})
            pkg = f["metadata"].get("sca", {}).get("package", "?")
            print(f"  {pkg}: epss={e.get('score',0):.2f} risk={r.get('level','?')}")
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
