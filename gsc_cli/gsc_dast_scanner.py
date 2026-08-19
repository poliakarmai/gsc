#!/usr/bin/env python3
"""GSC DAST Scanner v1.0 — nuclei-based dynamic scanning (SAST+DAST hybrid)."""
from __future__ import annotations
import json, subprocess, sys, tempfile
from pathlib import Path
from typing import Dict, List, Optional
try:
    import yaml
except ImportError:
    print("Install: pip install pyyaml"); sys.exit(1)

def _get_db():
    from gsc_db import GSCDatabase
    db = GSCDatabase()
    db.__enter__()
    return db

def _export_templates_from_db(conn) -> str:
    templates_dir = Path(tempfile.mkdtemp(prefix="gsc_nuclei_"))
    rows = conn.conn.execute("SELECT * FROM nuclei_templates").fetchall()
    if not rows:
        raise RuntimeError("No templates in DB. Run: gsc import-nuclei <directory>")
    for row in rows:
        template = {
            "id": row["template_id"],
            "info": {"name": row["name"], "severity": row["severity"],
                     "description": row["description"] or "",
                     "tags": json.loads(row["tags"] or "[]")},
            "requests": json.loads(row["requests"] or "[]"),
        }
        p = templates_dir / f"{row['template_id']}.yaml"
        p.write_text(yaml.dump(template, default_flow_style=False, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return str(templates_dir)

def _parse_nuclei_output(jsonl_path: str, target_url: str, conn=None) -> List[dict]:
    findings = []
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = result.get("info", {})
            finding = {
                "target_url": target_url,
                "template_id": result.get("template-id", result.get("templateID", "")),
                "severity": info.get("severity", "info").lower(),
                "matched_at": result.get("matched-at", result.get("matched", "")),
                "evidence": _extract_evidence(result),
            }
            if conn is not None:
                conn.conn.execute("""INSERT INTO dast_findings (target_url, template_id, severity, matched_at, evidence) VALUES (?, ?, ?, ?, ?)""",
                    (finding["target_url"], finding["template_id"], finding["severity"], finding["matched_at"], finding["evidence"]))
            findings.append(finding)
    if conn is not None:
        conn.conn.commit()
    return findings

def _extract_evidence(result: dict) -> str:
    extracted = result.get("extracted-results", [])
    if extracted: return str(extracted[0])[:200]
    ms = result.get("matcher-status", "")
    return str(ms)[:200] if ms else ""

def scan_target(target_url: str, severity_filter: List[str] = None) -> dict:
    conn = _get_db()
    templates_dir = _export_templates_from_db(conn)
    cmd = ["nuclei", "-t", templates_dir, "-u", target_url, "-jsonl", "-silent", "-timeout", "10"]
    if severity_filter:
        cmd.extend(["-severity", ",".join(severity_filter)])
    tmp = tempfile.NamedTemporaryFile(mode="w+", suffix=".jsonl", delete=False)
    output_path = tmp.name
    cmd.extend(["-o", output_path])
    tmp.close()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"nuclei error (exit {proc.returncode}): {proc.stderr[:300]}")
    except subprocess.TimeoutExpired:
        Path(output_path).unlink(missing_ok=True); raise RuntimeError("nuclei scan timed out (600s)")
    except FileNotFoundError:
        Path(output_path).unlink(missing_ok=True); raise RuntimeError("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    findings = _parse_nuclei_output(output_path, target_url, conn)
    Path(output_path).unlink(missing_ok=True)
    conn.close()
    return {"target": target_url, "findings_count": len(findings), "findings": findings}

def aggregate_report(sast_report: dict, dast_results: dict) -> dict:
    from gsc_correlation import correlate_sast_dast

    sf = sast_report.get("findings", [])
    df = dast_results.get("findings", [])

    # Solar appScreener-style: коррелируем SAST↔DAST, подтверждаем совпадения.
    corr = correlate_sast_dast(sf, df)
    enriched = corr["findings"]
    csum = corr["summary"]

    sc = {}
    for f in sf + df:
        s = f.get("severity", f.get("category", "unknown")).upper()
        sc[s] = sc.get(s, 0) + 1

    confirmed = [f for f in enriched
                 if f.get("metadata", {}).get("correlated_dast")]

    return {
        "summary": {
            "sast_total": len(sf),
            "dast_total": len(df),
            "total": len(sf) + len(df),
            "by_severity": sc,
            "confirmed_by_dast": csum["confirmed_by_dast"],
        },
        "correlation": csum["matched_pairs"],
        "sast_findings": [
            {"rule_id": f.get("rule_id", ""), "file": f.get("file_path", ""),
             "severity": f.get("category", ""), "title": f.get("title", ""),
             "review_status": f.get("review_status", ""),
             "correlated_dast": f.get("metadata", {}).get("correlated_dast", False),
             "dast_evidence": f.get("metadata", {}).get("dast_evidence", "")}
            for f in enriched[:50]
        ],
        "confirmed_findings": [
            {"rule_id": f.get("rule_id", ""), "file": f.get("file_path", ""),
             "title": f.get("title", ""),
             "dast_template_id": f.get("metadata", {}).get("dast_template_id", ""),
             "dast_evidence": f.get("metadata", {}).get("dast_evidence", "")}
            for f in confirmed
        ],
        "dast_findings": df[:10],
    }

def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC DAST Scanner")
    p.add_argument("target", help="Target URL")
    p.add_argument("--severity", nargs="+", choices=["info","low","medium","high","critical"])
    p.add_argument("--output", "-o")
    args = p.parse_args()
    try:
        results = scan_target(args.target, args.severity)
    except RuntimeError as e:
        print(f"❌ {e}"); sys.exit(1)
    print(f"✅ Scanned {args.target}\n   Findings: {results['findings_count']}")
    for f in results["findings"][:10]:
        print(f"   [{f['severity'].upper():>8}] {f['template_id']}")
    if results["findings_count"] > 10: print(f"   ... and {results['findings_count']-10} more")
    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
