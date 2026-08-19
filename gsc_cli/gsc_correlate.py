# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC correlate — SAST↔DAST correlation (Solar appScreener-style).

Сопоставляет статические находки (SAST) с динамическими (DAST/nuclei) и
подтверждает совпадения: `review_status='confirmed'` + рантайм-evidence.

Usage:
  gsc.py correlate <sast_report.json> <dast_report.json> [--output out.json]
  gsc.py correlate <sast_report.json> <dast_report.json> --json

Оба файла — JSON с ключом `findings` (или сам список находок).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _load_findings(path: str) -> list[dict]:
    """Прочитать JSON и вернуть список находок (терпим к `{findings: [...]}`)."""
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if isinstance(data, dict):
        if "findings" in data:
            return data["findings"]
        return data
    if isinstance(data, list):
        return data
    raise ValueError(f"unsupported report shape in {path}")


def build_report(sast_findings: list[dict], dast_findings: list[dict]) -> dict:
    """Унифицированный отчёт: SAST + корреляция + отдельные подтверждённые."""
    from gsc_correlation import correlate_sast_dast

    corr = correlate_sast_dast(sast_findings, dast_findings)
    enriched = corr["findings"]
    csum = corr["summary"]

    by_sev = {}
    for f in sast_findings + dast_findings:
        s = str(f.get("severity", f.get("category", "unknown"))).upper()
        by_sev[s] = by_sev.get(s, 0) + 1

    confirmed = [f for f in enriched if f.get("metadata", {}).get("correlated_dast")]

    return {
        "summary": {
            "sast_total": len(sast_findings),
            "dast_total": len(dast_findings),
            "total": len(sast_findings) + len(dast_findings),
            "by_severity": by_sev,
            "confirmed_by_dast": csum["confirmed_by_dast"],
        },
        "correlation": csum["matched_pairs"],
        "confirmed_findings": [
            {
                "rule_id": f.get("rule_id", ""),
                "file": f.get("file_path", ""),
                "title": f.get("title", ""),
                "review_status": f.get("review_status", ""),
                "dast_template_id": f.get("metadata", {}).get("dast_template_id", ""),
                "dast_evidence": f.get("metadata", {}).get("dast_evidence", ""),
            }
            for f in confirmed
        ],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="gsc correlate",
        description="SAST↔DAST correlation (Solar appScreener-style)")
    p.add_argument("sast_report", help="SAST scan report JSON (key 'findings')")
    p.add_argument("dast_report", help="DAST results JSON (key 'findings')")
    p.add_argument("--output", "-o", help="Save unified report JSON")
    p.add_argument("--json", action="store_true", help="Print full JSON to stdout")
    args = p.parse_args(argv)

    try:
        sast = _load_findings(args.sast_report)
        dast = _load_findings(args.dast_report)
    except Exception as e:
        print(f"❌ Cannot read report: {e}", file=sys.stderr)
        return 1

    report = build_report(sast, dast)
    s = report["summary"]

    if args.json or args.output:
        payload = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
            print(f"✅ Wrote {args.output}")
        if args.json:
            print(payload)

    if not args.json and not args.output:
        print("🧩 SAST↔DAST Correlation")
        print(f"   SAST: {s['sast_total']} | DAST: {s['dast_total']}")
        print(f"   ✅ Confirmed by DAST: {s['confirmed_by_dast']}")
        for f in report["confirmed_findings"]:
            ev = (f["dast_evidence"] or "")[:60]
            print(f"   - [{f['rule_id']}] {f['file']} ← {f['dast_template_id']}"
                  + (f": {ev}" if ev else ""))

    return 0


if __name__ == "__main__":
    sys.exit(main())
