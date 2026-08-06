"""Air-gap экспорт: findings на диск без облака."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def export_findings(report: dict, output_dir: str,
                    fmt: str = "json") -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        path = out / f"gsc_findings_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    elif fmt == "sarif":
        sarif = _to_sarif(report)
        path = out / f"gsc_findings_{ts}.sarif.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)
    else:
        raise ValueError(f"unknown format: {fmt}")
    return str(path)


def export_all_from_cache(cache, output_dir: str, fmt: str = "json"):
    paths = []
    for repo_name in cache.get_unsynced():
        report = cache.load(repo_name)
        if report:
            paths.append(export_findings(report, output_dir, fmt))
    return paths


def _to_sarif(report: dict) -> dict:
    """Минимальная SARIF-конвертация."""
    results = []
    for f in report.get("findings", []):
        results.append({
            "ruleId": f.get("rule_id", "GSC"),
            "message": {"text": f.get("snippet", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("file", "")},
                "region": {"startLine": f.get("line", 1)},
            }}],
            "level": _severity_to_sarif(f.get("severity", "LOW")),
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "GSC Enterprise Agent"}},
            "results": results,
        }],
    }


def _severity_to_sarif(sev: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note"}.get(sev, "note")