#!/usr/bin/env python3
"""Render dry-run summary for $GITHUB_STEP_SUMMARY. Counters only — no snippets."""
import json, sys


def main(path: str) -> None:
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    findings = report.get("findings", [])
    by_sev: dict = {}
    for f in findings:
        sev = f.get("severity", "?")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    dr = report.get("dry_run", {})
    features = report.get("features", {})
    active = [k for k, v in features.items() if v]

    lines = [
        "## 🛡️ GSC Dry-Run (Phase 1)",
        f"Findings: **{len(findings)}** "
        f"(CRITICAL: {by_sev.get('CRITICAL', 0)}, "
        f"HIGH: {by_sev.get('HIGH', 0)}, "
        f"MEDIUM: {by_sev.get('MEDIUM', 0)}, "
        f"LOW: {by_sev.get('LOW', 0)})",
    ]
    if dr.get("would_block"):
        lines.append(
            f"⚠️ Would block: **{dr['blocking_count']}** finding(s)")
    else:
        lines.append("✅ Would not block")
    lines.append(f"Mode: {', '.join(active) if active else 'regex-only'}")
    print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1])
