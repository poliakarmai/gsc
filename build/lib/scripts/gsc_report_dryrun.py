#!/usr/bin/env python3
"""Send dry-run metrics to GSC REST API. Best-effort: failures don't break CI."""
import json, os, sys, urllib.request


def main(path):
    api_url = os.environ.get("GSC_API_URL")
    api_key = os.environ.get("GSC_API_KEY")
    if not api_url or not api_key:
        print("Metrics skipped: GSC_API_URL/GSC_API_KEY not set", file=sys.stderr)
        return 0
    report = json.load(open(path, encoding="utf-8"))
    dr = report.get("dry_run", {})
    payload = {
        "target": report.get("target"),
        "profile": report.get("profile"),
        "findings_total": len(report.get("findings", [])),
        "blocking_count": dr.get("blocking_count", 0),
        "would_block": int(dr.get("would_block", False)),
        "llm_used": int(report.get("features", {}).get("chains", False)),
        "duration_sec": report.get("duration_sec"),
    }
    try:
        req = urllib.request.Request(
            f"{api_url.rstrip('/')}/api/v1/dryrun",
            data=json.dumps(payload).encode(),
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Metrics send failed (non-fatal): {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    main(sys.argv[1])
