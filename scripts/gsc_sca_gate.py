#!/usr/bin/env python3
"""SCA gate — fail CI on reachable MEDIUM+ CVEs in GSC's OWN dependencies.

Usage:
    python3 scripts/gsc_sca_gate.py [--repo .] [--fail-severity MEDIUM]

Exit 0 = clean (no reachable findings at/above the threshold).
Exit 1 = reachable findings at/above threshold (block merge).

Reachability (Ф5) already downgrades not_reachable findings, so "reachable"
here means genuinely imported/called vulnerable code paths — not fixture noise
(benchmark/calibration/build dirs are skipped by parse_repo_manifests).
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def main() -> int:
    ap = argparse.ArgumentParser(description="GSC SCA merge-gate")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--fail-severity", default="MEDIUM",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    args = ap.parse_args()

    from gsc_sca import parse_repo_manifests, query_osv, sca_findings
    from gsc_reachability import collect_python_usage

    packages = parse_repo_manifests(args.repo)
    if not packages:
        print("No dependency manifests found — nothing to gate.")
        return 0

    usage = collect_python_usage(args.repo)
    results = query_osv(packages)
    findings = sca_findings(packages, results, usage=usage)

    threshold = _SEV_RANK[args.fail_severity]
    blocking = [f for f in findings
                if f.get("metadata", {}).get("reachability") == "reachable"
                and _SEV_RANK.get(f["severity"], 0) >= threshold]

    print(f"📦 {len(packages)} packages | {len(findings)} CVEs | "
          f"{len(blocking)} reachable >= {args.fail_severity}")

    if blocking:
        print(f"\n❌ Blocking reachable findings (>= {args.fail_severity}):")
        for f in blocking:
            sca = f["metadata"]["sca"]
            print(f"  {f['severity']:<8} {sca['package']}@{sca['current_version']} "
                  f"→ {sca['fixed_version'] or '?'}  {sca['vuln_id']}")
        return 1

    print("✅ No reachable findings at/above threshold — pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
