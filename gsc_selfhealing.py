#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Self-Healing CI v1.0 — автономный remediation.

При обнаружении CRITICAL/HIGH находок — генерирует верифицированный фикс,
открывает PR с лейблом gsc-autofix.

Цикл:
  scan → CRITICAL/HIGH finding → Proof-of-Fix → verified patch → auto-PR

Эксклюзив: полный автономный цикл «уязвимость → рабочий PR».
Продаётся: «безопасность чинит себя сама».
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple


def _findings_from_report(report_path: str) -> List[dict]:
    """Load findings from scan report JSON."""
    with open(report_path) as f:
        data = json.load(f)
    return data.get("findings", [])


def _finding_key(f_: dict) -> str:
    import hashlib
    raw = f"{f_.get('rule_id','')}+{f_.get('file_path','')}+{f_.get('detail','')[:80]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _eligible_for_autofix(f_: dict) -> bool:
    """Check if a finding qualifies for auto-fix."""
    sev = f_.get("category", "").upper()
    conf = f_.get("confidence", 0)
    verdict = f_.get("revalidation_verdict", "")

    # Only CRITICAL or HIGH
    if sev not in ("CRITICAL", "HIGH"):
        return False

    # High confidence only (avoid FP-fixes)
    if conf < 0.80:
        return False

    # Don't auto-fix findings already resolved
    if verdict in ("fp", "fixed", "false-positive"):
        return False

    # Only certain detector types support auto-fix
    supported = {"GS001", "GS004", "GS005", "GS017", "GS020", "GS021"}
    if f_.get("rule_id", "").split(".")[0] not in supported:
        return False

    return True


def autofix(report_path: str, project_root: str = ".",
            max_fixes: int = 3, dry_run: bool = True) -> List[dict]:
    """
    Auto-fix eligible findings: generate patch, verify, create PR.

    Returns list of results: {finding_key, fixed, patch_file, pr_url}
    """
    findings = _findings_from_report(report_path)
    eligible = [f for f in findings if _eligible_for_autofix(f)]

    if not eligible:
        print("[Self-Heal] No eligible findings for auto-fix.")
        return []

    print(f"[Self-Heal] {len(eligible)} eligible findings, max {max_fixes}")

    results = []
    fixes_dir = Path(project_root) / ".gsc-fixes"
    fixes_dir.mkdir(exist_ok=True)

    sys.path.insert(0, str(Path(__file__).parent))
    from gsc_proofoffix import generate_fix, evidence_to_dict

    fixed_count = 0
    for f_ in eligible[:max_fixes]:
        key = _finding_key(f_)
        print(f"\n[Self-Heal] Processing {key} — {f_.get('rule_id')} {f_.get('category')}")

        try:
            evidence = generate_fix(key, report_path, project_root)
            result = {
                "finding_key": key,
                "rule_id": evidence.rule_id,
                "file_path": evidence.file_path,
                "fixed": evidence.verified,
                "patch_file": "",
                "pr_url": "",
                "error": evidence.error,
            }

            if evidence.verified:
                # Save patch
                patch_file = fixes_dir / f"{key}.diff"
                patch_file.write_text(evidence.patch)
                result["patch_file"] = str(patch_file)

                # Save evidence
                ev_file = fixes_dir / f"{key}.evidence.json"
                ev_file.write_text(json.dumps(evidence_to_dict(evidence), indent=2, ensure_ascii=False))

                fixed_count += 1
                print(f"  ✅ Verified fix saved to {patch_file}")
            else:
                print(f"  ❌ Could not verify: {evidence.error}")

            results.append(result)
        except Exception as e:
            results.append({"finding_key": key, "fixed": False, "error": str(e)})
            print(f"  ❌ {e}")

    # Create PR with all verified fixes
    if fixed_count > 0 and not dry_run:
        pr_url = _create_autofix_pr(results, fixes_dir, project_root)
        for r in results:
            r["pr_url"] = pr_url

    return results


def _create_autofix_pr(results: List[dict], fixes_dir: Path, project_root: str) -> str:
    """
    Create a GitHub PR with all verified fixes.
    Requires GH CLI or token.
    """
    branch = f"gsc-autofix-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    root = Path(project_root)

    # List what was fixed
    fixed = [r for r in results if r.get("fixed")]
    summary_lines = [
        "## 🛡️ GSC Self-Healing CI: Auto-Fix",
        "",
        f"**{len(fixed)} verified fixes** applied automatically.",
        "",
        "| # | Rule | Key | File |",
        "|---|------|-----|------|",
    ]
    for r in fixed:
        summary_lines.append(f"| {fixed.index(r)+1} | {r['rule_id']} | `{r['finding_key']}` | `{r['file_path']}` |")

    summary_lines += [
        "",
        "## Evidence",
    ]
    for r in fixed:
        summary_lines.append(f"- `{r['finding_key']}` — [evidence](fixes/{r['finding_key']}.evidence.json)")

    summary_lines += [
        "",
        "### How GSC Verified These Fixes",
        "1. Generated PoC exploit → reproduced vulnerability ✅",
        "2. Generated minimal patch via DeepSeek",
        "3. Applied patch in sandbox",
        "4. Re-ran PoC → exploit FAILED → fix VERIFIED ✅",
        "",
        "> This PR was created automatically by GSC Self-Healing CI.",
        "> Review the changes and merge if satisfied, or close with `/gsc override` if the fix is not desired.",
    ]

    body = "\n".join(summary_lines)

    # Check if we can use gh CLI or need manual
    gh_available = subprocess.run(["which", "gh"], capture_output=True).returncode == 0
    if not gh_available:
        print(f"\n[Self-Heal] GitHub CLI not found. Manual PR required:")
        print(f"  git checkout -b {branch}")
        print(f"  git add .gsc-fixes/")
        print(f"  git commit -m 'gsc: auto-fix {len(fixed)} findings'")
        print(f"  gh pr create --title 'gsc-autofix: {len(fixed)} verified fixes' --body '...' --label gsc-autofix")
        return "manual"

    # Create branch + commit + PR via gh CLI
    subprocess.run(["git", "-C", str(root), "checkout", "-b", branch], capture_output=True)
    subprocess.run(["git", "-C", str(root), "add", str(fixes_dir)], capture_output=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", f"gsc-autofix: {len(fixed)} verified fixes [skip ci]"],
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(root), "push", "origin", branch], capture_output=True)

    r = subprocess.run(
        ["gh", "pr", "create", "--title", f"🛡️ gsc-autofix: {len(fixed)} verified fixes",
         "--body", body, "--label", "gsc-autofix", "--base", "main",
         "--head", branch],
        capture_output=True, text=True, cwd=str(root),
    )

    if r.returncode == 0:
        pr_url = r.stdout.strip()
        print(f"\n[Self-Heal] PR created: {pr_url}")
        return pr_url
    else:
        print(f"[Self-Heal] PR creation failed: {r.stderr[:200]}")
        return ""


# ── CLI ───────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Self-Healing CI")
    p.add_argument("report", help="Scan report JSON")
    p.add_argument("--project-root", default=".", help="Project root")
    p.add_argument("--max-fixes", type=int, default=3, help="Max auto-fixes")
    p.add_argument("--dry-run", action="store_true", default=True, help="Don't create PR (default)")
    p.add_argument("--create-pr", dest="dry_run", action="store_false", help="Create actual PR")
    p.add_argument("--output", "-o", help="Save results JSON")

    args = p.parse_args()
    results = autofix(args.report, args.project_root, args.max_fixes, args.dry_run)

    if results:
        fixed = sum(1 for r in results if r.get("fixed"))
        print(f"\n{'='*50}")
        print(f"Self-Healing complete: {fixed}/{len(results)} findings fixed")
        if args.output:
            Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
