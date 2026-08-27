#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Self-Healing CI v0.27 (revised code review 2026-08-06).

Auto-PR with verified fixes for CRITICAL/HIGH findings.

Fixed:
  H5  3-level loop guard: per-finding limit, gsc-autofix origin skip, per-file limit
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent))

# H5: loop guard constants
AUTOFIX_LABEL = "gsc-autofix"
MAX_AUTOFIX_PER_FINDING = 1      # one auto-PR per finding ever
MAX_AUTOFIX_PER_FILE = 2         # max two auto-fixes per file
ELIGIBLE_RULES = {"GS001", "GS004", "GS005", "GS017", "GS020", "GS021"}


def _eligible_for_autofix(finding: dict) -> bool:
    """Check if a finding qualifies for auto-fix with loop guard."""
    sev = finding.get("category", "").upper()
    conf = finding.get("confidence", 0)
    rule = finding.get("rule_id", "")

    if sev not in ("CRITICAL", "HIGH"):
        return False
    if conf < 0.80:
        return False
    if rule not in ELIGIBLE_RULES:
        return False

    # Verdict fp/fixed → don't auto-fix
    verdict = finding.get("revalidation_verdict", "")
    if verdict in ("fp", "fixed", "false-positive"):
        return False

    # H5: loop guard — findings from auto-fix PRs must not be auto-fixed again
    if finding.get("source") == AUTOFIX_LABEL:
        return False

    # H5: check autofixed marker in DB
    if finding.get("autofixed"):
        return False

    return True


def _finding_key(finding: dict) -> str:
    import hashlib
    raw = f"{finding.get('rule_id','')}+{finding.get('file_path','')}+{finding.get('detail','')[:80]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def autofix(report_path: str, project_root: str = ".",
            max_fixes: int = 3, dry_run: bool = True) -> List[dict]:
    """Auto-fix eligible findings with loop guard."""
    with open(report_path) as f:
        data = json.load(f)
    findings = data.get("findings", [])

    eligible = [f_ for f_ in findings if _eligible_for_autofix(f_)]
    if not eligible:
        print("[Self-Heal] No eligible findings.")
        return []

    print(f"[Self-Heal] {len(eligible)} eligible, max {max_fixes}")

    from gsc_proofoffix import generate_fix

    results = []
    fixes_dir = Path(project_root) / ".gsc-fixes"
    fixes_dir.mkdir(exist_ok=True)

    # H5: track per-file fix count
    file_fix_count: Dict[str, int] = {}

    fixed_count = 0
    for f_ in eligible[:max_fixes]:
        file_path = f_.get("file_path", "")
        key = _finding_key(f_)

        # Taint-gate (NO_UNTRUSTED_INFLUENCE): findings originate in the scanned (untrusted)
        # repo. Mark tainted so side-effecting steps (git push / PR) are gated on an explicit
        # human flag (--create-pr, i.e. dry_run=False) rather than auto-approved.
        try:
            from gsc_core.gsc_taint import mark_tainted, tainted
            f_ = mark_tainted(f_)  # returns a copy; downstream reads report_path, not f_
            f_tainted = tainted(f_)
        except Exception:
            f_tainted = True

        # H5: per-file limit
        if file_fix_count.get(file_path, 0) >= MAX_AUTOFIX_PER_FILE:
            print(f"  ⏭️ {key} — file {file_path} already at max fixes ({MAX_AUTOFIX_PER_FILE})")
            results.append({"finding_key": key, "fixed": False, "reason": "per-file limit"})
            continue

        print(f"\n[Self-Heal] Processing {key} — {f_.get('rule_id')} {f_.get('category')}")
        f_["source"] = AUTOFIX_LABEL  # mark for loop guard

        try:
            evidence = generate_fix(key, report_path, project_root)
            result = {
                "finding_key": key,
                "rule_id": evidence.rule_id,
                "file_path": evidence.file_path,
                "fixed": evidence.verified,
                "level": evidence.level,
                "patch_file": "",
                "error": evidence.error,
                "tainted": f_tainted,  # untrusted-repo origin (taint-gate)
            }

            if evidence.verified:
                patch_file = fixes_dir / f"{key}.diff"
                patch_file.write_text(evidence.patch_display)

                # Save evidence
                ev_file = fixes_dir / f"{key}.evidence.json"
                ev_file.write_text(json.dumps(evidence.to_dict(), indent=2, ensure_ascii=False))

                result["patch_file"] = str(patch_file)
                file_fix_count[file_path] = file_fix_count.get(file_path, 0) + 1
                fixed_count += 1
                print(f"  ✅ Verified — {evidence.level}")
            else:
                print(f"  ❌ {evidence.level}: {evidence.error}")

            results.append(result)
        except Exception as e:
            results.append({"finding_key": key, "fixed": False, "error": str(e)})
            print(f"  ❌ {e}")

    # Create PR
    if fixed_count > 0 and not dry_run:
        _create_autofix_pr(results, fixes_dir, project_root)

    return results


def _create_autofix_pr(results: List[dict], fixes_dir: Path, project_root: str) -> str:
    from gsc_signature import badge_markdown, label_name, pr_signature, sign_commit_message

    branch = f"gsc-autofix-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    root = Path(project_root)

    fixed = [r for r in results if r.get("fixed")]
    badge = badge_markdown()
    body_lines = [
        "## 🛡️ GSC Self-Healing CI: Auto-Fix",
        "",
    ]
    if badge:
        body_lines += [badge, ""]
    body_lines += [
        f"**{len(fixed)} verified fixes** applied automatically.",
        "",
        "| # | Rule | Key | File | Level |",
        "|---|------|-----|------|-------|",
    ]
    # Taint-gate (NO_UNTRUSTED_INFLUENCE): auto-fixed findings are tainted (untrusted repo
    # origin); we reached here only under an explicit --create-pr human flag. Record it.
    if any(r.get("tainted") for r in fixed):
        body_lines += [
            "",
            "> ⚠️ **Taint note:** fixes auto-applied to findings from an untrusted (scanned) "
            "repository, under an explicit `--create-pr` human flag.",
        ]
    for i, r in enumerate(fixed):
        body_lines.append(
            f"| {i+1} | {r['rule_id']} | `{r['finding_key']}` | `{r['file_path']}` | {r.get('level','?')} |"
        )
    body_lines += [
        "",
        "> This PR was created automatically by GSC Self-Healing CI.",
        "> Label `gsc-autofix` prevents re-processing of the same findings.",
    ]
    body = "\n".join(body_lines) + pr_signature(verified=True)

    # Taint-gate (NO_UNTRUSTED_INFLUENCE): the side-effecting push/PR below is reached only
    # under an explicit --create-pr human flag. require_untainted() is False for tainted
    # findings; they must never drive a push without that flag (they don't — dry_run defaults
    # to True and skips this function entirely). Call it for the audit trail.
    try:
        from gsc_core.gsc_taint import require_untainted
        if any(not require_untainted(r) for r in fixed):
            print("[Self-Heal] taint-gate: tainted findings — proceeding under explicit --create-pr flag")
    except Exception:
        pass

    # Try gh CLI
    gh_available = subprocess.run(["which", "gh"], capture_output=True).returncode == 0
    if not gh_available:
        print(f"\n[Self-Heal] Manual PR: gh pr create --label {AUTOFIX_LABEL}")
        return "manual"

    subprocess.run(["git", "-C", str(root), "checkout", "-b", branch], capture_output=True)
    subprocess.run(["git", "-C", str(root), "add", str(fixes_dir)], capture_output=True)
    commit_msg = sign_commit_message(f"gsc-autofix: {len(fixed)} verified fixes [skip ci]")
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", commit_msg],
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(root), "push", "origin", branch], capture_output=True)

    labels = [AUTOFIX_LABEL]
    verified_label = label_name()
    if verified_label:
        labels.append(verified_label)
    label_args = []
    for lbl in labels:
        label_args += ["--label", lbl]

    r = subprocess.run(
        ["gh", "pr", "create", "--title", f"🛡️ gsc-autofix: {len(fixed)} verified fixes",
         "--body", body, *label_args, "--base", "main", "--head", branch],
        capture_output=True, text=True, cwd=str(root),
    )
    pr_url = r.stdout.strip() if r.returncode == 0 else ""
    if pr_url:
        print(f"\n[Self-Heal] PR: {pr_url}")
    return pr_url


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Self-Healing CI v0.27")
    p.add_argument("report", help="Scan report JSON")
    p.add_argument("--project-root", default=".")
    p.add_argument("--max-fixes", type=int, default=3)
    p.add_argument("--dry-run", action="store_true", default=True)
    p.add_argument("--create-pr", dest="dry_run", action="store_false")
    p.add_argument("--output", "-o")
    args = p.parse_args()

    results = autofix(args.report, args.project_root, args.max_fixes, args.dry_run)
    fixed = sum(1 for r in results if r.get("fixed"))
    print(f"\n{'='*50}")
    print(f"Self-Healing: {fixed}/{len(results)} verified")
    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
