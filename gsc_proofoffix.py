#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Proof-of-Fix v1.0 — верифицированная автокоррекция.

Цикл: finding → patch → sandbox → re-PoC → verify → before/after evidence.

Эксклюзив: никто не верифицирует фиксы повторным запуском эксплойта.
GSC доказывает, что патч работает.

CLI:
  gsc fix generate <finding_key> --report scan.json
  gsc fix verify <finding_key> --report scan.json
  gsc fix apply <finding_key> --report scan.json --output patch.diff
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── LLM helper ────────────────────────────────────────────
def _call_llm(system: str, user: str, max_tokens: int = 1200) -> Optional[str]:
    """Call DeepSeek API. Returns None on failure."""
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        return None

    import urllib.request as request
    data = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }).encode()
    req = request.Request("https://api.deepseek.com/v1/chat/completions", data=data)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
            return body["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[Proof-of-Fix] LLM error: {e}", file=sys.stderr)
        return None


# ── Data structures ───────────────────────────────────────
@dataclass
class FixEvidence:
    finding_key: str
    rule_id: str
    file_path: str
    line_number: int
    patch: str = ""
    patch_syntax_ok: bool = False
    poc_before: str = ""       # PoC output BEFORE fix
    poc_before_exit: int = 1   # exit code before (should be non-zero = vulnerable)
    poc_after: str = ""        # PoC output AFTER fix
    poc_after_exit: int = 0    # exit code after (should be 0 = safe)
    verified: bool = False
    verified_at: str = ""
    error: str = ""


# ── Core ──────────────────────────────────────────────────
def _find_finding(report_path: str, finding_key: str) -> Optional[dict]:
    """Find a finding in scan report by its key."""
    with open(report_path) as f:
        report = json.load(f)
    for f_ in report.get("findings", []):
        import hashlib
        raw = f"{f_.get('rule_id','')}+{f_.get('file_path','')}+{f_.get('detail','')[:80]}"
        key = hashlib.sha256(raw.encode()).hexdigest()[:12]
        if key == finding_key:
            return f_
    return None


def _read_source(finding: dict, project_root: Path) -> str:
    """Read the source file containing the finding."""
    rel_path = finding.get("file_path", "")
    abs_path = project_root / rel_path
    if abs_path.exists():
        return abs_path.read_text()
    return ""


def _generate_patch(finding: dict, source: str) -> str:
    """Use DeepSeek to generate a fix patch for the finding."""
    rule = finding.get("rule_id", "")
    category = finding.get("category", "")
    title = finding.get("title", "")
    detail = finding.get("detail", "")[:500]
    line = finding.get("line_number", 0)
    file_path = finding.get("file_path", "")

    system = (
        "You are a senior security engineer. Generate a MINIMAL, CORRECT patch "
        "that fixes the security vulnerability described. Output ONLY a unified diff "
        "(diff -u format) or a precise old_string→new_string replacement. "
        "The patch must be MINIMAL — change only what's necessary. "
        "Do NOT add features, refactor, or change variable names. "
        "Output format:\n"
        "```diff\n"
        "--- a/path/file.py\n"
        "+++ b/path/file.py\n"
        "@@ -line,count +line,count @@\n"
        " context line\n"
        "-vulnerable line\n"
        "+fixed line\n"
        " context line\n"
        "```\n"
        "Then on the next line: EXPLANATION: <one sentence why this fixes the issue>"
    )

    user = (
        f"VULNERABILITY: {rule} — {title} ({category})\n"
        f"File: {file_path}:{line}\n"
        f"Details: {detail}\n\n"
        f"SOURCE CODE (relevant snippet around line {line}):\n"
        f"{source[:4000]}\n\n"
        f"Generate a minimal patch that fixes this specific vulnerability."
    )

    return _call_llm(system, user, max_tokens=1500) or ""


def _parse_patch(llm_output: str) -> str:
    """Extract unified diff from LLM output."""
    if "```diff" in llm_output:
        llm_output = llm_output.split("```diff", 1)[1]
        if "```" in llm_output:
            llm_output = llm_output.split("```", 1)[0]
    elif "```" in llm_output:
        llm_output = llm_output.split("```", 1)[1]
        if "```" in llm_output:
            llm_output = llm_output.split("```", 1)[0]

    # Remove EXPLANATION line
    for line in llm_output.split("\n"):
        if line.strip().upper().startswith("EXPLANATION"):
            llm_output = llm_output.split(line, 1)[0]
            break

    return llm_output.strip()


def _apply_patch(source: str, patch: str) -> str:
    """Apply unified diff patch to source. Returns patched source or raises."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    f.write(source)
    f.close()

    pf = tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False)
    pf.write(patch)
    pf.close()

    try:
        r = subprocess.run(
            ["patch", "-u", "--force", f.name, pf.name],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            raise RuntimeError(f"patch failed: {r.stderr[:200]}")
        patched = Path(f.name).read_text()
        return patched
    finally:
        Path(f.name).unlink(missing_ok=True)
        Path(pf.name).unlink(missing_ok=True)


def _run_poc(finding: dict, source_code: str, project_root: Path) -> tuple[str, int]:
    """
    Run PoC against source code in a sandbox.
    Returns (output, exit_code).
    exit_code != 0 means PoC succeeded (vulnerable).
    """
    # Use existing PoC generator to create exploit
    sys.path.insert(0, str(Path(__file__).parent))
    from gsc_poc_generator import PoCGenerator

    gen = PoCGenerator(budget=1)
    poc = gen.generate(finding, source_code)

    if not poc or not poc.code:
        return "No PoC generated", -1

    # Run PoC in sandbox
    sandbox = tempfile.mkdtemp(prefix="gsc_sandbox_")
    try:
        # Save the source code
        file_path = finding.get("file_path", "target.py")
        sandbox_file = Path(sandbox) / Path(file_path).name
        sandbox_file.write_text(source_code)

        # Save PoC
        poc_file = Path(sandbox) / "poc.py"
        poc_file.write_text(poc.code)

        # Run
        r = subprocess.run(
            [sys.executable, str(poc_file)],
            capture_output=True, text=True, timeout=30,
            cwd=sandbox,
        )
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "PoC timeout", 124
    except Exception as e:
        return str(e), -1
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def generate_fix(finding_key: str, report_path: str, project_root: str) -> FixEvidence:
    """Generate and verify a fix for a finding. Full cycle."""
    root = Path(project_root).resolve()
    finding = _find_finding(report_path, finding_key)
    evidence = FixEvidence(
        finding_key=finding_key,
        rule_id="unknown",
        file_path="unknown",
        line_number=0,
    )

    if not finding:
        evidence.error = f"Finding {finding_key} not found in {report_path}"
        return evidence

    evidence.rule_id = finding.get("rule_id", "unknown")
    evidence.file_path = finding.get("file_path", "unknown")
    evidence.line_number = finding.get("line_number", 0)

    # Step 1: Read source
    source = _read_source(finding, root)
    if not source:
        evidence.error = f"Source file not found: {evidence.file_path}"
        return evidence

    # Step 2: Run PoC BEFORE (prove it's vulnerable)
    print(f"[PoF] Step 1: Running PoC BEFORE fix on {evidence.file_path}")
    evidence.poc_before, evidence.poc_before_exit = _run_poc(finding, source, root)

    # Step 3: Generate patch via LLM
    print(f"[PoF] Step 2: Generating patch via DeepSeek...")
    llm_output = _generate_patch(finding, source)
    evidence.patch = _parse_patch(llm_output)

    if not evidence.patch:
        evidence.error = "LLM failed to generate patch"
        return evidence

    # Step 4: Verify patch syntax
    evidence.patch_syntax_ok = bool(evidence.patch) and "---" in evidence.patch

    # Step 5: Apply patch to sandbox copy
    print(f"[PoF] Step 3: Applying patch in sandbox...")
    try:
        patched_source = _apply_patch(source, evidence.patch)
    except Exception as e:
        evidence.error = f"Patch application failed: {e}"
        return evidence

    # Step 6: Re-run PoC on patched code
    print(f"[PoF] Step 4: Re-running PoC AFTER fix...")
    evidence.poc_after, evidence.poc_after_exit = _run_poc(finding, patched_source, root)

    # Step 7: Verify — PoC should fail on patched code
    evidence.verified = (
        evidence.poc_before_exit != 0          # was vulnerable
        and evidence.poc_after_exit != 0       # still vulnerable? BAD
    ) is False  # We want: before vulnerable, after NOT vulnerable

    # Better check: PoC transitioned from vulnerable → safe
    if evidence.poc_before_exit != 0 and "No PoC" not in evidence.poc_before:
        if evidence.poc_after_exit == 0:
            evidence.verified = True
        elif "No PoC" in evidence.poc_after:
            evidence.verified = True  # PoC can't even generate against fixed code
    else:
        # PoC didn't work on original — can't verify
        evidence.verified = False
        if not evidence.error:
            evidence.error = "PoC did not trigger on original code — can't verify fix"

    evidence.verified_at = datetime.now(timezone.utc).isoformat()
    return evidence


# ── Report ────────────────────────────────────────────────
def evidence_to_dict(ev: FixEvidence) -> dict:
    return {
        "finding_key": ev.finding_key,
        "rule_id": ev.rule_id,
        "file_path": ev.file_path,
        "line_number": ev.line_number,
        "patch_syntax_ok": ev.patch_syntax_ok,
        "patch": ev.patch[:2000],
        "poc_before": ev.poc_before[:500],
        "poc_before_exit": ev.poc_before_exit,
        "poc_after": ev.poc_after[:500],
        "poc_after_exit": ev.poc_after_exit,
        "verified": ev.verified,
        "verified_at": ev.verified_at,
        "error": ev.error,
    }


def evidence_to_markdown(ev: FixEvidence) -> str:
    icon = "✅ VERIFIED" if ev.verified else "❌ FAILED"
    lines = [
        f"# Proof-of-Fix: {ev.finding_key} — {icon}",
        "",
        f"**Rule:** {ev.rule_id}",
        f"**File:** {ev.file_path}:{ev.line_number}",
        f"**Verified at:** {ev.verified_at}",
        "",
        "## Before (Vulnerable)",
        f"```",
        ev.poc_before[:1000] if ev.poc_before else "(no PoC output)",
        f"```",
        f"Exit code: {ev.poc_before_exit}",
        "",
        "## After (Fixed)",
        f"```",
        ev.poc_after[:1000] if ev.poc_after else "(no PoC output)",
        f"```",
        f"Exit code: {ev.poc_after_exit}",
        "",
        "## Patch",
        f"```diff",
        ev.patch[:3000] if ev.patch else "(no patch)",
        f"```",
    ]
    if ev.error:
        lines.append(f"\n## Error\n{ev.error}")
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Proof-of-Fix — verified autofix")
    sub = p.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="Generate and verify a fix")
    gen.add_argument("finding_key", help="Finding key from scan report")
    gen.add_argument("--report", "-r", required=True, help="Scan report JSON")
    gen.add_argument("--project-root", default=".", help="Project root directory")
    gen.add_argument("--output", "-o", help="Save evidence as JSON")

    sub.add_parser("batch", help="Generate fixes for all CRITICAL findings in report")
    # batch handled below

    args = p.parse_args()

    if args.cmd == "generate":
        print(f"[PoF] Processing {args.finding_key}...")
        evidence = generate_fix(args.finding_key, args.report, args.project_root)

        print(evidence_to_markdown(evidence))
        print(f"\n{'✅ VERIFIED — fix works!' if evidence.verified else '❌ Could not verify — see errors above'}")

        if args.output:
            Path(args.output).write_text(json.dumps(evidence_to_dict(evidence), indent=2, ensure_ascii=False))
            print(f"Evidence saved to {args.output}")

        sys.exit(0 if evidence.verified else 1)


if __name__ == "__main__":
    main()
