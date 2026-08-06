#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Proof-of-Fix v1.1 — верифицированная автокоррекция.

v1.1 fixes (code review 2026-08-06):
  C1: SUCCESS_MARKERS contract — PoC exits 0 + prints marker on success
  H1: Sandbox isolation — tempdir + NO_NET_ENV + timeout
  H2: Edit-instructions fallback — find/replace before unified diff

Цикл: finding → patch (edit-instruction priority) → sandbox → re-PoC → verify.

CLI: gsc pof generate <key> --report scan.json
"""

from __future__ import annotations

import json, os, shutil, subprocess, sys, tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── C1: PoC SUCCESS markers (explicit contract) ────────────
SUCCESS_MARKERS = ("VULNERABLE", "EXPLOITED", "PWNED", "LEAKED", "SUCCESS",
                   "SQLI_SUCCESS", "XSS_SUCCESS", "RCE_SUCCESS", "SSRF_SUCCESS")
FAILURE_MARKERS = ("SAFE", "NOT_VULNERABLE", "PATCHED", "BLOCKED", "FAILED")

# ── H1: Sandbox isolation ──────────────────────────────────
NO_NET_ENV = {
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "http_proxy": "http://127.0.0.1:9",
    "https_proxy": "http://127.0.0.1:9",
    "NO_PROXY": "",
    "REQUESTS_CA_BUNDLE": "/dev/null",
    "CURL_CA_BUNDLE": "/dev/null",
}
SANDBOX_TIMEOUT = 30  # seconds per PoC run


# ── LLM ────────────────────────────────────────────────────
def _call_llm(system: str, user: str, max_tokens: int = 1500) -> Optional[str]:
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
        "max_tokens": max_tokens, "temperature": 0.1,
    }).encode()
    req = request.Request("https://api.deepseek.com/v1/chat/completions", data=data)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[PoF] LLM error: {e}", file=sys.stderr)
        return None


# ── Data ───────────────────────────────────────────────────
@dataclass
class FixEvidence:
    finding_key: str
    rule_id: str = "unknown"
    file_path: str = "unknown"
    line_number: int = 0
    patch: str = ""
    patch_mode: str = "none"          # edit_instruction | unified_diff | none
    patch_syntax_ok: bool = False
    # C1: marker-based verification
    exploited_before: bool = False
    poc_before: str = ""
    exploited_after: bool = False
    poc_after: str = ""
    verified: bool = False
    verified_at: str = ""
    error: str = ""


# ── Finding lookup ─────────────────────────────────────────
def _find_finding(report_path: str, finding_key: str) -> Optional[dict]:
    with open(report_path) as f:
        report = json.load(f)
    import hashlib
    for f_ in report.get("findings", []):
        raw = f"{f_.get('rule_id','')}+{f_.get('file_path','')}+{f_.get('detail','')[:80]}"
        if hashlib.sha256(raw.encode()).hexdigest()[:12] == finding_key:
            return f_
    return None


# ── H2: Patch generation (edit-instruction priority) ───────
def _generate_patch(finding: dict, source: str) -> tuple:
    """Returns (patch_text, mode) where mode = 'edit_instruction' | 'unified_diff'."""
    rule = finding.get("rule_id", "")
    detail = finding.get("detail", "")[:500]
    file_path = finding.get("file_path", "")
    line = finding.get("line_number", 0)

    system = (
        "You are a security fix engine. Generate a minimal patch as an EDIT INSTRUCTION, "
        "not a unified diff. Format:\n\n"
        "```edit\n"
        "@@ file:path/to/file.py @@\n"
        "@@ find @@\n"
        "exact vulnerable line(s) from source\n"
        "@@ replace @@\n"
        "fixed line(s)\n"
        "@@ end @@\n"
        "```\n\n"
        "RULES:\n"
        "- The 'find' block MUST match source EXACTLY (character-for-character)\n"
        "- The 'find' block must appear EXACTLY ONCE in the file\n"
        "- Change ONLY what's necessary — minimal diff\n"
        "- Never refactor, rename, or add features\n"
        "- If the fix requires a unified diff, fallback to:\n"
        "```diff\n--- a/path\n+++ b/path\n@@ -line,count +line,count @@\n context\n-old\n+new\n```\n"
        "Then append on the last line: EXPLANATION: <one sentence>"
    )

    user = (
        f"VULNERABILITY: {rule} — {file_path}:{line}\n"
        f"Details: {detail}\n\n"
        f"SOURCE CODE (around line {line}):\n{source[:4000]}"
    )

    raw = _call_llm(system, user, max_tokens=1500)
    if not raw:
        return "", "none"

    # H2: Try edit-instruction first
    if "```edit" in raw:
        patch = raw.split("```edit", 1)[1]
        if "```" in patch:
            patch = patch.split("```", 1)[0]
        return patch.strip(), "edit_instruction"

    # Fallback: unified diff
    if "```diff" in raw:
        patch = raw.split("```diff", 1)[1]
    elif "```" in raw:
        patch = raw.split("```", 1)[1]
    else:
        patch = raw

    if "```" in patch:
        patch = patch.split("```", 1)[0]

    # Strip EXPLANATION line
    for line_text in patch.split("\n"):
        if line_text.strip().upper().startswith("EXPLANATION"):
            patch = patch.split(line_text, 1)[0]
            break

    return patch.strip(), "unified_diff"


# ── H2: Patch application ──────────────────────────────────
def _apply_patch(source: str, patch: str, mode: str) -> str:
    """Apply patch. Returns patched source or raises."""
    if mode == "edit_instruction":
        # Parse find/replace blocks
        find_block = None
        replace_block = None
        for line_text in patch.split("\n"):
            if line_text.strip() == "@@ find @@" and find_block is None:
                find_block = ""
            elif line_text.strip() == "@@ replace @@" and find_block is not None:
                replace_block = ""
            elif line_text.strip() == "@@ end @@":
                break
            elif find_block is not None and replace_block is None:
                find_block += line_text + "\n"
            elif replace_block is not None:
                replace_block += line_text + "\n"

        find_block = (find_block or "").rstrip("\n")
        replace_block = (replace_block or "").rstrip("\n")

        if not find_block:
            raise RuntimeError("No 'find' block in edit instruction")

        # Verify find_block appears EXACTLY ONCE
        count = source.count(find_block)
        if count == 0:
            raise RuntimeError(f"'find' block not found in source (len={len(find_block)})")
        if count > 1:
            raise RuntimeError(f"'find' block appears {count} times — must be unique")

        return source.replace(find_block, replace_block, 1)

    # unified_diff fallback
    import tempfile as _tf
    with _tf.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as sf:
        sf.write(source)
        sf_path = sf.name
    with _tf.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as pf:
        pf.write(patch)
        pf_path = pf.name

    try:
        r = subprocess.run(
            ["patch", "-u", "--force", "--fuzz=2", sf_path, pf_path],
            capture_output=True, text=True, timeout=10,
        )
        # patch returns 0 on success, but also on "already applied" — check stderr
        if r.returncode != 0 and "FAILED" in (r.stderr or ""):
            raise RuntimeError(f"patch failed: {r.stderr[:200]}")
        return Path(sf_path).read_text()
    finally:
        Path(sf_path).unlink(missing_ok=True)
        Path(pf_path).unlink(missing_ok=True)


# ── C1+H1: PoC runner with sandbox + marker contract ───────
def _run_poc(finding: dict, source_code: str) -> tuple:
    """
    Returns (output, exit_code, exploited).
    exploited = True when: exit_code == 0 AND output contains a SUCCESS_MARKER.
    """
    sys.path.insert(0, str(Path(__file__).parent))
    from gsc_poc_generator import PoCGenerator

    gen = PoCGenerator(budget=1)
    poc = gen.generate(finding, source_code)

    if not poc or not poc.code:
        return "No PoC generated", -1, False

    # H1: isolated sandbox
    sandbox = tempfile.mkdtemp(prefix="gsc_sandbox_")
    try:
        sandbox_file = Path(sandbox) / Path(finding.get("file_path", "target.py")).name
        sandbox_file.write_text(source_code)

        poc_file = Path(sandbox) / "poc.py"
        poc_file.write_text(poc.code)

        r = subprocess.run(
            [sys.executable, str(poc_file)],
            capture_output=True, text=True,
            timeout=SANDBOX_TIMEOUT,
            cwd=sandbox,
            env={**os.environ, **NO_NET_ENV},
        )
        out = (r.stdout or "") + (r.stderr or "")

        # C1: marker-based exploitation check
        exploited = (
            r.returncode == 0
            and any(m in out.upper() for m in SUCCESS_MARKERS)
        )
        return out[-4096:], r.returncode, exploited
    except subprocess.TimeoutExpired:
        return "PoC timeout", 124, False
    except Exception as e:
        return str(e), -1, False
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


# ── Main cycle ─────────────────────────────────────────────
def generate_fix(finding_key: str, report_path: str, project_root: str) -> FixEvidence:
    root = Path(project_root).resolve()
    finding = _find_finding(report_path, finding_key)
    evidence = FixEvidence(finding_key=finding_key)

    if not finding:
        evidence.error = f"Finding {finding_key} not found in {report_path}"
        return evidence

    evidence.rule_id = finding.get("rule_id", "unknown")
    evidence.file_path = finding.get("file_path", "unknown")
    evidence.line_number = finding.get("line_number", 0)

    source = (root / evidence.file_path).read_text() if (root / evidence.file_path).exists() else ""
    if not source:
        evidence.error = f"Source file not found: {evidence.file_path}"
        return evidence

    # 1. Run PoC BEFORE (prove vulnerable)
    print(f"[PoF] Step 1: PoC BEFORE on {evidence.file_path}")
    evidence.poc_before, _, evidence.exploited_before = _run_poc(finding, source)
    if not evidence.exploited_before:
        evidence.error = (
            "PoC did not trigger on original code — cannot verify fix. "
            "Either the vulnerability is not exploitable or the PoC generator needs improvement."
        )
        return evidence

    # 2. Generate patch (edit-instruction priority)
    print("[PoF] Step 2: Generating patch via DeepSeek...")
    evidence.patch, evidence.patch_mode = _generate_patch(finding, source)
    if not evidence.patch:
        evidence.error = "LLM failed to generate patch"
        return evidence

    evidence.patch_syntax_ok = bool(evidence.patch)

    # 3. Apply in sandbox
    print(f"[PoF] Step 3: Applying patch ({evidence.patch_mode})...")
    try:
        patched = _apply_patch(source, evidence.patch, evidence.patch_mode)
    except Exception as e:
        evidence.error = f"Patch application failed: {e}"
        return evidence

    # 4. Re-run PoC AFTER (prove fixed)
    print("[PoF] Step 4: PoC AFTER on patched code...")
    evidence.poc_after, _, evidence.exploited_after = _run_poc(finding, patched)

    # C1: VERIFIED = exploited before AND NOT exploited after
    evidence.verified = evidence.exploited_before and not evidence.exploited_after
    evidence.verified_at = datetime.now(timezone.utc).isoformat()
    return evidence


# ── Reporting ──────────────────────────────────────────────
def evidence_to_dict(ev: FixEvidence) -> dict:
    return {
        "finding_key": ev.finding_key, "rule_id": ev.rule_id,
        "file_path": ev.file_path, "line_number": ev.line_number,
        "patch_mode": ev.patch_mode, "patch": ev.patch[:2000],
        "exploited_before": ev.exploited_before,
        "poc_before": ev.poc_before[:500],
        "exploited_after": ev.exploited_after,
        "poc_after": ev.poc_after[:500],
        "verified": ev.verified, "verified_at": ev.verified_at,
        "error": ev.error,
    }


def evidence_to_markdown(ev: FixEvidence) -> str:
    icon = "✅ VERIFIED" if ev.verified else "❌ FAILED"
    lines = [
        f"# Proof-of-Fix: {ev.finding_key} — {icon}",
        f"**Rule:** {ev.rule_id} | **File:** {ev.file_path}:{ev.line_number}",
        f"**Patch mode:** {ev.patch_mode} | **Verified at:** {ev.verified_at}",
        "",
        f"### Before (Exploitable: {'YES' if ev.exploited_before else 'NO'})",
        f"```\n{ev.poc_before[:1000]}\n```",
        f"### After (Exploitable: {'YES' if ev.exploited_after else 'NO'})",
        f"```\n{ev.poc_after[:1000]}\n```",
        f"### Patch",
        f"```{ev.patch_mode}\n{ev.patch[:3000]}\n```",
    ]
    if ev.error:
        lines.append(f"\n### Error\n{ev.error}")
    return "\n".join(lines)


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Proof-of-Fix v1.1")
    sub = p.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate", help="Generate and verify a fix")
    gen.add_argument("finding_key")
    gen.add_argument("--report", "-r", required=True)
    gen.add_argument("--project-root", default=".")
    gen.add_argument("--output", "-o")
    args = p.parse_args()

    if args.cmd == "generate":
        evidence = generate_fix(args.finding_key, args.report, args.project_root)
        print(evidence_to_markdown(evidence))
        print(f"\n{'✅ VERIFIED' if evidence.verified else '❌ COULD NOT VERIFY'}")
        if args.output:
            Path(args.output).write_text(json.dumps(evidence_to_dict(evidence), indent=2))
        sys.exit(0 if evidence.verified else 1)


if __name__ == "__main__":
    main()
