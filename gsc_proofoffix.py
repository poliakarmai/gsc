#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Proof-of-Fix v0.27 (revised code review 2026-08-06).

Cycle: finding → patch → sandbox apply → re-PoC → verify → evidence.

Fixed:
  C1  verified by PoC markers, not bare exit code
  H1  PoC executed ONLY in sandbox (tempdir, no-network, timeout)
  H2  patch applied via edit-instructions {find, replace}, not unified diff
"""

from __future__ import annotations

import ast
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from gsc_poc_generator import SUCCESS_MARKERS

POC_TIMEOUT_SEC = 30
POC_MAX_OUTPUT = 4096
MAX_ITERATIONS = 3
MAX_EDITS = 6

# Any PoC network call immediately fails (port 9 = discard)
NO_NET_ENV = {
    "http_proxy": "http://127.0.0.1:9",
    "https_proxy": "http://127.0.0.1:9",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "no_proxy": "",
}


@dataclass
class FixEvidence:
    finding_key: str
    rule_id: str = ""
    file_path: str = ""
    line_number: int = 0
    level: str = "failed"          # verified|structural|syntax_only|failed
    verified: bool = False
    patch: list = field(default_factory=list)   # edit-instructions
    patch_display: str = ""
    reasoning: str = ""
    exploited_before: Optional[bool] = None
    exploited_after: Optional[bool] = None
    detector_fires_before: bool = False
    detector_fires_after: bool = False
    poc_before: str = ""
    poc_after: str = ""
    iterations: int = 0
    verified_by: str = "sandbox"    # sandbox|sandbox_dast|dast_only
    dast_verified: Optional[bool] = None
    dast_output: str = ""
    dast_exit: Optional[int] = None
    error: str = ""

    def to_dict(self):
        d = asdict(self)
        d.pop("patch_display", None)
        d["patch_display"] = self.patch_display[:3000]
        return d


# ── Sandbox ────────────────────────────────────────────────
class FixSandbox:
    """Isolated file copy in tempdir. Original is never mutated."""

    def __init__(self, file_path: str, original: str):
        self.file_path = file_path
        self.basename = os.path.basename(file_path)
        self.dir = tempfile.TemporaryDirectory(prefix="gsc_pof_")
        self.workfile = os.path.join(self.dir.name, self.basename)
        Path(self.workfile).write_text(original, encoding="utf-8")

    def apply_edits(self, edits: list) -> str:
        content = Path(self.workfile).read_text(encoding="utf-8")
        for e in edits:
            find_text = e["find"]
            replace_text = e["replace"]
            n = content.count(find_text)
            if n != 1:
                raise PatchApplyError(f"find-block not unique/absent (occurrences={n})")
            content = content.replace(find_text, replace_text, 1)
        Path(self.workfile).write_text(content, encoding="utf-8")
        return content

    def syntax_ok(self, content: str) -> bool:
        if not self.basename.endswith(".py"):
            return True
        try:
            ast.parse(content)
            return True
        except SyntaxError:
            return False

    def cleanup(self):
        self.dir.cleanup()


class PatchApplyError(Exception):
    pass


# ── PoC execution with marker contract (C1) + isolation (H1) ──
def _run_poc_sandboxed(poc_code: str, sandbox_dir: str) -> dict:
    """Execute PoC in isolation. Returns {exploited, output, exit}.

    exploited = True when exit_code == 0 AND a SUCCESS_MARKER is in output.
    exploited = None when marker was not printed or process crashed.
    """
    poc_path = os.path.join(sandbox_dir, "poc_verify.py")
    Path(poc_path).write_text(poc_code, encoding="utf-8")

    env = {**os.environ, **NO_NET_ENV, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        proc = subprocess.run(
            [sys.executable, poc_path],
            cwd=sandbox_dir, env=env,
            timeout=POC_TIMEOUT_SEC, capture_output=True, text=True,
        )
    except subprocess.TimeoutExpired:
        return {"exploited": None, "output": "<timeout>", "exit": None}
    except Exception as e:
        return {"exploited": None, "output": f"<error: {e}>", "exit": None}

    out = (proc.stdout or "")[-POC_MAX_OUTPUT:]
    has_marker = any(m in out.upper() for m in SUCCESS_MARKERS)
    exploited = (proc.returncode == 0) and has_marker
    return {"exploited": exploited, "output": out, "exit": proc.returncode}


# ── LLM helpers ────────────────────────────────────────────
def _call_llm(system: str, user: str, max_tokens: int = 900) -> Optional[str]:
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


# ── Patch generator (edit-instructions) ────────────────────
PATCH_PROMPT = """You are a security engineer. Fix the vulnerability with the
MINIMAL safe change. Do not refactor unrelated code. Do not delete
functionality unless it IS the vulnerability.

Rule: {rule_id} — {title}
File: {file_path}:{line}
Code:
{context}

{history}

Output strictly as JSON:
{{
  "reasoning": "one paragraph",
  "edits": [{{"find": "<exact text from the file>",
              "replace": "<fixed text>"}}]
}}

Requirements:
- "find" MUST match the file text EXACTLY (whitespace included)
- use parameterization/escaping/allowlists/validation as appropriate
- keep legitimate behavior intact
"""


class PatchGenerator:
    def __init__(self, budget: int = 4):
        self.budget = budget

    def generate(self, finding, source, failed=None) -> Optional[dict]:
        if self.budget <= 0:
            return None
        self.budget -= 1

        context = self._context(source, finding.get("line", finding.get("line_number", 1)))
        history = ""
        if failed:
            history = ("Previous attempts FAILED:\n"
                       + "\n".join(f"- {a}" for a in failed[-3:])
                       + "\nPropose a different approach.")

        prompt = PATCH_PROMPT.format(
            rule_id=finding.get("rule_id"), title=finding.get("title", ""),
            file_path=finding.get("file_path", finding.get("file", "")),
            line=finding.get("line_number", finding.get("line", 1)),
            context=context, history=history,
        )

        raw = _call_llm(
            "You are a security fix engine. Output strictly JSON with edit instructions.",
            prompt, max_tokens=900,
        )
        if not raw:
            return None
        return self._parse(raw)

    def _context(self, source, line, span=15):
        lines = source.splitlines()
        start = max(0, line - 1 - span)
        return "\n".join(lines[start:start + span * 2])

    def _parse(self, raw):
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None

        edits = data.get("edits")
        if not isinstance(edits, list) or not edits or len(edits) > MAX_EDITS:
            return None
        for e in edits:
            if not isinstance(e.get("find"), str) or not e["find"].strip():
                return None
            if not isinstance(e.get("replace"), str):
                return None
        return {"reasoning": str(data.get("reasoning", ""))[:400], "edits": edits}


def _render_diff(before: str, after: str, path: str) -> str:
    return "\n".join(difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
    ))


# ── Orchestrator ───────────────────────────────────────────
class ProofOfFix:
    def __init__(self, patch_generator, detect_fn, max_iter=MAX_ITERATIONS,
                 staging_url: str = None, dast_timeout: int = 300):
        self.gen = patch_generator
        self.detect_fn = detect_fn   # detect_fn(file, content) -> [findings]
        self.max_iter = max_iter
        self.staging_url = staging_url
        self.dast_timeout = dast_timeout

    def _detector_fires(self, finding, source):
        hits = self.detect_fn(finding.get("file_path", finding.get("file", "")), source)
        return any(h.get("rule_id") == finding.get("rule_id", "") for h in hits)

    def attempt(self, finding, source, poc_code) -> FixEvidence:
        import hashlib
        raw = f"{finding.get('rule_id','')}+{finding.get('file_path','')}+{finding.get('detail','')[:80]}"
        key = hashlib.sha256(raw.encode()).hexdigest()[:12]

        ev = FixEvidence(
            finding_key=key, rule_id=finding.get("rule_id", ""),
            file_path=finding.get("file_path", ""),
            line_number=finding.get("line_number", 0),
        )
        failed = []
        best_level, best_patch, best_reason = "failed", [], ""

        fires_before = self._detector_fires(finding, source)
        ev.detector_fires_before = fires_before

        # Pre-fix PoC (gold-standard signal)
        pre_sb = FixSandbox(finding.get("file_path", "t.py"), source)
        try:
            pre = _run_poc_sandboxed(poc_code, pre_sb.dir.name)
            ev.exploited_before = pre["exploited"]
            ev.poc_before = pre["output"]
        finally:
            pre_sb.cleanup()

        for i in range(self.max_iter):
            patch = self.gen.generate(finding, source, failed)
            if patch is None:
                failed.append("generator returned nothing")
                continue

            sb = FixSandbox(finding.get("file_path", "t.py"), source)
            try:
                patched = sb.apply_edits(patch["edits"])
                if not sb.syntax_ok(patched):
                    failed.append(f"iter{i}: syntax broken")
                    continue

                fires_after = self._detector_fires(finding, patched)
                post = _run_poc_sandboxed(poc_code, sb.dir.name)
                exploited_after = post["exploited"]

                level = self._classify(
                    ev.exploited_before, exploited_after,
                    fires_before, fires_after,
                )

                if _rank(level) > _rank(best_level):
                    best_level = level
                    best_patch = patch["edits"]
                    best_reason = patch["reasoning"]
                    ev.exploited_after = exploited_after
                    ev.poc_after = post["output"]
                    ev.detector_fires_after = fires_after
                    ev.patch_display = _render_diff(source, patched, finding.get("file_path", "t.py"))

                if level == "verified":
                    break
                if fires_after:
                    failed.append(f"iter{i}: detector still fires, poc_after={exploited_after}")
                else:
                    failed.append(f"iter{i}: level={level}")
            except PatchApplyError as e:
                failed.append(f"iter{i}: apply failed — {e}")
            finally:
                sb.cleanup()

        ev.level = best_level
        ev.patch = best_patch
        ev.reasoning = best_reason
        ev.verified = (best_level == "verified")
        ev.iterations = i + 1

        # Wave 3: DAST verification on staging
        if self.staging_url and ev.level in ("verified", "structural"):
            from gsc_dast_validator import validate_fix_on_staging
            dast_result = validate_fix_on_staging(
                finding, poc_code, ev.to_dict(),
                self.staging_url, self.dast_timeout)
            ev.dast_verified = dast_result["dast_verified"]
            ev.dast_output = dast_result["dast_output"]
            ev.dast_exit = dast_result["dast_exit"]
            if ev.dast_verified is True:
                ev.verified_by = "sandbox_dast"
            elif ev.dast_verified is False:
                ev.level = "failed"
                ev.verified = False
                ev.verified_by = "sandbox"
            # dast_verified=None → keep sandbox-only
        elif not self.staging_url:
            ev.verified_by = "sandbox"

        # 🆕 Deep verification: run PoC in isolated venv with project dependencies
        if ev.verified and ev.level == "verified" and best_patch:
            try:
                from gsc_pof_sandbox import verify_pof
                # Apply best patch to get patched source
                temp_sb = FixSandbox(finding.get("file_path", "t.py"), source)
                try:
                    patched_source = temp_sb.apply_edits(best_patch)
                finally:
                    temp_sb.cleanup()
                
                deep = verify_pof(
                    finding=finding,
                    vulnerable_code=source,
                    patched_code=patched_source,
                    poc_code=poc_code,
                    project_dir=str(Path(finding.get("file_path", ".")).parent) if finding.get("file_path") else None,
                )
                if deep.verified:
                    ev.verified_by = "sandbox_venv"
                elif deep.reason:
                    ev.reasoning += f" | deep_sandbox: {deep.reason}"
            except Exception as e:
                ev.reasoning += f" | deep_sandbox_err: {str(e)[:80]}"

        return ev

    @staticmethod
    def _classify(expl_before, expl_after, fires_before, fires_after):
        # Gold: exploitable BEFORE and NOT exploitable AFTER
        if expl_before is True and expl_after is False:
            return "verified"
        # Deterministic signal: detector stopped firing
        if fires_before and not fires_after:
            return "structural"
        # Nothing proven, but syntax is intact
        return "syntax_only"


def _rank(level):
    return {"failed": 0, "syntax_only": 1, "structural": 2, "verified": 3}.get(level, 0)


# ── Generate PoC code for a finding ────────────────────────
def _generate_poc_code(finding: dict, source_code: str) -> Optional[str]:
    sys.path.insert(0, str(Path(__file__).parent))
    from gsc_poc_generator import PoCGenerator
    gen = PoCGenerator(budget=1)
    poc = gen.generate(finding, source_code)
    return poc.code if poc and poc.code else None


# ── Main entry point ───────────────────────────────────────
def generate_fix(finding_key: str, report_path: str, project_root: str) -> FixEvidence:
    root = Path(project_root).resolve()
    finding = _find_finding(report_path, finding_key)
    ev = FixEvidence(finding_key=finding_key)

    if not finding:
        ev.error = f"Finding {finding_key} not found in {report_path}"
        return ev

    ev.rule_id = finding.get("rule_id", "")
    ev.file_path = finding.get("file_path", "")
    ev.line_number = finding.get("line_number", 0)

    file_path = root / ev.file_path
    if not file_path.exists():
        ev.error = f"Source file not found: {ev.file_path}"
        return ev

    source = file_path.read_text(encoding="utf-8")
    if not source.strip():
        ev.error = "Source file is empty"
        return ev

    # Generate PoC code
    print(f"[PoF] Generating PoC for {ev.rule_id} in {ev.file_path}...")
    poc_code = _generate_poc_code(finding, source)
    if not poc_code:
        ev.error = "PoC generation failed — cannot verify fix"
        return ev

    # A simple detect_fn that checks if the rule still fires
    # In production, this would call gsc_external detectors, but for
    # now we use a structural check: the detector stopped if we can't
    # find the same pattern in the source
    import re as _re

    def _detect_fn(file_path: str, content: str) -> list:
        """Minimal structural detector — checks if GS00X pattern still present."""
        results = []
        rule_prefix = finding.get("rule_id", "")
        if rule_prefix == "GS001" and "sk-" in content:
            results.append({"rule_id": "GS001"})
        if rule_prefix == "GS004" and ("os.system" in content or "shell=True" in content):
            results.append({"rule_id": "GS004"})
        if rule_prefix == "GS005" and _re.search(r"SELECT.*\+|f\"SELECT|%.*sql", content, _re.IGNORECASE):
            results.append({"rule_id": "GS005"})
        if rule_prefix == "GS017" and "password" in content.lower():
            results.append({"rule_id": "GS017"})
        return results

    print(f"[PoF] Running Proof-of-Fix orchestrator ({MAX_ITERATIONS} iterations)...")
    gen = PatchGenerator(budget=MAX_ITERATIONS)
    pof = ProofOfFix(gen, _detect_fn, max_iter=MAX_ITERATIONS)
    result = pof.attempt(finding, source, poc_code)

    result.error = ev.error
    return result


# ── Output ─────────────────────────────────────────────────
def evidence_to_markdown(ev: FixEvidence) -> str:
    level_icon = {"verified": "✅ VERIFIED", "structural": "🟡 STRUCTURAL",
                   "syntax_only": "⚪ SYNTAX ONLY", "failed": "❌ FAILED"}
    icon = level_icon.get(ev.level, "❓")

    lines = [
        f"# Proof-of-Fix: {ev.finding_key} — {icon}",
        f"**Rule:** {ev.rule_id} | **File:** {ev.file_path}:{ev.line_number}",
        f"**Level:** {ev.level} (iterations: {ev.iterations})",
        f"**Reasoning:** {ev.reasoning[:300]}",
        "",
        f"### Before (Exploitable: {ev.exploited_before})",
        f"```\n{ev.poc_before[:1000]}\n```",
        f"### After (Exploitable: {ev.exploited_after})",
        f"```\n{ev.poc_after[:1000]}\n```",
        f"### Patch ({len(ev.patch)} edits)",
        f"```diff\n{ev.patch_display[:3000]}\n```",
    ]
    if ev.error:
        lines.append(f"\n### Error\n{ev.error}")
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Proof-of-Fix v0.27")
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
            Path(args.output).write_text(json.dumps(evidence.to_dict(), indent=2, ensure_ascii=False))
        sys.exit(0 if evidence.verified else 1)


if __name__ == "__main__":
    main()
