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
    isolation_before: str = ""
    isolation_after: str = ""
    detector_fires_before: bool = False
    detector_fires_after: bool = False
    poc_before: str = ""
    poc_after: str = ""
    iterations: int = 0
    verified_by: str = "sandbox"    # sandbox|sandbox_dast|dast_only
    dast_verified: Optional[bool] = None
    dast_output: str = ""
    dast_exit: Optional[int] = None
    # Фаза 10.2: число мутаций, прошедших adversarial re-attack (superficial fix).
    adversarial_mutations: int = 0
    # GSC-003: audit-visible DAST/deep-verify status — never silently skipped.
    dast_skipped: bool = False
    dast_skip_reason: str = ""
    deep_verify_error: str = ""
    error: str = ""
    # Evidence Passport (audit Killer feature B): signed, self-contained proof.
    passport: Optional[dict] = None

    def to_dict(self):
        d = asdict(self)
        d.pop("patch_display", None)
        d["patch_display"] = self.patch_display[:3000]
        return d


# DD-05: canonical finding field names are `file_path` and `line_number`
# (used by gsc_db schema, action.yml, and the CLI). These helpers tolerate
# legacy `file`/`line` keys from older JSON reports so no caller breaks.
def _norm_file(f: dict) -> str:
    return f.get("file_path") or f.get("file") or ""


def _norm_line(f: dict) -> int:
    return f.get("line_number") or f.get("line") or 0


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


def _adversarial_recheck(finding: dict, poc_code: str, sandbox_dir: str, fmt: str) -> int:
    """Фаза 10.2 (Shinobi): мутировать base-payload и перезапустить PoC.

    Поверхностный фикс (фильтр одной строки) заблокирует исходный payload, но
    пропустит обфускацию той же атаки. Возвращает число мутаций, которые всё ещё
    эксплуатируют — >0 означает «залатали симптом, не причину».
    """
    try:
        from gsc_poc_deterministic import DETERMINISTIC_RULES
        from gsc_poc_mutator import mutate
    except Exception:
        return 0
    rule_id = finding.get("rule_id", "")
    base_payload = kind = None
    for prefix, (k, payload, _marker, _f) in DETERMINISTIC_RULES.items():
        if rule_id.startswith(prefix):
            base_payload, kind = payload, k
            break
    if not base_payload or base_payload not in poc_code:
        return 0  # payload не в PoC литералом (LLM-сгенерированный) — пропуск
    n = 0
    for variant in mutate(base_payload, kind):
        mutated_poc = poc_code.replace(base_payload, variant, 1)
        try:
            res = _run_poc_sandboxed(mutated_poc, sandbox_dir, fmt=fmt)
        except Exception:
            continue
        if res.get("exploited"):
            n += 1
    return n


# ── PoC execution with marker contract (C1) + isolation (H1) ──
def _run_poc_sandboxed(poc_code: str, sandbox_dir: str, fmt: str = "python",
                       target_code: str = "") -> dict:
    """Execute PoC in isolation. Returns {exploited, output, exit, isolation}.

    exploited = True when exit_code == 0 AND a SUCCESS_MARKER is in output.
    exploited = None when the marker was not printed or the process crashed.

    fmt dispatch (fix): curl/bash/shell/sh PoCs are executed as shell via
    PoFSandbox._execute_shell (which serves the target web app and substitutes
    TARGET_URL); anything else runs as a Python script. Previously a curl PoC
    was written verbatim into poc_verify.py and run as Python → SyntaxError →
    exploited always False, so "verified" was unreachable.
    """
    fmt = (fmt or "python").lower()

    # Shell/curl PoCs — delegate to the PoFSandbox shell executor.
    if fmt in ("curl", "bash", "shell", "sh"):
        try:
            from gsc_pof_sandbox import PoFSandbox
        except Exception as e:
            return {"exploited": None, "output": f"<gsc_pof_sandbox unavailable: {e}>",
                    "exit": None, "isolation": "rlimit"}
        try:
            res = PoFSandbox()._execute_shell(poc_code, target_code or "")
            out = (res.stdout or "")
            if res.stderr:
                out += ("\n[stderr]\n" + res.stderr)
            exploited = res.success if not res.error else None
            return {"exploited": exploited, "output": out[-POC_MAX_OUTPUT:],
                    "exit": res.exit_code, "isolation": res.isolation}
        except Exception as e:
            return {"exploited": None, "output": f"<shell exec error: {e}>",
                    "exit": None, "isolation": "rlimit"}

    # Python PoC — write to poc_verify.py and run under best isolation.
    poc_path = os.path.join(sandbox_dir, "poc_verify.py")
    Path(poc_path).write_text(poc_code, encoding="utf-8")
    try:
        from gsc_core.gsc_provenance import mark
        mark(poc_path, "agent", "poc_generation")  # provenance: agent-created, not repo
    except Exception:
        pass

    # DD-01 + DD-02: PoC must NOT inherit host secrets (DEEPSEEK_API_KEY,
    # GITHUB_TOKEN, JWT_SECRET, ...) and must run under the best available
    # isolation — container (docker/podman) first, then rlimit+minimal-env.
    try:
        from gsc_pof_sandbox import (
            SANDBOX_ENV_WHITELIST, _sandbox_env, _sandbox_limits,
            _isolation_backend, _run_isolated,
        )
    except Exception:
        SANDBOX_ENV_WHITELIST = {
            "PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH",
            "TMPDIR", "TEMP", "TMP", "SHELL",
        }
        _sandbox_env = _sandbox_limits = _isolation_backend = _run_isolated = None

    # Minimal env — never inherit host secrets (DD-01).
    if _sandbox_env is not None:
        env = _sandbox_env(sandbox_dir)
    else:
        env = {k: os.environ[k] for k in SANDBOX_ENV_WHITELIST if k in os.environ}
    env.update(NO_NET_ENV)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    def _host_run():
        # rlimit fallback — still drops privileges + minimal env (DD-02).
        return subprocess.run(
            [sys.executable, poc_path],
            cwd=sandbox_dir, env=env,
            preexec_fn=(_sandbox_limits if _sandbox_limits is not None else None),
            timeout=POC_TIMEOUT_SEC, capture_output=True, text=True,
        )

    isolation = "rlimit"
    try:
        proc = None
        # Container path first (strongest isolation — DD-02).
        if (_run_isolated is not None and _isolation_backend is not None
                and _isolation_backend() != "rlimit"):
            try:
                os.chmod(sandbox_dir, 0o777)
            except OSError:
                pass
            try:
                proc, iso = _run_isolated(
                    ["python3", "poc_verify.py"], sandbox_dir, POC_TIMEOUT_SEC
                )
                if proc is not None and iso:
                    isolation = iso
            except subprocess.TimeoutExpired:
                return {"exploited": None, "output": "<timeout>", "exit": None,
                        "isolation": "timeout"}
            except Exception:
                proc = None
        if proc is None:
            proc = _host_run()
    except subprocess.TimeoutExpired:
        return {"exploited": None, "output": "<timeout>", "exit": None,
                "isolation": "timeout"}
    except Exception as e:
        return {"exploited": None, "output": f"<error: {e}>", "exit": None,
                "isolation": "rlimit"}

    out = (proc.stdout or "")[-POC_MAX_OUTPUT:]
    has_marker = any(m in out.upper() for m in SUCCESS_MARKERS)
    exploited = (proc.returncode == 0) and has_marker
    return {"exploited": exploited, "output": out, "exit": proc.returncode,
            "isolation": isolation}


def _isolation_allows_verified(iso_before: str, iso_after: str) -> bool:
    """GSC-001: "verified" requires OS isolation (docker/podman) on BOTH the
    before-fix and after-fix runs. rlimit fallback is a degradation, not proof
    — a hostile PoC executed on the host must never yield "verified"."""
    try:
        from gsc_pof_sandbox import _is_container_isolation
    except Exception:
        def _is_container_isolation(iso: str) -> bool:
            return bool(iso) and iso not in ("rlimit", "timeout") and "rlimit" not in iso
    return _is_container_isolation(iso_before) and _is_container_isolation(iso_after)


def _warn_no_container_isolation() -> Optional[str]:
    """DD-05: fail-fast — surface when docker/podman is absent so callers never
    silently accept an rlimit-degraded "verified". Returns a warning, or None."""
    try:
        from gsc_pof_sandbox import _isolation_backend, _is_container_isolation
        backend = _isolation_backend()
        if not _is_container_isolation(backend):
            return ("container runtime (docker/podman) not found — proof-of-fix "
                    "degrades to rlimit (structural only, not 'verified'). "
                    "Install docker or podman for full verification.")
    except Exception:
        pass
    return None


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
    findings = report.get("findings", []) if isinstance(report, dict) else report
    import hashlib
    for f_ in findings:
        if f_.get("finding_key") == finding_key:
            return f_
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
            file_path=_norm_file(finding),
            line=_norm_line(finding),
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
        hits = self.detect_fn(_norm_file(finding), source)
        return any(h.get("rule_id") == finding.get("rule_id", "") for h in hits)

    def attempt(self, finding, source, poc_code, poc_fmt: str = "python") -> FixEvidence:
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
            pre = _run_poc_sandboxed(poc_code, pre_sb.dir.name, fmt=poc_fmt,
                                     target_code=source)
            ev.exploited_before = pre["exploited"]
            ev.poc_before = pre["output"]
            ev.isolation_before = pre.get("isolation", "")
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
                post = _run_poc_sandboxed(poc_code, sb.dir.name, fmt=poc_fmt,
                                          target_code=patched)
                exploited_after = post["exploited"]

                # Фаза 10.2: adversarial re-attack — если оригинальный PoC заблокирован,
                # прогоняем мутированные payload'ы той же атаки.
                if ev.exploited_before and exploited_after is False:
                    adv = _adversarial_recheck(finding, poc_code, sb.dir.name, poc_fmt)
                    if adv > 0:
                        exploited_after = True
                        ev.adversarial_mutations = adv

                level = self._classify(
                    ev.exploited_before, exploited_after,
                    fires_before, fires_after,
                )
                # GSC-001 fail-closed: "verified" requires OS isolation on both
                # runs. rlimit fallback degrades to "structural", never "verified".
                if level == "verified" and not _isolation_allows_verified(
                        ev.isolation_before, post.get("isolation", "")):
                    level = "structural"

                if _rank(level) > _rank(best_level):
                    best_level = level
                    best_patch = patch["edits"]
                    best_reason = patch["reasoning"]
                    ev.exploited_after = exploited_after
                    ev.poc_after = post["output"]
                    ev.isolation_after = post.get("isolation", "")
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
            ev.dast_skipped = True
            ev.dast_skip_reason = "no staging_url configured"

        # 🆕 Deep verification: run PoC in isolated venv with project dependencies
        if ev.verified and ev.level == "verified" and best_patch and poc_code:
            try:
                from gsc_pof_sandbox import verify_pof
                # Apply best patch edits to source
                temp_sb = FixSandbox(finding.get("file_path", "t.py"), source)
                patched_source = source
                try:
                    patched_source = temp_sb.apply_edits(best_patch)
                except Exception:
                    pass  # Edit application can fail for complex patches
                finally:
                    temp_sb.cleanup()

                # Only attempt if source is a runnable unit (> 3 lines, has def/class/import)
                if len(source.split("\n")) > 3:
                    deep = verify_pof(
                        finding=finding,
                        vulnerable_code=source,
                        patched_code=patched_source,
                        poc_code=poc_code,
                        project_dir=str(Path(finding.get("file_path", ".")).parent) if finding.get("file_path") else None,
                    )
                    if deep.verified:
                        ev.verified_by = "sandbox_venv"
                        ev.reasoning += " | deep_sandbox: VERIFIED in isolated venv"
            except ImportError:
                ev.deep_verify_error = "gsc_pof_sandbox not installed — deep verify skipped"
            except Exception as e:
                ev.deep_verify_error = str(e)[:200]
                ev.reasoning += f" | deep_sandbox: {str(e)[:60]}"

        # Evidence Passport (audit Killer feature B). Emit UNCONDITIONALLY — a signed
        # record that a fix *failed* is itself audit evidence. Verdict derives from the
        # final ev.verified + both-runs isolation + image digest (after DAST/deep-verify).
        from gsc_cli.gsc_evidence_passport import make_passport, verdict_from_isolation
        iso = ev.isolation_before or ev.isolation_after or ""
        digest = os.environ.get("GSC_IMAGE_DIGEST")
        verdict = verdict_from_isolation(iso, digest)
        # Never claim "verified" unless the fix actually held (ev.verified + level).
        if not (ev.verified and ev.level == "verified") and verdict == "verified":
            verdict = "structural"
        signing_key = None
        if os.environ.get("GSC_EVIDENCE_KEY"):
            signing_key = os.environ["GSC_EVIDENCE_KEY"].encode()
        ev.passport = make_passport(
            finding_key=ev.finding_key,
            verdict=verdict,
            before={"exploited": ev.exploited_before, "isolation": ev.isolation_before},
            after={"exploited": ev.exploited_after, "isolation": ev.isolation_after},
            scanner_sha=os.environ.get("GSC_SCANNER_SHA", ""),
            image_digest=digest,
            signing_key=signing_key,
            repo=os.environ.get("GSC_REPO", ""),
            commit=os.environ.get("GSC_COMMIT", ""),
        )

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
def _generate_poc_code(finding: dict, source_code: str):
    sys.path.insert(0, str(Path(__file__).parent))
    # 1) deterministic PoC (no LLM) — covers SQLi/CMDI/IDOR/XSS/SSRF/redirect
    #    and (via title keywords) SSTI/pickle/XXE/path-traversal.
    from gsc_poc_deterministic import get_deterministic_poc
    det = get_deterministic_poc(
        finding.get("rule_id", ""),
        finding.get("title", finding.get("pattern_title", "")),
    )
    if det:
        return det._generate_code(), det.fmt
    # 2) fall back to LLM PoC generator
    from gsc_poc_generator import PoCGenerator
    gen = PoCGenerator(budget=1)
    poc = gen.generate(finding, source_code)
    if poc and poc.code:
        return poc.code, "python"
    return None, None


# ── Main entry point ───────────────────────────────────────
def generate_fix(finding_key: str, report_path: str, project_root: str) -> FixEvidence:
    root = Path(project_root).resolve()
    _warn = _warn_no_container_isolation()
    if _warn:
        # Fail-fast (DD-05): generate_fix always executes the PoC in the sandbox
        # (there is no dry-run path here), so rlimit degradation is immediately relevant.
        print(f"[PoF] {_warn}", file=sys.stderr)
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
    poc_code, poc_fmt = _generate_poc_code(finding, source)
    if not poc_code:
        ev.error = "PoC generation failed — cannot verify fix"
        return ev

    # DD-03: real detector check via the registry — not a 4-rule stub. For the
    # finding's rule_id, ask the actual detector whether it still fires on the
    # patched content. Falls back to legacy heuristics only if the registry or
    # that specific detector is unavailable.
    import re as _re

    def _detect_fn(file_path: str, content: str) -> list:
        """Detect if the finding's rule still fires on the given content."""
        results = []
        target_rule = finding.get("rule_id", "")
        try:
            from gsc_detectors.registry import get_detectors
            from gsc_detectors import AuditContext
            for det in get_detectors(echelon=None):
                if det.rule_id != target_rule:
                    continue
                detect_fn = det.detect
                try:
                    if (hasattr(detect_fn, '__self__')
                            and hasattr(detect_fn.__self__, '_compiled')):
                        # RegexDetector: detect(file_path, content)
                        det_findings = detect_fn(file_path, content)
                    else:
                        # Plugin detector: detect(ctx)
                        ctx = AuditContext(
                            project=finding.get("project", "pof"),
                            path=Path(file_path).parent,
                        )
                        ctx.files = [Path(file_path)]
                        det_findings = detect_fn(ctx)
                    if det_findings:
                        results.append({"rule_id": det.rule_id})
                except Exception:
                    continue
                break
        except Exception:
            results = []
        # Legacy fallback only when registry unavailable (DD-03 safety net).
        if not results:
            if target_rule == "GS001" and "sk-" in content:
                results.append({"rule_id": "GS001"})
            elif target_rule == "GS004" and ("os.system" in content or "shell=True" in content):
                results.append({"rule_id": "GS004"})
            elif target_rule == "GS005" and _re.search(r"SELECT.*\+|f\"SELECT|%.*sql", content, _re.IGNORECASE):
                results.append({"rule_id": "GS005"})
            elif target_rule == "GS017" and "password" in content.lower():
                results.append({"rule_id": "GS017"})
        return results

    print(f"[PoF] Running Proof-of-Fix orchestrator ({MAX_ITERATIONS} iterations)...")
    gen = PatchGenerator(budget=MAX_ITERATIONS)
    pof = ProofOfFix(gen, _detect_fn, max_iter=MAX_ITERATIONS)
    result = pof.attempt(finding, source, poc_code, poc_fmt=poc_fmt or "python")

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
    from gsc_cli.gsc_signature import pr_signature
    verified = bool(getattr(ev, "verified", False)) or ev.level == "verified"
    poc_success = bool(ev.exploited_before and ev.exploited_after is False)
    lines.append(pr_signature(verified=verified, poc_success=poc_success, rule_id=ev.rule_id))
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
