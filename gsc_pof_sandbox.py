#!/usr/bin/env python3
"""
GSC Proof-of-Fix Sandbox — executes PoCs before and after fix application.

Verifies: vulnerable_code → PoC SUCCESS, patched_code → PoC FAILURE.
Only then a fix is truly "verified."

Currently supports Python code in isolated venv.
Uses subprocess with timeout + resource limits for safety.
"""
from __future__ import annotations

import json, os, re, subprocess, sys, tempfile, time, venv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SANDBOX_TIMEOUT = 30  # Max seconds per PoC execution
MAX_OUTPUT_BYTES = 10_000
SUCCESS_MARKERS = re.compile(r'(VULNERABLE|EXPLOITED|PWNED|LEAKED|SUCCESS|BREACH)', re.I)
SANDBOX_ROOT = Path(os.path.expanduser("~/.hermes/state/gsc_sandbox"))

# Audit F-05: pass a minimal, secret-free environment into the sandbox. A PoC
# must NOT inherit DEEPSEEK_API_KEY / GITHUB_TOKEN / other host secrets — that
# would turn a "verified fix" into a credential-exfiltration primitive.
SANDBOX_ENV_WHITELIST = {
    "PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH",
    "TMPDIR", "TEMP", "TMP", "SHELL",
}

# Hard resource limits for the PoC child (CPU / RAM / processes / file size).
SANDBOX_MEM_LIMIT = 512 * 1024 * 1024   # 512 MB address space
SANDBOX_FSIZE_LIMIT = 16 * 1024 * 1024  # 16 MB max file write

# Phase 2: run a web target as a live HTTP server so curl-PoCs (SQLi/SSRF/IDOR/
# SSTI/auth-bypass) have a real TARGET_URL to hit. Best-effort: only standalone
# single-file apps are served; multi-module apps fall back to "SAFE" (no endpoint).
SERVE_TEMPLATES = {
    "flask": "from target_app import app\napp.run(host='127.0.0.1', port={port})\n",
    "sanic": "from target_app import app\napp.run(host='127.0.0.1', port={port})\n",
    "bottle": "from target_app import app\napp.run(host='127.0.0.1', port={port})\n",
    "fastapi": "import uvicorn\nfrom target_app import app\nuvicorn.run(app, host='127.0.0.1', port={port}, log_level='error')\n",
}


def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _detect_framework(target_code: str) -> str | None:
    """Heuristic web-framework detection from target source (single-file apps)."""
    t = target_code.lower()
    if "fastapi(" in t or "from fastapi" in t or "import fastapi" in t:
        return "fastapi"
    if "flask(" in t or "from flask" in t or "import flask" in t:
        return "flask"
    if "sanic(" in t or "from sanic" in t or "import sanic" in t:
        return "sanic"
    if "bottle(" in t or "from bottle" in t or "import bottle" in t:
        return "bottle"
    return None


def _detect_app_creation(target_code: str) -> str | None:
    """Detect `app = Framework(...)` creation (not a bare import) — stricter than
    _detect_framework, which also matches `from flask import Blueprint`."""
    import re
    m = re.search(r'\b(app|application)\s*=\s*(Flask|FastAPI|Sanic|Bottle)\s*\(', target_code)
    if m:
        return m.group(2).lower()
    return None


def _find_web_entrypoint(project_dir: str) -> tuple[str, str] | None:
    """Locate a web app entrypoint inside a (multi-module) project directory.

    Returns (framework, dotted_module_name) relative to project_dir, or None.
    Phase 3: serve real-world projects, not just single-file apps.
    """
    import os
    skip = {'.git', 'node_modules', 'venv', '.venv', 'build', 'dist',
            '__pycache__', '.next', 'tests', 'test', 'site-packages'}
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in skip]
        for fn in files:
            if not fn.endswith('.py'):
                continue
            p = os.path.join(root, fn)
            try:
                txt = open(p, encoding='utf-8', errors='ignore').read()
            except Exception:
                continue
            fw = _detect_app_creation(txt)
            if fw:
                rel = os.path.relpath(p, project_dir)
                mod = rel.replace(os.sep, '.').removesuffix('.py')
                return fw, mod
    return None


def _sandbox_env(workdir: str) -> dict:
    """Build a minimal env without host secrets (audit F-05)."""
    env = {k: os.environ[k] for k in SANDBOX_ENV_WHITELIST if k in os.environ}
    env["PYTHONPATH"] = workdir
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _sandbox_limits():
    """Apply hard CPU/memory/process/file limits to the PoC child (audit F-05).

    Best-effort: if ``resource`` is unavailable (e.g. non-POSIX) we degrade to
    subprocess timeout + output cap only.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_TIMEOUT, SANDBOX_TIMEOUT + 5))
        resource.setrlimit(resource.RLIMIT_AS, (SANDBOX_MEM_LIMIT, SANDBOX_MEM_LIMIT))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (SANDBOX_FSIZE_LIMIT, SANDBOX_FSIZE_LIMIT))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except Exception:
        pass


def _sandbox_limits_shell():
    """Limits for shell/curl PoC execution.

    RLIMIT_AS is omitted: a bash forked from a Python parent inherits a large
    virtual address space, so a 512 MB AS cap makes every fork() of external
    commands (curl/grep) fail with EAGAIN. Keep CPU/FSIZE/NPROC/NOFILE.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_TIMEOUT, SANDBOX_TIMEOUT + 5))
        resource.setrlimit(resource.RLIMIT_FSIZE, (SANDBOX_FSIZE_LIMIT, SANDBOX_FSIZE_LIMIT))
        resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except Exception:
        pass


@dataclass
class SandboxResult:
    """Result of a single PoC execution."""
    success: bool          # Did PoC marker appear?
    exit_code: int
    stdout: str
    stderr: str
    elapsed: float
    error: str = ""


@dataclass 
class FixVerification:
    """Result of before/after fix verification."""
    verified: bool          # Both checks passed?
    before: SandboxResult | None = None   # PoC on vulnerable code
    after: SandboxResult | None = None    # PoC on patched code
    reason: str = ""


class PoFSandbox:
    """Execute PoCs in isolated environment to verify fixes."""

    def __init__(self, project_dir: str | None = None, install_deps: bool = False):
        self.project_dir = Path(project_dir) if project_dir else None
        self.venv_dir = SANDBOX_ROOT / "venv"
        self._ensure_venv(install_deps=install_deps)

    def _ensure_venv(self, install_deps: bool = False):
        """Create isolated venv if not exists."""
        if self.venv_dir.exists():
            return
        SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
        builder = venv.EnvBuilder(with_pip=True, clear=True)
        builder.create(str(self.venv_dir))

        # Audit F-05: installing a scanned repo's requirements.txt executes
        # arbitrary build steps / pulls untrusted packages. Off by default;
        # opt-in with install_deps=True only for trusted internal repos.
        if install_deps and self.project_dir:
            req_file = self.project_dir / "requirements.txt"
            if req_file.exists():
                pip = str(self.venv_dir / "bin" / "pip")
                try:
                    subprocess.run(
                        [pip, "install", "-r", str(req_file)],
                        capture_output=True, text=True,
                        timeout=60, cwd=str(self.project_dir))
                except Exception:
                    pass  # Dependency install is best-effort

    @property
    def _python(self) -> str:
        return str(self.venv_dir / "bin" / "python3")

    # ── Core: verify fix ──────────────────────────────────────────

    def verify_fix(
        self, 
        vulnerable_code: str,
        patched_code: str,
        poc_code: str,
        language: str = "python",
        fmt: str = "python",
    ) -> FixVerification:
        """Full fix verification cycle.

        1. Execute PoC against vulnerable code → must SUCCEED
        2. Execute PoC against patched code → must FAIL
        3. Only then → verified = True
        """
        if language != "python":
            return FixVerification(verified=False, reason=f"Sandbox only supports Python, got {language}")

        # Step 1: PoC against vulnerable code
        before = self._execute(poc_code, vulnerable_code, fmt=fmt)
        if before.error:
            return FixVerification(verified=False, before=before, reason=f"before execution error: {before.error}")
        if not before.success:
            return FixVerification(verified=False, before=before, reason="PoC did not trigger on vulnerable code (possible FP)")

        # Step 2: PoC against patched code
        after = self._execute(poc_code, patched_code, fmt=fmt)
        if after.error:
            return FixVerification(verified=False, before=before, after=after, reason=f"after execution error: {after.error}")
        if after.success:
            return FixVerification(verified=False, before=before, after=after, reason="PoC STILL triggers on patched code (fix incomplete)")

        # Both passed → verified
        return FixVerification(verified=True, before=before, after=after, reason="PoC triggers before fix, fails after fix")

    # ── Execute PoC in sandbox ────────────────────────────────────

    def _execute(self, poc_code: str, target_code: str, fmt: str = "python",
                 project_dir: str | None = None) -> SandboxResult:
        """Dispatch by PoC format (fix: curl/bash PoCs were run as Python → TypeError).

        fmt: 'python'/'py' → import target + run as Python;
             'curl'/'bash'/'shell'/'sh' → run via bash -c (secret-free env + limits).

        project_dir: for curl PoCs, if set and TARGET_URL is referenced, serve the
        whole (multi-module) project as a live HTTP server (Phase 3).
        """
        fmt = (fmt or "python").lower()
        if fmt in ("curl", "bash", "shell", "sh"):
            return self._execute_shell(poc_code, target_code, project_dir=project_dir)
        return self._execute_python(poc_code, target_code)

    def _serve_target(self, target_code: str, workdir: Path):
        """Serve a single-file web app on a free local port. Returns (Popen, url) or None."""
        fw = _detect_framework(target_code)
        if fw is None:
            return None
        port = _free_port()
        (workdir / "target_app.py").write_text(target_code)
        (workdir / "serve.py").write_text(SERVE_TEMPLATES[fw].format(port=port))
        try:
            proc = subprocess.Popen(
                [self._python, str(workdir / "serve.py")],
                cwd=str(workdir), env=_sandbox_env(str(workdir)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except Exception:
            return None
        import urllib.request, urllib.error
        url = f"http://127.0.0.1:{port}"
        for _ in range(20):
            try:
                urllib.request.urlopen(url, timeout=0.3)
                return proc, url
            except urllib.error.HTTPError:
                return proc, url  # 4xx/5xx от живого сервера — это ОК
            except Exception:
                if proc.poll() is not None:
                    return None  # server exited
                time.sleep(0.2)
        try:
            proc.terminate()
        except Exception:
            pass
        return None

    def _serve_project(self, project_dir: str, workdir: Path):
        """Serve a multi-module web project (Phase 3). Returns (Popen, url) or None."""
        import os
        found = _find_web_entrypoint(project_dir)
        if not found:
            return None
        fw, mod = found
        port = _free_port()
        # Symlink the project into workdir so multi-module imports resolve.
        target_dir = workdir / "project"
        try:
            os.symlink(project_dir, target_dir, target_is_directory=True)
        except Exception:
            try:
                import shutil
                shutil.copytree(
                    project_dir, target_dir, symlinks=True,
                    ignore=shutil.ignore_patterns(
                        '.git', 'node_modules', 'venv', '.venv', 'build',
                        'dist', '__pycache__', '.next'),
                )
            except Exception:
                return None
        if fw == "fastapi":
            wrapper = (f"import uvicorn\nfrom {mod} import app\n"
                       f"uvicorn.run(app, host='127.0.0.1', port={port}, log_level='error')\n")
        else:
            wrapper = (f"from {mod} import app\n"
                       f"app.run(host='127.0.0.1', port={port})\n")
        (workdir / "serve_project.py").write_text(wrapper)
        env = _sandbox_env(str(workdir))
        env["PYTHONPATH"] = str(target_dir)
        try:
            proc = subprocess.Popen(
                [self._python, str(workdir / "serve_project.py")],
                cwd=str(target_dir), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except Exception:
            return None
        import urllib.request, urllib.error
        url = f"http://127.0.0.1:{port}"
        for _ in range(30):
            try:
                urllib.request.urlopen(url, timeout=0.4)
                return proc, url
            except urllib.error.HTTPError:
                return proc, url  # 4xx/5xx от живого сервера (нет route на /) — это ОК
            except Exception:
                if proc.poll() is not None:
                    return None
                time.sleep(0.25)
        try:
            proc.terminate()
        except Exception:
            pass
        return None

    def _execute_shell(self, poc_code: str, target_code: str,
                       project_dir: str | None = None) -> SandboxResult:
        """Run a shell/curl PoC via bash -c. If it references TARGET_URL, serve the
        target: a whole (multi-module) project if project_dir is set, else a
        single-file app — then substitute the live URL."""
        workdir = SANDBOX_ROOT / f"run_{int(time.time())}"
        workdir.mkdir(parents=True, exist_ok=True)
        server = None
        try:
            script = poc_code
            if "TARGET_URL" in script:
                served = None
                if project_dir and os.path.isdir(project_dir):
                    served = self._serve_project(project_dir, workdir)
                if served is None and target_code.strip():
                    served = self._serve_target(target_code, workdir)
                if served is not None:
                    server, url = served
                    script = script.replace("TARGET_URL", url)
            t0 = time.time()
            try:
                proc = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=True, text=True,
                    timeout=SANDBOX_TIMEOUT,
                    cwd=str(workdir),
                    env=_sandbox_env(str(workdir)),
                    preexec_fn=_sandbox_limits_shell,
                )
                elapsed = time.time() - t0
            except subprocess.TimeoutExpired:
                return SandboxResult(success=False, exit_code=-1, stdout="",
                                     stderr=f"TIMEOUT after {SANDBOX_TIMEOUT}s",
                                     elapsed=SANDBOX_TIMEOUT, error="timeout")
            stdout = proc.stdout[:MAX_OUTPUT_BYTES]
            stderr = proc.stderr[:MAX_OUTPUT_BYTES]
            has_marker = bool(SUCCESS_MARKERS.search(stdout))
            success = proc.returncode == 0 and has_marker
            return SandboxResult(success=success, exit_code=proc.returncode,
                                 stdout=stdout, stderr=stderr, elapsed=round(elapsed, 2))
        except Exception as e:
            return SandboxResult(success=False, exit_code=-1, stdout="", stderr=str(e),
                                 elapsed=0, error=str(e))
        finally:
            if server is not None:
                try:
                    server.terminate()
                    server.wait(timeout=3)
                except Exception:
                    pass
            try:
                import shutil
                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass

    def _execute_python(self, poc_code: str, target_code: str) -> SandboxResult:
        """Execute PoC against target code in sandbox venv."""
        # Write target code and PoC to temp files
        workdir = SANDBOX_ROOT / f"run_{int(time.time())}"
        workdir.mkdir(parents=True, exist_ok=True)

        try:
            # Write target module + PoC runner
            target_file = workdir / "target.py"
            target_file.write_text(target_code)

            runner_file = workdir / "run_poc.py"
            runner_code = self._build_runner(poc_code)
            runner_file.write_text(runner_code)

            # Execute
            t0 = time.time()
            try:
                proc = subprocess.run(
                    [self._python, str(runner_file)],
                    capture_output=True, text=True,
                    timeout=SANDBOX_TIMEOUT,
                    cwd=str(workdir),
                    env=_sandbox_env(str(workdir)),
                    preexec_fn=_sandbox_limits,
                )
                elapsed = time.time() - t0
            except subprocess.TimeoutExpired:
                return SandboxResult(
                    success=False, exit_code=-1,
                    stdout="", stderr=f"TIMEOUT after {SANDBOX_TIMEOUT}s",
                    elapsed=SANDBOX_TIMEOUT, error="timeout")

            stdout = proc.stdout[:MAX_OUTPUT_BYTES]
            stderr = proc.stderr[:MAX_OUTPUT_BYTES]

            # Check for success marker
            has_marker = bool(SUCCESS_MARKERS.search(stdout))
            success = proc.returncode == 0 and has_marker

            return SandboxResult(
                success=success, exit_code=proc.returncode,
                stdout=stdout, stderr=stderr,
                elapsed=round(elapsed, 2))

        except Exception as e:
            return SandboxResult(
                success=False, exit_code=-1,
                stdout="", stderr=str(e), elapsed=0, error=str(e))
        finally:
            # Cleanup (but keep on error for debugging)
            try:
                import shutil
                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass

    def _build_runner(self, poc_code: str) -> str:
        """Build a Python script that imports target + runs PoC."""
        return f'''#!/usr/bin/env python3
"""GSC PoF Sandbox Runner — auto-generated."""
import sys, os

# Add cwd to path
sys.path.insert(0, os.getcwd())

try:
    # Import target code
    import target
except Exception as e:
    print(f"IMPORT_ERROR: {{e}}", file=sys.stderr)
    sys.exit(1)

# Execute PoC
{poc_code}
'''


# ── Module-level API ──────────────────────────────────────────────

def verify_pof(
    finding: dict,
    vulnerable_code: str,
    patched_code: str,
    poc_code: str,
    project_dir: str | None = None,
    language: str = "python",
) -> FixVerification:
    """High-level API: verify a Proof-of-Fix through sandbox execution.

    Args:
        finding: GSC finding dict with rule_id, severity, etc.
        vulnerable_code: Original vulnerable code
        patched_code: LLM-generated fix
        poc_code: Generated PoC
        project_dir: Project root (for dependency install)
        language: python | javascript | go | rust

    Returns:
        FixVerification with verified=True only if PoC succeeds before fix
        and fails after fix.
    """
    fmt = (finding.get("metadata", {}) or {}).get("poc_format", "python")
    sandbox = PoFSandbox(project_dir)
    return sandbox.verify_fix(vulnerable_code, patched_code, poc_code, language, fmt=fmt)


if __name__ == "__main__":
    # Quick smoke test
    vuln = """
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect(':memory:')
    return conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall()
"""

    patched = """
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect(':memory:')
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
"""

    poc = """
import sqlite3
conn = sqlite3.connect(':memory:')
conn.execute('CREATE TABLE users (id INT, name TEXT)')
conn.execute("INSERT INTO users VALUES (1, 'admin')")
conn.execute("INSERT INTO users VALUES (2, 'user')")
result = target.get_user("1 OR 1=1")
assert len(result) == 2, f'Expected 2 rows, got {len(result)}'
print('EXPLOITED')
"""

    print("Testing PoF Sandbox...")
    sandbox = PoFSandbox()
    result = sandbox.verify_fix(vuln, patched, poc)
    print(f"  Verified: {result.verified}")
    print(f"  Reason: {result.reason}")
    if result.before:
        print(f"  Before: success={result.before.success} exit={result.before.exit_code} elapsed={result.before.elapsed}s")
        print(f"    stdout: {result.before.stdout[:200]}")
    if result.after:
        print(f"  After:  success={result.after.success} exit={result.after.exit_code} elapsed={result.after.elapsed}s")
