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

    def _execute(self, poc_code: str, target_code: str, fmt: str = "python") -> SandboxResult:
        """Dispatch by PoC format (fix: curl/bash PoCs were run as Python → TypeError).

        fmt: 'python'/'py' → import target + run as Python;
             'curl'/'bash'/'shell'/'sh' → run via bash -c (secret-free env + limits).
        """
        fmt = (fmt or "python").lower()
        if fmt in ("curl", "bash", "shell", "sh"):
            return self._execute_shell(poc_code, target_code)
        return self._execute_python(poc_code, target_code)

    def _execute_shell(self, poc_code: str, target_code: str) -> SandboxResult:
        """Run a shell/curl PoC via bash -c in the same secret-free, limited env."""
        workdir = SANDBOX_ROOT / f"run_{int(time.time())}"
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            t0 = time.time()
            try:
                proc = subprocess.run(
                    ["bash", "-c", poc_code],
                    capture_output=True, text=True,
                    timeout=SANDBOX_TIMEOUT,
                    cwd=str(workdir),
                    env=_sandbox_env(str(workdir)),
                    preexec_fn=_sandbox_limits,
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
