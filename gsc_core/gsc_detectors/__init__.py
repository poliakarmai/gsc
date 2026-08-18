# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Detector System — plugin architecture for security findings.

Inspired by OWASP CVE Lite CLI override detectors:
- Each detector = independent module with `detect(ctx) → Finding[]`
- Centralised `AuditContext` carries project state
- Registry maps detectors to echelons

Usage:
    from gsc_detectors import ALL_DETECTORS, AuditContext
    ctx = AuditContext(project="bybit-ws", path=Path("/home/.../bybit-ws"))
    for det in ALL_DETECTORS:
        findings.extend(det.detect(ctx))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol, Sequence


# ── Types ────────────────────────────────────────────────────────────────────

class Finding(dict):
    """Typed finding result. Backward-compatible with existing dict findings."""

    def __init__(
        self,
        rule_id: str,
        severity: str = "MEDIUM",
        title: str = "",
        file_path: str = "",
        line: int = 0,
        detail: str = "",
        fix_suggestion: str = "",
        references: list[str] | None = None,
        noise_tier: str = "normal",
        **kwargs,
    ):
        # Support both 'severity' and 'category' keys (backward compat)
        sev = kwargs.pop("category", severity)
        line_no = kwargs.pop("line_number", line)
        super().__init__(
            rule_id=rule_id,
            severity=sev,
            category=sev,
            title=title,
            file_path=file_path,
            line=line_no,
            line_number=line_no,
            detail=detail,
            fix_suggestion=fix_suggestion,
            references=references or [],
            noise_tier=noise_tier or "normal",
            **kwargs,
        )


@dataclass
class AuditContext:
    """Context passed to every detector — all project state in one place."""

    project: str
    path: Path                          # absolute project root

    # File inventory (lazy-loaded by detectors that need it)
    files: list[Path] = field(default_factory=list)
    file_contents: dict[str, str] = field(default_factory=dict)

    # Git info (for diff-mode)
    diff_files: list[str] | None = None
    diff_ranges: dict[str, list[tuple[int, int]]] | None = None

    # Known patterns from DB (for ref-based checks)
    known_patterns: list[dict] = field(default_factory=list)

    # Skipped detectors (avoid re-running)
    skipped_detectors: set[str] = field(default_factory=set)

    # ── File classification ───────────────────────────────────────────────

    # Files larger than this are skipped (prevents scans stalling on huge
    # data/models/media — e.g. 100MB+ static assets, 19MB text dumps).
    MAX_SCAN_FILE_SIZE: int = 1_000_000  # 1 MB

    # Directory names that are never source code (always skipped).
    SKIP_DIRS: tuple[str, ...] = (
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        "dist", "build", ".next", ".nuxt",
    )

    # Hidden files that are legitimate secret sources and MUST be scanned.
    # Hidden DIRECTORIES stay excluded (.git/.idea/.vscode are never code),
    # but .env / .credentials / .netrc / .bash_history hold the exact secrets
    # GS001/GS014/GS017/GS029 are meant to catch (dotfiles gap).
    SECRET_DOTFILES: frozenset[str] = frozenset({
        ".credentials", ".netrc", ".bash_history",
        ".pgpass", ".npmrc", ".pypirc", ".git-credentials",
    })

    # Glob patterns for files that are NEVER code (skip in all detectors)
    NON_CODE_GLOBS: tuple[str, ...] = (
        "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.webp",
        "*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
        "*.mp3", "*.mp4", "*.avi", "*.mov", "*.webm", "*.wav", "*.ogg",
        "*.zip", "*.tar", "*.gz", "*.bz2", "*.7z", "*.whl", "*.egg",
        "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
        "*.db", "*.sqlite", "*.sqlite3", "*.model", "*.onnx", "*.pt", "*.pth",
        "*.bin", "*.so", "*.dll", "*.dylib", "*.exe", "*.wasm",
        "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "*.min.js", "*.min.css", "*.map",
    )

    # Glob patterns that indicate test/demo files
    TEST_GLOBS: tuple[str, ...] = (
        "test_*.py", "*_test.py", "conftest.py",
        "*.test.js", "*.spec.js", "*.test.ts", "*.spec.ts",
        "*_test.go", "*_test.rs",
        "test_*.java", "*Test.java", "*Tests.java",
    )

    def is_test_file(self, filepath: Path) -> bool:
        """Check if file is a test/demo/fixture file."""
        name = filepath.name
        for g in self.TEST_GLOBS:
            if filepath.match(g):
                return True
        parts = filepath.parts
        return ("test" in parts or "tests" in parts or "fixtures" in parts
                or "__pycache__" in parts)

    def is_non_code_file(self, filepath: Path) -> bool:
        """Check if file is not source code (images, fonts, media, lockfiles)."""
        for g in self.NON_CODE_GLOBS:
            if filepath.match(g):
                return True
        return False

    def glob(self, pattern: str) -> list[Path]:
        """Return files matching glob relative to project root."""
        return sorted(self.path.glob(pattern))

    def get_files(self, extensions: Sequence[str] | None = None) -> list[Path]:
        """Return all source files, optionally filtered by extension.

        Pre-filter: skips hidden/skip dirs, non-code (binary/media/lock) files,
        and anything over MAX_SCAN_FILE_SIZE — so scans never stall on huge
        static assets, ML models, or multi-MB text dumps."""
        if not self.files:
            self.files = sorted(
                f for f in self.path.rglob("*")
                if f.is_file()
                and not any(p.startswith(".") for p in f.parts[:-1])
                and (not f.name.startswith(".")
                     or f.name.startswith(".env")
                     or f.name in self.SECRET_DOTFILES)
                and not any(d in f.parts for d in self.SKIP_DIRS)
                and ".git/" not in str(f)
                and not self.is_non_code_file(f)
                and self._within_size_limit(f)
            )
        if extensions:
            return [f for f in self.files if f.suffix in extensions]
        return self.files

    def _within_size_limit(self, filepath: Path) -> bool:
        """True if file is within MAX_SCAN_FILE_SIZE (files over the limit are
        skipped to keep scans fast; giant text/binary blobs never yield real
        findings and stall rg + Python fallback)."""
        try:
            return filepath.stat().st_size <= self.MAX_SCAN_FILE_SIZE
        except OSError:
            return False

    def get_source_files(self, extensions: Sequence[str] | None = None) -> list[Path]:
        """Return source files, excluding tests and non-code files."""
        files = self.get_files(extensions=extensions)
        return [f for f in files
                if not self.is_test_file(f) and not self.is_non_code_file(f)]

    def read_file(self, filepath: Path) -> str:
        """Read file content with caching."""
        key = str(filepath)
        if key not in self.file_contents:
            self.file_contents[key] = filepath.read_text(errors="replace")
        return self.file_contents[key]

    def get_disabled_patterns(self, rule_id: str) -> set[str]:
        """Get disabled pattern IDs for a rule (cached per scan).

        Used by GS005 decomposition — noisy patterns can be selectively
        disabled via pattern_status table without code changes.
        Falls back to empty set if DB unavailable or no pattern_status table.
        """
        if not hasattr(self, "_disabled_cache"):
            self._disabled_cache = {}
        if rule_id not in self._disabled_cache:
            try:
                import sqlite3
                db = sqlite3.connect(
                    str(Path.home() / ".hermes/state/gsc_audit.db"))
                rows = db.execute(
                    "SELECT pattern_id FROM pattern_status "
                    "WHERE rule_id=? AND enabled=0", (rule_id,)
                ).fetchall()
                db.close()
                self._disabled_cache[rule_id] = {r[0] for r in rows}
            except Exception:
                self._disabled_cache[rule_id] = set()
        return self._disabled_cache[rule_id]


class Detector(Protocol):
    """Detector interface — mirrors CVE Lite's DetectorFn."""

    rule_id: str
    echelon: int

    def detect(self, ctx: AuditContext) -> list[Finding]: ...

    @property
    def description(self) -> str: ...
