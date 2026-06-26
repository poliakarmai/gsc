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
        category: str = "MEDIUM",
        title: str = "",
        file_path: str = "",
        line_number: int = 0,
        detail: str = "",
        fix_suggestion: str = "",
        references: list[str] | None = None,
        **kwargs,
    ):
        super().__init__(
            rule_id=rule_id,
            category=category,
            title=title,
            file_path=file_path,
            line_number=line_number,
            detail=detail,
            fix_suggestion=fix_suggestion,
            references=references or [],
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

    # Glob patterns for files that are NEVER code (skip in all detectors)
    NON_CODE_GLOBS: tuple[str, ...] = (
        "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.webp",
        "*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
        "*.mp3", "*.mp4", "*.avi", "*.mov", "*.webm",
        "*.zip", "*.tar", "*.gz", "*.bz2", "*.7z",
        "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx",
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
        """Return all source files, optionally filtered by extension."""
        if not self.files:
            self.files = sorted(
                f for f in self.path.rglob("*")
                if f.is_file()
                and not any(p.startswith(".") for p in f.parts)
                and ".git/" not in str(f)
                and "node_modules/" not in str(f)
            )
        if extensions:
            return [f for f in self.files if f.suffix in extensions]
        return self.files

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


class Detector(Protocol):
    """Detector interface — mirrors CVE Lite's DetectorFn."""

    rule_id: str
    echelon: int

    def detect(self, ctx: AuditContext) -> list[Finding]: ...

    @property
    def description(self) -> str: ...
