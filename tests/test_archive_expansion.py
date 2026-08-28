#!/usr/bin/env python3
"""Tests for archive expansion in AuditContext (expand_archives / cleanup_archives).

Verifies the integration glue that wires gsc_core.gsc_archive into the scan
inventory: archives are expanded into a hidden dir inside the project, their
text files are added to ctx.files, archive_map records stable virtual names
(``arch!/inner``), and cleanup removes the extraction dir.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gsc_core.gsc_detectors import AuditContext  # noqa: E402


def _make_jar(root: Path) -> Path:
    jar = root / "lib" / "foo.jar"
    jar.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("application.properties", 'db.password = "MySuperSecret123"\n')
        zf.writestr("../evil.txt", "should be dropped\n")
    return jar


def test_expand_archives_extracts_text_files(tmp_path: Path) -> None:
    """A jar's inner text file lands in ctx.files; zip-slip entries are dropped;
    archive_map carries the virtual ``foo.jar!/application.properties`` name."""
    _make_jar(tmp_path)
    ctx = AuditContext(project="test", path=tmp_path)
    ctx.files = ctx.get_files()
    ctx.expand_archives()

    # The jar itself is non-code (excluded); the inner text file must be present.
    assert not any(p.suffix == ".jar" for p in ctx.files), "jar must stay excluded"
    extracted = [p for p in ctx.files if p.name == "application.properties"]
    assert extracted, "application.properties from the archive was not extracted"

    # archive_map must map the extracted file to a virtual archive-traceable name.
    virtuals = list(ctx.archive_map.values())
    assert any(v.endswith("foo.jar!/application.properties") for v in virtuals), virtuals

    # zip-slip entry must never be materialized.
    assert not any("evil.txt" in str(p) for p in ctx.files)

    # cleanup removes the extraction dir and clears the marker.
    tmpdir = ctx._archive_tmpdir
    assert tmpdir is not None and tmpdir.exists()
    ctx.cleanup_archives()
    assert not tmpdir.exists()


def test_expand_archives_no_archive_is_noop(tmp_path: Path) -> None:
    """No archive files -> no extraction dir, no archive_map entries."""
    (tmp_path / "plain.py").write_text("x = 1\n", encoding="utf-8")
    ctx = AuditContext(project="test", path=tmp_path)
    ctx.files = ctx.get_files()
    ctx.expand_archives()
    assert ctx._archive_tmpdir is None
    assert ctx.archive_map == {}


def test_expand_archives_idempotent(tmp_path: Path) -> None:
    """A second expand_archives call must not re-extract or duplicate files."""
    _make_jar(tmp_path)
    ctx = AuditContext(project="test", path=tmp_path)
    ctx.files = ctx.get_files()
    ctx.expand_archives()
    n_files = len(ctx.files)
    ctx.expand_archives()
    assert len(ctx.files) == n_files
    ctx.cleanup_archives()
