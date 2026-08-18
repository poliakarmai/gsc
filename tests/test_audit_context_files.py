"""tests/test_audit_context_files.py — dotfile + special-name file collection.

Regression tests for the recall fix: get_files() must collect dotfiles
(.env, .git-credentials, .credentials) and suffix-less files (Dockerfile)
that Path.rglob("*") skips on Python >=3.11, while still pruning hidden dirs
and arbitrary dotfiles.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gsc_core.gsc_detectors import AuditContext


def _names(ctx):
    return {f.name for f in ctx.get_files()}


def test_collects_env_dotfile(tmp_path):
    (tmp_path / ".env").write_text("PASSWORD=1234\n")
    assert ".env" in _names(AuditContext(project="t", path=tmp_path))


def test_collects_secret_dotfiles(tmp_path):
    (tmp_path / ".git-credentials").write_text("x\n")
    (tmp_path / ".credentials").write_text("x\n")
    names = _names(AuditContext(project="t", path=tmp_path))
    assert ".git-credentials" in names
    assert ".credentials" in names


def test_skips_arbitrary_dotfile(tmp_path):
    (tmp_path / ".hidden.txt").write_text("x\n")
    assert ".hidden.txt" not in _names(AuditContext(project="t", path=tmp_path))


def test_collects_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("ENV X 1\n")
    assert "Dockerfile" in _names(AuditContext(project="t", path=tmp_path))


def test_skips_hidden_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x\n")
    (tmp_path / "app.py").write_text("x\n")
    ctx = AuditContext(project="t", path=tmp_path)
    rels = [str(f.relative_to(tmp_path)) for f in ctx.get_files()]
    assert "app.py" in rels
    assert not any(".git" in r for r in rels)


def test_extension_filter_matches_by_name(tmp_path):
    (tmp_path / "Dockerfile").write_text("x\n")
    (tmp_path / ".env").write_text("x\n")
    ctx = AuditContext(project="t", path=tmp_path)
    names = {f.name for f in ctx.get_files(extensions=(".env", "Dockerfile"))}
    assert "Dockerfile" in names
    assert ".env" in names


def test_source_files_include_env(tmp_path):
    (tmp_path / ".env").write_text("PASSWORD=1234\n")
    ctx = AuditContext(project="t", path=tmp_path)
    names = {f.name for f in ctx.get_source_files(extensions=(".env",))}
    assert ".env" in names
