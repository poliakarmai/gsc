"""Tests for GSC MCP auth + path scoping (gsc_cloud/gsc_mcp_auth.py)."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_cloud.gsc_mcp_auth import (
    GSCMCPAuth,
    allowed_roots,
    auth_configured,
    resolve_repo_path,
    resolve_token,
)


# ---------------------------------------------------------------------------
# allowed_roots / resolve_repo_path
# ---------------------------------------------------------------------------
def test_allowed_roots_empty_by_default(monkeypatch):
    monkeypatch.delenv("GSC_ALLOWED_ROOTS", raising=False)
    assert allowed_roots() == []


def test_allowed_roots_parses_comma_separated(monkeypatch, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    monkeypatch.setenv("GSC_ALLOWED_ROOTS", f"{a},{b}")
    assert allowed_roots() == [a.resolve(), b.resolve()]


def test_resolve_repo_path_empty():
    _, err = resolve_repo_path("")
    assert err == "empty repo_path"


def test_resolve_repo_path_not_a_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x")
    _, err = resolve_repo_path(str(f))
    assert err is not None and err.startswith("not a directory")


def test_resolve_repo_path_allows_dir(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    resolved, err = resolve_repo_path(str(d))
    assert err is None
    assert resolved == d.resolve()


def test_resolve_repo_path_rejects_outside_roots(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("GSC_ALLOWED_ROOTS", str(root))
    _, err = resolve_repo_path(str(outside))
    assert err is not None and "outside allowed roots" in err


def test_resolve_repo_path_allows_within_root(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    sub = root / "sub"
    sub.mkdir(parents=True)
    monkeypatch.setenv("GSC_ALLOWED_ROOTS", str(root))
    resolved, err = resolve_repo_path(str(sub))
    assert err is None
    assert resolved == sub.resolve()


def test_resolve_repo_path_resolves_symlink_escape(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    link.symlink_to(outside)
    monkeypatch.setenv("GSC_ALLOWED_ROOTS", str(root))
    _, err = resolve_repo_path(str(link))
    assert err is not None and "outside allowed roots" in err


# ---------------------------------------------------------------------------
# auth_configured / resolve_token
# ---------------------------------------------------------------------------
def test_auth_configured_false_by_default(monkeypatch):
    monkeypatch.delenv("GSC_MCP_TOKEN", raising=False)
    monkeypatch.delenv("GSC_DATABASE_URL", raising=False)
    assert auth_configured() is False


def test_auth_configured_true_on_static_token(monkeypatch):
    monkeypatch.setenv("GSC_MCP_TOKEN", "tok")
    monkeypatch.delenv("GSC_DATABASE_URL", raising=False)
    assert auth_configured() is True


def test_resolve_token_unconfigured_returns_none(monkeypatch):
    monkeypatch.delenv("GSC_MCP_TOKEN", raising=False)
    monkeypatch.delenv("GSC_DATABASE_URL", raising=False)
    assert resolve_token("anything") is None


def test_resolve_token_static_match(monkeypatch):
    monkeypatch.setenv("GSC_MCP_TOKEN", "sekret-token")
    monkeypatch.setenv("GSC_MCP_TENANT", "42")
    monkeypatch.delenv("GSC_DATABASE_URL", raising=False)
    assert resolve_token("sekret-token") == 42


def test_resolve_token_static_mismatch(monkeypatch):
    monkeypatch.setenv("GSC_MCP_TOKEN", "sekret-token")
    monkeypatch.delenv("GSC_DATABASE_URL", raising=False)
    assert resolve_token("wrong") is None


def test_resolve_token_static_default_tenant(monkeypatch):
    monkeypatch.setenv("GSC_MCP_TOKEN", "tok")
    monkeypatch.delenv("GSC_MCP_TENANT", raising=False)
    monkeypatch.delenv("GSC_DATABASE_URL", raising=False)
    assert resolve_token("tok") == 0


def test_resolve_token_empty(monkeypatch):
    monkeypatch.setenv("GSC_MCP_TOKEN", "tok")
    assert resolve_token("") is None


# ---------------------------------------------------------------------------
# GSCMCPAuth.verify_token
# ---------------------------------------------------------------------------
def test_verify_token_valid():
    auth = GSCMCPAuth(resolver=lambda t: 7 if t == "good" else None)
    tok = asyncio.run(auth.verify_token("good"))
    assert tok is not None
    assert tok.claims["tenant_id"] == 7
    assert "scan" in tok.scopes


def test_verify_token_invalid():
    auth = GSCMCPAuth(resolver=lambda t: None)
    assert asyncio.run(auth.verify_token("bad")) is None
