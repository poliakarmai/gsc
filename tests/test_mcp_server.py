"""Tests for the GSC MCP server (read-only security tools)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import gsc_mcp_server as gscm


def test_three_tools_registered():
    async def _run():
        tools = await gscm.mcp.list_tools()
        return {t.name for t in tools}
    names = asyncio.run(_run())
    assert {"scan_repo", "list_findings", "verify_finding"} <= names


def test_list_findings_returns_list():
    # Seed 1 finding в изолированную DB (conftest._isolate_gsc_db), чтобы тест был
    # самодостаточным, а не зависел от засеянной/порядка-тестов DB.
    from gsc_db import GSCDatabase
    db = GSCDatabase()
    db.execute(
        "INSERT INTO findings (project, echelon, category, title, file_path, "
        "line_number, detail, status, rule_id, pattern_title, finding_key) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("test", 1, "CRITICAL", "test finding", "/tmp/x.py", 1, "d",
         "open", "GS005", "test", "deadbeef1234"),
    )
    db.commit()
    db.close()

    async def _run():
        r = await gscm.mcp.call_tool("list_findings", {"limit": 2})
        content = getattr(r, "content", r)
        if isinstance(content, list):
            return "".join(getattr(c, "text", str(c)) for c in content)
        return str(content)
    out = asyncio.run(_run())
    assert "finding_key" in out or out.startswith("[") or "rule_id" in out


def test_severity_fallback_to_category():
    assert gscm._severity({"category": "MEDIUM"}) == "MEDIUM"
    assert gscm._severity({"severity": "HIGH"}) == "HIGH"
    assert gscm._severity({}) == "unknown"


def test_scan_repo_rejects_outside_roots(tmp_path, monkeypatch):
    # Path-guard должен сработать ДО запуска скана (без gsc_external).
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("GSC_ALLOWED_ROOTS", str(root))

    async def _run():
        r = await gscm.mcp.call_tool("scan_repo", {"repo_path": str(outside)})
        content = getattr(r, "content", r)
        if isinstance(content, list):
            return "".join(getattr(c, "text", str(c)) for c in content)
        return str(content)
    out = asyncio.run(_run())
    assert "outside allowed roots" in out
