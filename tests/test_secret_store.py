# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for the SecretStore (ported from openworker secrets.py)."""

import json

from gsc_core.gsc_secret_store import SecretStore


def test_put_get_roundtrip(tmp_path):
    s = SecretStore(tmp_path / "secrets.json")
    s.put("github:main", {"type": "token", "value": "ghp_secret"})
    assert s.get("github:main")["value"] == "ghp_secret"


def test_env_var_resolution(tmp_path, monkeypatch):
    monkeypatch.setenv("GSC_TEST_SECRET", "resolved-value")
    s = SecretStore(tmp_path / "secrets.json")
    s.put("x", {"value": "${GSC_TEST_SECRET}"})
    assert s.get("x")["value"] == "resolved-value"


def test_status_never_leaks_values(tmp_path):
    s = SecretStore(tmp_path / "secrets.json")
    s.put("github:main", {"type": "token", "value": "ghp_supersecret"})
    status = s.status()
    assert status[0]["profile"] == "github:main"
    assert "value" not in status[0]
    assert "ghp_supersecret" not in json.dumps(status)


def test_delete(tmp_path):
    s = SecretStore(tmp_path / "secrets.json")
    s.put("a", {"value": "1"})
    assert s.delete("a") is True
    assert s.get("a") is None


def test_file_mode_0600(tmp_path):
    p = tmp_path / "secrets.json"
    s = SecretStore(p)
    s.put("a", {"value": "1"})
    assert (p.stat().st_mode & 0o777) == 0o600


def test_missing_profile_returns_none(tmp_path):
    s = SecretStore(tmp_path / "secrets.json")
    assert s.get("nonexistent") is None
