# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""tests/test_dto_contract.py — DTO-консистентность (audit C-05).

Фиксирует контракт DTO находок, чтобы будущий дрейф ловился громко:

1. `make_finding` эмитит И канонические ключи (severity/file/line/snippet),
   И легаси-алиасы (category/file_path/line_number/detail) — downstream читает
   либо то, либо другое. Убрать одну половину = молча сломать другого потребителя.
2. `_normalize_finding` маппит ключи сканера → cloud-схему. Две копии
   (server.py / gsc_scan_worker.py) обязаны оставаться в синхроне — worker
   намеренно дублирует, чтобы не импортировать module-level state server.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gsc_core.gsc_detectors.base import make_finding
from gsc_cloud.gsc_scan_worker import _normalize_finding as worker_normalize
from gsc_cloud.server import _normalize_finding as server_normalize


def test_make_finding_emits_canonical_and_legacy_keys():
    f = make_finding("GS001", "t", "HIGH", 0.9, "a.py", 3, "secret = 'x'")
    assert f is not None
    # canonical
    assert f["severity"] == "HIGH"
    assert f["file"] == "a.py"
    assert f["line"] == 3
    assert f["snippet"].startswith("secret")
    # legacy aliases — equal to canonical
    assert f["category"] == f["severity"]
    assert f["file_path"] == f["file"]
    assert f["line_number"] == f["line"]
    assert f["detail"] == f["snippet"]


def test_make_finding_empty_rule_id_returns_none():
    assert make_finding("", "t", "LOW", 0.5, "a.py", 1, "x") is None


def test_normalize_finding_maps_scanner_to_cloud_schema():
    raw = {
        "finding_key": "k1", "rule_id": "GS001", "title": "t",
        "category": "HIGH",  # legacy-only: no severity key
        "file_path": "a.py", "line_number": 3, "detail": "leak",
    }
    for norm in (worker_normalize, server_normalize):
        n = norm(raw)
        assert n["severity"] == "HIGH"          # category → severity
        assert n["file"] == "a.py"              # file_path → file
        assert n["line"] == 3                   # line_number → line
        assert n["snippet"] == "leak"           # detail → snippet
        assert n["finding_key"] == "k1"
        assert n["rule_id"] == "GS001"


def test_normalize_finding_prefers_severity_over_category():
    raw = {"severity": "CRITICAL", "category": "LOW", "file_path": "b.py",
           "line_number": 1, "detail": "x"}
    for norm in (worker_normalize, server_normalize):
        assert norm(raw)["severity"] == "CRITICAL"


def test_server_and_worker_normalize_stay_in_sync():
    """Drift-guard: две копии _normalize_finding обязаны согласовываться."""
    raw = {
        "finding_key": "k2", "rule_id": "GS002", "title": "t",
        "severity": "MEDIUM", "confidence": 0.7,
        "file_path": "c.py", "line_number": 9, "detail": "snippet",
    }
    assert worker_normalize(raw) == server_normalize(raw)
