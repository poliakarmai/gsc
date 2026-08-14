"""tests/test_detector_registry.py — GSC roadmap 2.3: smoke-fixture для каждого детектора.

Каждый registry-детектор должен импортироваться, вызываться на минимальном
контексте и возвращать ``list`` (находки), не бросая исключение. Это минимальный
контракт работоспособности; full positive/negative fixtures — coverage matrix в
``detector_contract.json`` (генерация: ``scripts/gsc_detector_matrix.py``).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_detectors import AuditContext
from gsc_detectors.registry import get_detectors


@pytest.mark.parametrize("det", get_detectors(), ids=lambda d: d.rule_id)
def test_detector_smoke(det, tmp_path):
    ctx = AuditContext(project="smoke", path=tmp_path, file_contents={})
    if det.rule_id.startswith("YAML"):
        # YAML-rules: detect(file_path, content, language='auto')
        result = det.detect("smoke.py", "")
    else:
        try:
            result = det.detect(ctx)
        except TypeError:
            result = det.detect("", "")
    assert isinstance(result, list), f"{det.rule_id} detect() → {type(result).__name__}, ожидался list"
