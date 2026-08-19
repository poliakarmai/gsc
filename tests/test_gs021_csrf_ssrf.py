# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""tests/test_gs021_csrf_ssrf.py — positive/negative fixtures for GS021.

Guards the GS021 precision pass:
- the `localhost|127.0.0.1|0.0.0.0` INFO pattern is removed (0 real TP — it
  fired on bind addresses / default args / docstrings / loopback comparisons);
- SSRF markers (AWS metadata) still fire;
- f-string URL requires a taint token inside `{...}`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs021_csrf_ssrf as gs021


@pytest.fixture()
def scan(tmp_path):
    def _scan(files):
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        ctx = AuditContext(project="test", path=tmp_path)
        return gs021.detect(ctx)
    return _scan


def _titles(fs):
    return [f["title"] for f in fs]


# ── SSRF localhost removal (precision) ───────────────────────────────────────

def test_localhost_reference_not_flagged(scan):
    # bind address / default arg — NOT SSRF
    fs = scan({"app.py": "app.run(host='127.0.0.1', port=5000)\n"})
    assert not any("localhost" in t.lower() for t in _titles(fs))


def test_aws_metadata_fires(scan):
    fs = scan({"app.py": "requests.get('http://169.254.169.254/latest/meta-data')\n"})
    assert any("AWS metadata" in t for t in _titles(fs))


def test_csrf_exempt_fires(scan):
    fs = scan({"views.py": "@csrf_exempt\ndef transfer(request):\n    pass\n"})
    assert any("@csrf_exempt" in t for t in _titles(fs))


# ── SSRF f-string URL taint (precision) ───────────────────────────────────────

def test_fstring_tainted_url_fires(scan):
    fs = scan({"app.py": "url = f\"https://{request.args['url']}\"\n"})
    assert any("f-string URL" in t for t in _titles(fs))


def test_fstring_untainted_url_not_flagged(scan):
    # config-derived base URL — not user input
    fs = scan({"app.py": "url = f\"https://{config.base_url}/api\"\n"})
    assert not any("f-string URL" in t for t in _titles(fs))


def test_http_request_to_variable_fires(scan):
    # indirect taint — kept (ambiguous, 3 TP on pygoat SSRF lab)
    fs = scan({"app.py": "import requests\nurl = request.args.get('url')\nrequests.get(url)\n"})
    assert any("HTTP request to a variable" in t for t in _titles(fs))
