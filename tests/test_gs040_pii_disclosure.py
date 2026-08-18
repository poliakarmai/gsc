"""tests/test_gs040_pii_disclosure.py — positive/negative fixtures for GS040."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors.gs040_pii_disclosure import GS040PiiDisclosureDetector


@pytest.fixture()
def det():
    return GS040PiiDisclosureDetector()


def _ids(findings):
    return {f["rule_id"] for f in findings}


def test_email_disclosure(det):
    f = det.detect("app.py", 'ADMIN_EMAIL = "john.doe@company.com"\n')
    assert "GS040-pii_email" in _ids(f)


def test_email_placeholder_ignored(det):
    f = det.detect("app.py", 'contact = "test@example.com"\n')
    assert not f


def test_email_role_account_ignored(det):
    f = det.detect("app.py", 'x = "noreply@company.com"\n')
    assert not f


def test_secret_in_comment(det):
    f = det.detect("app.py", "# password: hunter2\n")
    assert "GS040-suspicious_comment" in _ids(f)


def test_comment_negative_ignored(det):
    f = det.detect("app.py", "# do not store password here\n")
    assert not f


def test_debug_token(det):
    f = det.detect("app.php", "XDEBUG_SESSION=phpstorm\n")
    assert "GS040-debug_token" in _ids(f)


def test_debug_artifact(det):
    f = det.detect("app.php", "adminer.php\n")
    assert "GS040-debug_token" in _ids(f)


def test_private_ip_in_config(det):
    f = det.detect(".env", "DB_HOST=10.0.0.5\n")
    assert "GS040-private_ip_config" in _ids(f)


def test_private_ip_in_url(det):
    f = det.detect(".env", "REDIS_URL=redis://192.168.1.10:6379\n")
    assert "GS040-private_ip_config" in _ids(f)


def test_private_ip_in_app_code_ignored(det):
    # private IP in application source is legitimate (service mesh / local net)
    f = det.detect("app.py", 'host = "10.0.0.5"\n')
    assert not f


def test_loopback_ignored(det):
    f = det.detect(".env", "DB_HOST=127.0.0.1\n")
    assert not f
