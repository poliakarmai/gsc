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


# ── PII data-flow patterns (Bearer-inspired) ──────────────────────────────


def test_pii_in_log_email(det):
    f = det.detect("app.py", 'logger.info("user john.doe@company.com logged in")\n')
    assert "GS040-pii_in_log" in _ids(f)


def test_pii_in_log_credit_card(det):
    f = det.detect("app.py", 'logger.info("card 4111111111111111")\n')
    assert "GS040-pii_in_log" in _ids(f)


def test_pii_in_log_ssn(det):
    f = det.detect("app.js", 'console.log("ssn 123-45-6789")\n')
    assert "GS040-pii_in_log" in _ids(f)


def test_pii_to_third_party(det):
    f = det.detect(
        "app.py",
        'requests.post("https://api.example.com", '
        'json={"email": "john@company.com"})\n',
    )
    assert "GS040-pii_to_third_party" in _ids(f)


def test_log_without_pii_ignored(det):
    f = det.detect("app.py", 'logger.info("user logged in")\n')
    assert not f


def test_log_placeholder_email_ignored(det):
    f = det.detect("app.py", 'logger.info("test@example.com")\n')
    assert not f


def test_credit_card_without_keyword_ignored(det):
    f = det.detect("app.py", 'logger.info("id 4111111111111111")\n')
    assert not f


def test_ssn_wrong_format_ignored(det):
    f = det.detect("app.py", 'logger.info("id 123456789")\n')
    assert not f

