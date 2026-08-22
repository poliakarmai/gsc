"""GSC Secrets Verifier tests (Фаза 8, offline — HTTP mocked)."""
import urllib.error
import gsc_secrets_verifier as SV


class _Resp:
    def __init__(self, status, body=""):
        self.status = status
        self._body = body.encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_detect_provider():
    assert SV.detect_provider("ghp_abc123") == "github"
    assert SV.detect_provider("xoxb-123") == "slack"
    assert SV.detect_provider("sk_live_abc") == "stripe"
    assert SV.detect_provider("AKIA1234567890ABCDEF") == "aws"
    assert SV.detect_provider("postgres://u:p@h/db") == "db"
    assert SV.detect_provider("random") == "unknown"


def test_verify_github_live(monkeypatch):
    monkeypatch.setattr(SV, "urlopen", lambda req, timeout: _Resp(200, "{}"))
    assert SV.verify_secret("ghp_live_token", "github")["status"] == "live"


def test_verify_github_dead(monkeypatch):
    def _err(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)
    monkeypatch.setattr(SV, "urlopen", _err)
    assert SV.verify_secret("ghp_dead_token", "github")["status"] == "dead"


def test_verify_slack_dead(monkeypatch):
    monkeypatch.setattr(SV, "urlopen",
                        lambda req, timeout: _Resp(200, '{"ok":false,"error":"invalid_auth"}'))
    assert SV.verify_secret("xoxb-dead", "slack")["status"] == "dead"


def test_verify_cache(monkeypatch):
    calls = {"n": 0}

    def _counting(req, timeout):
        calls["n"] += 1
        return _Resp(200, "{}")

    monkeypatch.setattr(SV, "urlopen", _counting)
    SV._CACHE.clear()
    r1 = SV.verify_secret("ghp_cached", "github")
    r2 = SV.verify_secret("ghp_cached", "github")
    assert r1["status"] == "live"
    assert r2["cached"] is True
    assert calls["n"] == 1  # второй вызов из кэша, без сети


def test_deboost_dead(monkeypatch):
    monkeypatch.setattr(SV, "urlopen",
                        lambda req, timeout: _Resp(401, ""))
    SV._CACHE.clear()
    findings = [{"value": "ghp_fake1", "confidence": 0.9, "metadata": {}},
                {"value": "ghp_fake2", "confidence": 0.9, "metadata": {}}]
    n = SV.deboost_dead(findings)
    assert n == 2
    for f in findings:
        assert f["metadata"]["secret_status"] == "dead"
        assert f["confidence"] <= 0.3
