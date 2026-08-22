"""GSC Secrets Verifier tests (Фаза 8, offline — _http mocked)."""
import gsc_secrets_verifier as SV


def test_detect_provider():
    assert SV.detect_provider("ghp_abc123") == "github"
    assert SV.detect_provider("github_pat_abc") == "github"
    assert SV.detect_provider("xoxb-123") == "slack"
    assert SV.detect_provider("sk_live_abc") == "stripe"
    assert SV.detect_provider("AKIA1234567890ABCDEF") == "aws"
    assert SV.detect_provider("postgres://u:p@h/db") == "db"
    assert SV.detect_provider("random") == "unknown"
    # non-verifiable prefixes → unknown (verdict судьи)
    assert SV.detect_provider("ghs_123") == "unknown"
    assert SV.detect_provider("xoxa-123") == "unknown"


def test_is_test_key():
    assert SV.is_test_key("sk_test_abc")
    assert SV.is_test_key("rk_test_abc")
    assert SV.is_test_key("ASIA123")
    assert not SV.is_test_key("sk_live_abc")
    assert not SV.is_test_key("ghp_abc")


def test_verify_github_live(monkeypatch):
    monkeypatch.setattr(SV, "_http", lambda m, u, h: (200, "{}"))
    SV._CACHE.clear()
    assert SV.verify_secret("ghp_live_token", "github")["status"] == "live"


def test_verify_github_dead(monkeypatch):
    monkeypatch.setattr(SV, "_http", lambda m, u, h: (401, ""))
    SV._CACHE.clear()
    assert SV.verify_secret("ghp_dead_token", "github")["status"] == "dead"


def test_verify_github_403_unknown(monkeypatch):
    # 403 = rate-limit/SAML → НЕ dead (verdict судьи)
    monkeypatch.setattr(SV, "_http", lambda m, u, h: (403, '{"message":"API rate limit"}'))
    SV._CACHE.clear()
    assert SV.verify_secret("ghp_ratelimited", "github")["status"] == "unknown"


def test_verify_slack_dead(monkeypatch):
    monkeypatch.setattr(SV, "_http",
                        lambda m, u, h: (200, '{"ok":false,"error":"invalid_auth"}'))
    SV._CACHE.clear()
    assert SV.verify_secret("xoxb-dead", "slack")["status"] == "dead"


def test_verify_slack_missing_scope_unknown(monkeypatch):
    # missing_scope = токен жив, проба неуместна → НЕ dead (verdict судьи)
    monkeypatch.setattr(SV, "_http",
                        lambda m, u, h: (200, '{"ok":false,"error":"missing_scope"}'))
    SV._CACHE.clear()
    assert SV.verify_secret("xoxb-missingscope", "slack")["status"] == "unknown"


def test_verify_cache_dead(monkeypatch):
    calls = {"n": 0}

    def _counting(m, u, h):
        calls["n"] += 1
        return (401, "")

    monkeypatch.setattr(SV, "_http", _counting)
    SV._CACHE.clear()
    r1 = SV.verify_secret("ghp_cached_dead", "github")
    r2 = SV.verify_secret("ghp_cached_dead", "github")
    assert r1["status"] == "dead"
    assert r2["cached"] is True
    assert calls["n"] == 1  # dead кэшируется


def test_verify_live_not_cached(monkeypatch):
    calls = {"n": 0}

    def _counting(m, u, h):
        calls["n"] += 1
        return (200, "{}")

    monkeypatch.setattr(SV, "_http", _counting)
    SV._CACHE.clear()
    SV.verify_secret("ghp_live_uncached", "github")
    SV.verify_secret("ghp_live_uncached", "github")
    assert calls["n"] == 2  # live/unknown/error не кэшируются


def test_deboost_dead(monkeypatch):
    monkeypatch.setattr(SV, "_http", lambda m, u, h: (401, ""))
    SV._CACHE.clear()
    findings = [{"value": "ghp_fake1", "confidence": 0.9, "severity": "HIGH", "metadata": {}},
                {"value": "ghp_fake2", "confidence": 0.9, "severity": "CRITICAL", "metadata": {}}]
    n = SV.deboost_dead(findings)
    assert n == 2
    for f in findings:
        assert f["metadata"]["secret_status"] == "dead"
        assert f["confidence"] <= 0.3
        assert f["severity"] == "INFO"
