"""GSC GS029 live-verify integration tests (Фаза 8)."""
from gsc_core.gsc_detectors.gs029_secrets import GS029SecretsDetector


def _detector():
    return GS029SecretsDetector()


def test_gs029_live_verify_dead(monkeypatch):
    import gsc_secrets_verifier as SV
    monkeypatch.setattr(SV, "verify_secret",
                        lambda v, p=None: {"provider": "github", "status": "dead", "fingerprint": "x"})
    fs = _detector().detect("app.py", 'API_KEY = "ghp_dead_token_123"\n', verify_live=True)
    assert len(fs) == 1
    assert fs[0]["confidence"] <= 0.3
    assert fs[0]["severity"] == "INFO"  # dead → не CRITICAL/HIGH
    assert fs[0]["metadata"]["secrets"]["status"] == "dead"
    assert fs[0]["metadata"]["secrets"]["provider"] == "github"


def test_gs029_live_verify_live_keeps_confidence(monkeypatch):
    import gsc_secrets_verifier as SV
    monkeypatch.setattr(SV, "verify_secret",
                        lambda v, p=None: {"provider": "github", "status": "live", "fingerprint": "x"})
    fs = _detector().detect("app.py", 'API_KEY = "ghp_live_token_123"\n', verify_live=True)
    assert len(fs) == 1
    assert fs[0]["confidence"] == 0.85  # live → не трогаем
    assert "status" not in fs[0]["metadata"]["secrets"]


def test_gs029_no_verify_by_default(monkeypatch):
    import gsc_secrets_verifier as SV
    monkeypatch.setattr(SV, "verify_secret", lambda v, p=None: (_ for _ in ()).throw(AssertionError("should not call")))
    fs = _detector().detect("app.py", 'API_KEY = "ghp_dead_token_123"\n')  # default off
    assert len(fs) == 1
    assert fs[0]["confidence"] == 0.85
    assert "status" not in fs[0]["metadata"]["secrets"]


def test_gs029_env_flag_enables(monkeypatch):
    import gsc_secrets_verifier as SV
    monkeypatch.setenv("GSC_VERIFY_SECRETS", "1")
    monkeypatch.setattr(SV, "verify_secret",
                        lambda v, p=None: {"provider": "github", "status": "dead", "fingerprint": "x"})
    fs = _detector().detect("app.py", 'API_KEY = "ghp_dead_token_123"\n')  # env-флаг включает
    assert fs[0]["metadata"]["secrets"]["status"] == "dead"
    assert fs[0]["confidence"] <= 0.3
