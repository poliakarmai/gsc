"""Tests for the unified LLM provider layer (gsc_llm_providers)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import gsc_llm_providers as g


def _clean_env():
    for k in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY", "OLLAMA_BASE_URL",
              "LMSTUDIO_BASE_URL", "LLM_BASE_URL", "GSC_LLM_PROVIDERS"]:
        os.environ.pop(k, None)
    g.get_manager.cache_clear()


def test_no_providers_returns_empty(monkeypatch):
    _clean_env()
    monkeypatch.setattr(g, "_env_key", lambda name: "")
    assert g.build_providers_from_env() == []
    assert g.get_manager().chat("s", "u") is None


def test_deepseek_and_openrouter_and_ollama():
    _clean_env()
    os.environ["DEEPSEEK_API_KEY"] = "sk-deep"
    os.environ["OPENROUTER_API_KEY"] = "sk-or-deep"
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    providers = g.build_providers_from_env()
    names = [p.name for p in providers]
    assert names == ["deepseek", "openrouter", "ollama"]


def test_explicit_order():
    _clean_env()
    os.environ["DEEPSEEK_API_KEY"] = "sk-deep"
    os.environ["OPENROUTER_API_KEY"] = "sk-or-deep"
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    os.environ["GSC_LLM_PROVIDERS"] = "ollama,deepseek"
    names = [p.name for p in g.build_providers_from_env()]
    assert names == ["ollama", "deepseek"]


def test_failover_to_next_provider():
    class Boom:
        name = "deepseek"
        def chat(self, *a, **k):
            raise RuntimeError("down")

    class OK:
        name = "openrouter"
        def chat(self, *a, **k):
            return "hello"

    m = g.LLMProviderManager([Boom(), OK()])
    assert m.chat("s", "u") == "hello"
    assert m.active is not None and m.active.name == "openrouter"


def test_retry_active_then_succeed():
    attempts = {"n": 0}

    class Flaky:
        name = "deepseek"
        def chat(self, *a, **k):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise RuntimeError("transient")
            return "ok"

    m = g.LLMProviderManager([Flaky()])
    assert m.chat("s", "u") == "ok"
    assert attempts["n"] == 2


def test_all_fail_returns_none():
    class Boom:
        name = "deepseek"
        def chat(self, *a, **k):
            raise RuntimeError("down")

    m = g.LLMProviderManager([Boom()])
    assert m.chat("s", "u", retries=1) is None


def test_provider_builds_correct_url_and_headers(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": "hi"}}]}

    def fake_post(url, headers, json, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return FakeResp()

    monkeypatch.setattr(g, "requests", type("R", (), {"post": staticmethod(fake_post)}))
    p = g.LLMProvider("deepseek", "https://api.deepseek.com/v1", "deepseek-chat", "sk-x")
    out = p.chat("sys", "usr", max_tokens=123)
    assert out == "hi"
    assert captured["url"] == "https://api.deepseek.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk-x"
    assert captured["json"]["model"] == "deepseek-chat"
