"""GSC PoC Payload Mutator tests."""
from gsc_poc_mutator import mutate, adversarial_recheck


def test_mutate_excludes_original_and_empty():
    v = mutate("{{ 7 * 7 }}", "ssti")
    assert "{{ 7 * 7 }}" not in v
    assert "" not in v
    assert len(v) > 3  # generic + class-specific + alternates


def test_mutate_url_encoded_variant():
    v = mutate("{{ 7 * 7 }}", "ssti")
    assert any(s.startswith("%7B%7B") for s in v)  # full url-encode


def test_mutate_sql_obfuscation():
    v = mutate("' OR '1'='1", "sql_injection")
    assert "'/**/OR/**/'1'='1" in v   # whitespace → /**/
    assert "' or '1'='1" in v          # case swap
    assert any(s.islower() for s in v)


def test_mutate_path_traversal_encoding():
    v = mutate("../../etc/passwd", "path_traversal")
    assert any("%2f" in s or "%2e" in s for s in v)  # encoded traversal


def test_adversarial_recheck_detects_superficial_fix():
    # naive filter blocks only the exact "{{ 7 * 7 }}" payload, but not {{config}}
    def run_poc(p: str) -> bool:
        return p == "{{config}}"

    r = adversarial_recheck("{{ 7 * 7 }}", "ssti", run_poc)
    assert r["variants"] >= 1
    assert r["still_exploitable"] >= 1  # mutation bypasses the superficial fix
