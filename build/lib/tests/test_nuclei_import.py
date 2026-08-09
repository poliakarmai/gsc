#!/usr/bin/env python3
"""tests/test_nuclei_import.py — nuclei import round-trip tests (+6)."""
import sys, os, tempfile, json
from pathlib import Path

os.chdir('/home/openclaw/gsc')
sys.path.insert(0, '.')

from gsc_nuclei_import import NucleiTemplate, import_nuclei_directory, list_templates
from gsc_dast_scanner import _parse_nuclei_output, _extract_evidence

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f'  ✅ {name}')
        passed += 1
    except Exception as e:
        print(f'  ❌ {name}: {e}')
        failed += 1


def t1():
    with tempfile.TemporaryDirectory() as d:
        yaml_file = Path(d) / "test.yaml"
        yaml_file.write_text("""id: cve-2024-1234
info:
  name: Test CVE
  severity: critical
  description: Test description
  tags: cve,rce

requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable"
    matchers:
      - type: word
        words:
          - "VULNERABLE"
""")
        template = NucleiTemplate.from_yaml(str(yaml_file))
        assert template is not None
        assert template.id == "cve-2024-1234"
        assert template.severity == "critical"
        assert "cve" in template.tags
        assert len(template.requests) == 1
        assert template.requests[0]["method"] == "GET"
test('parse nuclei YAML basic', t1)


def t2():
    with tempfile.TemporaryDirectory() as d:
        yaml_file = Path(d) / "test.yaml"
        yaml_file.write_text("""id: test-1
info:
  name: Test
  severity: high
  tags: "cve,misconfig"
requests:
  - method: GET
    path: ["{{BaseURL}}/"]
""")
        template = NucleiTemplate.from_yaml(str(yaml_file))
        assert template is not None
        assert template.tags == ["cve", "misconfig"]
test('tags as string normalised', t2)


def t3():
    with tempfile.TemporaryDirectory() as d:
        yaml_file = Path(d) / "test.yaml"
        yaml_file.write_text("not: valid: yaml: [")
        template = NucleiTemplate.from_yaml(str(yaml_file))
        assert template is None
test('invalid YAML → None', t3)


def t4():
    with tempfile.TemporaryDirectory() as d:
        for i in range(3):
            f = Path(d) / f"test{i}.yaml"
            f.write_text(f"""id: test-{i}
info:
  name: Test {i}
  severity: high
requests:
  - method: GET
    path: ["{{{{BaseURL}}}}/"]
""")
        stats = import_nuclei_directory(str(d))
        assert stats["imported"] == 3
        assert stats["skipped"] == 0

        templates = list_templates()
        assert len(templates) == 3
test('import 3 templates', t4)


def t5():
    with tempfile.TemporaryDirectory() as d:
        f1 = Path(d) / "test.yaml"
        f1.write_text("""id: test-1
info:
  name: Original
  severity: high
requests:
  - method: GET
    path: ["{{BaseURL}}/"]
""")
        # Isolated DB for true idempotency test
        import sqlite3
        iso_db = str(Path(d) / "iso.db")
        conn = sqlite3.connect(iso_db)
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INT)")
        conn.execute("INSERT INTO schema_version VALUES (28)")
        conn.execute("CREATE TABLE IF NOT EXISTS nuclei_templates (template_id TEXT PRIMARY KEY, name TEXT, severity TEXT, description TEXT, tags TEXT, requests TEXT, matchers TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS findings (finding_key TEXT PRIMARY KEY, rule_id TEXT, title TEXT, severity TEXT, confidence REAL, file TEXT, line INT, snippet TEXT)")
        conn.commit(); conn.close()
        import_nuclei_directory(str(d), db_path=iso_db)
        import_nuclei_directory(str(d), db_path=iso_db)  # duplicate
        templates = list_templates(db_path=iso_db)
        assert len(templates) == 1  # not duplicated
import pytest
test('idempotent import (xfail: shared DB state)', t5)


def t6():
    with tempfile.TemporaryDirectory() as d:
        jsonl = Path(d) / "results.jsonl"
        jsonl.write_text("""{"template-id":"cve-2024-1234","info":{"severity":"critical"},"matched-at":"https://target.com/vuln"}
{"template-id":"default-login","info":{"severity":"high"},"matched-at":"https://target.com/admin"}
""")
        findings = _parse_nuclei_output(str(jsonl), "https://target.com", None)
        assert len(findings) == 2
        assert findings[0]["template_id"] == "cve-2024-1234"
        assert findings[1]["severity"] == "high"
test('parse nuclei JSONL output', t6)


def t7():
    result = {"extracted-results": ["admin:password123"]}
    evidence = _extract_evidence(result)
    assert evidence == "admin:password123"

    result2 = {"matcher-status": "matched"}
    assert _extract_evidence(result2) == "matched"

    assert _extract_evidence({}) == ""
test('evidence extraction', t7)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
