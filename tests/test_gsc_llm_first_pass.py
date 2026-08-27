# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the GSC LLM first-pass helpers (Phase 2 — LLM precision ladder).

Covers:
  * select_relevant_files: exclusion of binaries/images/archives/fonts/docs,
    lockfiles, vendored dirs, log files, minified/generated artefacts; sorting
    and input immutability.
  * build_first_pass_prompt: manifest → prompt, file count, no-LLM contract.
  * parse_first_pass_response: JSON + fenced + prose-wrapped parsing,
    schema validation, severity / line / confidence coercion, hallucinated
    path rejection, total-function error handling.
"""

import json

from gsc_cli.gsc_llm_first_pass import (
    SEVERITIES,
    build_first_pass_prompt,
    parse_first_pass_response,
    select_relevant_files,
)


# ── select_relevant_files ────────────────────────────────────────────────────


def test_select_relevant_files_basic():
    files = ["src/main.py", "README.md", "app.py"]
    assert select_relevant_files(files) == ["app.py", "src/main.py"]
    # README.md excluded (doc)


def test_select_relevant_files_excludes_binaries():
    files = ["a.py", "b.png", "c.jpg", "d.exe", "e.so", "f.dylib"]
    result = select_relevant_files(files)
    assert "a.py" in result
    assert not any(x in result for x in ["b.png", "c.jpg", "d.exe", "e.so", "f.dylib"])


def test_select_relevant_files_excludes_log_files():
    assert select_relevant_files(["app.log"]) == []
    assert select_relevant_files(["a.py", "app.log"]) == ["a.py"]


def test_select_relevant_files_excludes_lockfiles_by_basename():
    files = [
        "package-lock.json",
        "yarn.lock",
        "Cargo.lock",
        "go.sum",
        "poetry.lock",
        "composer.lock",
        "pipfile.lock",
    ]
    assert select_relevant_files(files) == []


def test_select_relevant_files_excludes_vendored_dirs():
    files = [
        "src/app.py",
        "vendor/lib/crypto.py",
        "node_modules/pkg/index.js",
        ".git/config",
        "target/debug/app",
        "build/generated.rs",
        "dist/bundle.js",
    ]
    result = select_relevant_files(files)
    assert result == ["src/app.py"]


def test_select_relevant_files_excludes_minified_and_maps():
    files = [
        "app.js",
        "app.min.js",
        "styles.css",
        "styles.min.css",
        "bundle.js.map",
    ]
    result = select_relevant_files(files)
    assert result == ["app.js", "styles.css"]


def test_select_relevant_files_excludes_images_archives_fonts_docs():
    files = [
        "x.py",
        "img.png", "img.jpg", "img.jpeg", "img.gif", "img.bmp",
        "img.webp", "img.svg",
        "a.zip", "b.gz", "c.tar", "d.tar.gz", "e.tgz", "f.bz2",
        "g.7z", "h.rar", "i.xz",
        "doc.pdf", "doc.doc", "doc.docx",
        "sheet.xls", "sheet.xlsx",
        "fnt.woff", "fnt.woff2", "fnt.ttf", "fnt.eot", "fnt.otf",
        "bytecode.class", "lib.jar", "lib.aar",
    ]
    result = select_relevant_files(files)
    assert result == ["x.py"]


def test_select_relevant_files_sorted():
    files = ["z.py", "a.py", "m.py"]
    result = select_relevant_files(files)
    assert result == ["a.py", "m.py", "z.py"]


def test_select_relevant_files_does_not_mutate_input():
    files = ["z.py", "a.py", "img.png"]
    original = list(files)
    select_relevant_files(files)
    assert files == original  # caller's list untouched


def test_select_relevant_files_empty():
    assert select_relevant_files([]) == []
    assert select_relevant_files(None) == [] or select_relevant_files(None) == []


def test_select_relevant_files_skips_non_string_entries():
    files = ["a.py", None, 42, b"b.py", "", "c.py"]
    result = select_relevant_files(files)
    assert result == ["a.py", "c.py"]


def test_select_relevant_files_keeps_venv_segment_name():
    # "venv" is a dir segment that should exclude, but "venv.py" is a file
    files = ["venv/run.py", "venv.py"]
    result = select_relevant_files(files)
    assert "venv.py" in result
    assert not any(f.endswith("run.py") for f in result)


# ── build_first_pass_prompt ─────────────────────────────────────────────────


def test_build_first_pass_prompt_contains_files():
    manifest = {"files": ["src/a.py", "src/b.py"]}
    prompt = build_first_pass_prompt(manifest)
    assert "src/a.py" in prompt
    assert "src/b.py" in prompt
    assert "count=2" in prompt


def test_build_first_pass_prompt_has_schema_contract():
    manifest = {"files": ["a.py"]}
    prompt = build_first_pass_prompt(manifest)
    # The instruction pins the required keys and severities.
    for key in ("rule", "title", "severity", "file_path", "line", "detail", "confidence"):
        assert key in prompt
    for sev in SEVERITIES:
        assert sev in prompt
    assert '"findings"' in prompt


def test_build_first_pass_prompt_no_prose_instructions():
    manifest = {"files": ["a.py"]}
    prompt = build_first_pass_prompt(manifest)
    # Must demand JSON-only reply.
    assert "Reply ONLY with valid JSON" in prompt
    assert "hallucinated paths" in prompt.lower()


def test_build_first_pass_prompt_empty_manifest():
    prompt = build_first_pass_prompt({})
    assert "count=0" in prompt
    assert isinstance(prompt, str)


def test_build_first_pass_prompt_non_dict_manifest():
    prompt = build_first_pass_prompt("not a dict")
    assert "count=0" in prompt


def test_build_first_pass_prompt_non_list_files():
    prompt = build_first_pass_prompt({"files": "a.py"})
    assert "count=0" in prompt


def test_build_first_pass_prompt_drops_non_string_files():
    manifest = {"files": ["a.py", None, 42, "b.py"]}
    prompt = build_first_pass_prompt(manifest)
    assert "a.py" in prompt
    assert "b.py" in prompt
    assert "None" not in prompt
    assert "count=2" in prompt


# ── parse_first_pass_response ───────────────────────────────────────────────


def test_parse_simple_json():
    resp = json.dumps({
        "findings": [
            {"rule": "secrets", "title": "Hardcoded key", "severity": "HIGH",
             "file_path": "src/a.py", "line": 42, "detail": "key in code",
             "confidence": 0.9},
        ]
    })
    out = parse_first_pass_response(resp, {"src/a.py"})
    assert len(out) == 1
    f = out[0]
    assert f["rule_id"] == "secrets"
    assert f["severity"] == "HIGH"
    assert f["file_path"] == "src/a.py"
    assert f["line"] == 42
    assert f["confidence"] == 0.9
    assert f["detail"] == "key in code"
    assert f["title"] == "Hardcoded key"


def test_parse_fenced_json():
    resp = '```json\n' + json.dumps({"findings": [
        {"rule": "xss", "title": "T", "severity": "LOW",
         "file_path": "a.js", "line": 1, "detail": "d", "confidence": 0.5}
    ]}) + '\n```'
    out = parse_first_pass_response(resp, {"a.js"})
    assert len(out) == 1
    assert out[0]["rule_id"] == "xss"


def test_parse_prose_wrapped_json():
    body = json.dumps({"findings": [
        {"rule": "ssrf", "title": "T", "severity": "CRITICAL",
         "file_path": "x.py", "line": 3, "detail": "d", "confidence": 0.95}
    ]})
    resp = "Here is my analysis:\n" + body + "\nThat's all."
    out = parse_first_pass_response(resp, {"x.py"})
    assert len(out) == 1
    assert out[0]["severity"] == "CRITICAL"


def test_parse_rejects_hallucinated_file_path():
    resp = json.dumps({"findings": [
        {"rule": "secrets", "title": "T", "severity": "HIGH",
         "file_path": "fake/missing.py", "line": 1, "detail": "d", "confidence": 0.8}
    ]})
    out = parse_first_pass_response(resp, {"src/a.py"})
    assert out == []


def test_parse_multiple_with_some_rejected():
    resp = json.dumps({"findings": [
        {"rule": "a", "title": "T1", "severity": "HIGH",
         "file_path": "a.py", "line": 1, "detail": "d1", "confidence": 0.9},
        {"rule": "b", "title": "T2", "severity": "LOW",
         "file_path": "ghost.py", "line": 2, "detail": "d2", "confidence": 0.4},
        {"rule": "c", "title": "T3", "severity": "MEDIUM",
         "file_path": "a.py", "line": 9, "detail": "d3", "confidence": 0.2},
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    assert len(out) == 2
    assert [f["title"] for f in out] == ["T1", "T3"]


def test_parse_severity_normalisation():
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "high", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.1},
        {"rule": "r", "title": "t", "severity": "BOGUS", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.1},
        {"rule": "r", "title": "t", "severity": None, "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.1},
        {"rule": "r", "title": "t", "severity": "critical", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.1},
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    sevs = [f["severity"] for f in out]
    assert sevs == ["HIGH", "INFO", "INFO", "CRITICAL"]


def test_parse_line_coercion():
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": "5", "detail": "d", "confidence": 0.1},
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": None, "detail": "d", "confidence": 0.1},
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": "abc", "detail": "d", "confidence": 0.1},
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "detail": "d", "confidence": 0.1},
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    lines = [f["line"] for f in out]
    assert lines == [5, 1, 1, 1]


def test_parse_confidence_clamp():
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 1.5},
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": -0.5},
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": "garbage"},
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": None},
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    confs = [f["confidence"] for f in out]
    assert confs == [1.0, 0.0, 0.0, 0.0]


def test_parse_rule_id_fallback():
    # ``rule`` missing, ``rule_id`` present
    resp = json.dumps({"findings": [
        {"rule_id": "GS123", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.5}
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    assert out[0]["rule_id"] == "GS123"


def test_parse_rule_id_unknown_when_missing():
    resp = json.dumps({"findings": [
        {"title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.5}
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    assert out[0]["rule_id"] == "UNKNOWN"


def test_parse_empty_json_findings():
    assert parse_first_pass_response('{"findings": []}', {"a.py"}) == []
    assert parse_first_pass_response('{"findings": [{}]}', {"a.py"}) == []  # missing file_path


def test_parse_non_dict_finding_skipped():
    resp = '{"findings": ["not a dict", 42, null]}'
    assert parse_first_pass_response(resp, {"a.py"}) == []


def test_parse_non_list_findings():
    resp = '{"findings": "oops"}'
    assert parse_first_pass_response(resp, {"a.py"}) == []


def test_parse_non_dict_root():
    resp = '[{"findings": []}]'
    assert parse_first_pass_response(resp, {"a.py"}) == []


def test_parse_empty_response():
    assert parse_first_pass_response("", {"a.py"}) == []
    assert parse_first_first_pass_response_none() or parse_first_pass_response("", {"a.py"}) == []


def parse_first_first_pass_response_none():
    return parse_first_pass_response(None, {"a.py"}) == []


def test_parse_broken_json():
    resp = '{"findings": [{"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": "1", "detail": "d", "confidence": 0.5}]}'
    # Truncated/broken
    broken = resp[:30]
    assert parse_first_pass_response(broken, {"a.py"}) == []


def test_parse_no_known_files():
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.5}
    ]})
    assert parse_first_pass_response(resp, set()) == []


def test_parse_known_files_as_list():
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.5}
    ]})
    out = parse_first_pass_response(resp, ["a.py"])
    assert len(out) == 1


def test_parse_output_keys():
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": "a.py", "line": 1, "detail": "d", "confidence": 0.5}
    ]})
    out = parse_first_pass_response(resp, {"a.py"})
    assert set(out[0].keys()) == {"rule_id", "title", "severity", "file_path", "line", "detail", "confidence"}


def test_parse_strips_whitespace_in_file_path():
    # file_path with surrounding whitespace still matches known_files (exact match after strip)
    resp = json.dumps({"findings": [
        {"rule": "r", "title": "t", "severity": "HIGH", "file_path": " a.py ", "line": 1, "detail": "d", "confidence": 0.5}
    ]})
    # Known files has clean path; stripped " a.py " → "a.py" should match
    out = parse_first_pass_response(resp, {"a.py"})
    assert len(out) == 1
