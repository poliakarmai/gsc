"""tests/test_gs046_cpp.py — positive/negative fixtures for GS046 (C/C++ SAST).

Coverage:
  - All 9 pattern_id positives fire on a representative C/C++ snippet
  - Clean C/C++ code produces no findings
  - Non-C/C++ files (.go, .py) are ignored (extension gate)
  - Tests/vendor/third_party/build/extern paths are excluded
  - printf(IDENT) fires, printf("literal") does not
  - scanf with width specifier (%49s) is safe; bare %s is not
  - finding schema: finding_key/rule_id/severity/line_number/snippet
  - detect(ctx) returns list[dict]
  - Multi-line files produce N findings with correct line numbers
  - Detector module contains no Cyrillic (except SPDX copyright)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs046_cpp as g


def _run(tmp_path: Path) -> list[dict]:
    """Run detect(ctx) over tmp_path."""
    ctx = AuditContext(project="t", path=tmp_path)
    ctx.files = ctx.get_files()
    return g.detect(ctx)


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


def _run_direct(file_path: str, content: str) -> list[dict]:
    """Call detect(file_path, content) directly (bypasses ctx)."""
    return g.GS046CppDetector().detect(file_path, content)


# ── Positives: each of the 9 patterns must fire on a representative C snippet


def test_strcpy_detected(tmp_path):
    (tmp_path / "main.c").write_text(
        "#include <string.h>\n"
        "void f(char *src) {\n"
        "    char dst[64];\n"
        "    strcpy(dst, src);\n"
        "}\n"
    )
    findings = _run(tmp_path)
    assert "GS046-strcpy_buffer_overflow" in _rule_ids(findings)


def test_strcat_detected(tmp_path):
    (tmp_path / "a.c").write_text(
        "#include <string.h>\n"
        "void f(char *a, char *b) {\n"
        "    strcat(a, b);\n"
        "}\n"
    )
    assert "GS046-strcat_buffer_overflow" in _rule_ids(_run(tmp_path))


def test_gets_detected_critical(tmp_path):
    (tmp_path / "b.c").write_text(
        "#include <stdio.h>\n"
        "void f() {\n"
        "    char buf[64];\n"
        "    gets(buf);\n"
        "}\n"
    )
    findings = _run(tmp_path)
    rule = "GS046-gets_unsafe"
    assert rule in _rule_ids(findings)
    f = next(x for x in findings if x["rule_id"] == rule)
    assert f["severity"] == "CRITICAL"
    assert f["confidence"] >= 0.9


def test_sprintf_detected(tmp_path):
    (tmp_path / "c.c").write_text(
        "#include <stdio.h>\n"
        "void f(char *x) {\n"
        "    char buf[64];\n"
        "    sprintf(buf, \"%s\", x);\n"
        "}\n"
    )
    assert "GS046-sprintf_overflow" in _rule_ids(_run(tmp_path))


def test_vsprintf_detected(tmp_path):
    (tmp_path / "d.c").write_text(
        "#include <stdarg.h>\n"
        "void f(char *buf, char *fmt, va_list ap) {\n"
        "    vsprintf(buf, fmt, ap);\n"
        "}\n"
    )
    findings = _run(tmp_path)
    assert "GS046-vsprintf_overflow" in _rule_ids(findings)


def test_scanf_no_bounds_detected(tmp_path):
    (tmp_path / "e.c").write_text(
        "#include <stdio.h>\n"
        "void f() {\n"
        "    char buf[64];\n"
        "    scanf(\"%s\", buf);\n"
        "}\n"
    )
    assert "GS046-scanf_no_bounds" in _rule_ids(_run(tmp_path))


def test_scanf_with_width_is_safe(tmp_path):
    (tmp_path / "safe.c").write_text(
        "#include <stdio.h>\n"
        "void f() {\n"
        "    char buf[64];\n"
        "    scanf(\"%49s\", buf);\n"
        "}\n"
    )
    assert "GS046-scanf_no_bounds" not in _rule_ids(_run(tmp_path))


def test_printf_format_string_detected(tmp_path):
    (tmp_path / "fmt.c").write_text(
        "#include <stdio.h>\n"
        "void f(char *user) {\n"
        "    printf(user);\n"
        "}\n"
    )
    assert "GS046-printf_format_string" in _rule_ids(_run(tmp_path))


def test_printf_with_literal_is_safe(tmp_path):
    (tmp_path / "ok.c").write_text(
        "#include <stdio.h>\n"
        "void f(int x) {\n"
        "    printf(\"hello %d\\n\", x);\n"
        "}\n"
    )
    assert "GS046-printf_format_string" not in _rule_ids(_run(tmp_path))


def test_printf_through_fprintf_is_safe(tmp_path):
    # fprintf/sprintf/snprintf are NOT printf — they are explicitly handled
    # by their own rules or are safe by construction. printf_format_string
    # must NOT match fprintf.
    (tmp_path / "log.c").write_text(
        "#include <stdio.h>\n"
        "void f(char *msg) {\n"
        "    fprintf(stderr, \"err: %s\\n\", msg);\n"
        "}\n"
    )
    assert "GS046-printf_format_string" not in _rule_ids(_run(tmp_path))


def test_system_detected(tmp_path):
    (tmp_path / "sys.c").write_text(
        "#include <stdlib.h>\n"
        "void f(char *cmd) {\n"
        "    system(cmd);\n"
        "}\n"
    )
    findings = _run(tmp_path)
    rule = "GS046-system_command_injection"
    assert rule in _rule_ids(findings)
    f = next(x for x in findings if x["rule_id"] == rule)
    assert f["severity"] == "CRITICAL"


def test_popen_detected(tmp_path):
    (tmp_path / "pop.c").write_text(
        "#include <stdio.h>\n"
        "void f(char *cmd) {\n"
        "    FILE *p = popen(cmd, \"r\");\n"
        "}\n"
    )
    assert "GS046-popen_command_injection" in _rule_ids(_run(tmp_path))


# ── Negatives (must NOT fire)


def test_clean_c_not_flagged(tmp_path):
    (tmp_path / "clean.c").write_text(
        "#include <string.h>\n"
        "#include <stdio.h>\n"
        "void f(char *src, size_t n) {\n"
        "    char dst[64];\n"
        "    memcpy(dst, src, n);\n"
        "    int x = n + 1;\n"
        "    fprintf(stdout, \"x=%d\\n\", x);\n"
        "}\n"
    )
    assert _run(tmp_path) == []


def test_clean_cpp_not_flagged(tmp_path):
    (tmp_path / "clean.cpp").write_text(
        "#include <string>\n"
        "#include <iostream>\n"
        "void f() {\n"
        "    std::string s = \"hello\";\n"
        "    std::cout << s << std::endl;\n"
        "    int x = 1 + 2;\n"
        "}\n"
    )
    assert _run(tmp_path) == []


def test_go_file_ignored(tmp_path):
    # GS038 owns .go. GS046 must not fire on Go code.
    (tmp_path / "main.go").write_text(
        "package main\n"
        "func main() {}\n"
    )
    assert _run(tmp_path) == []


def test_python_file_ignored(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\ndef f(x):\n    os.system(x)\n"
    )
    assert _run(tmp_path) == []


def test_vendor_path_excluded(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.c").write_text(
        "#include <string.h>\n"
        "void f(char *s) { char b[8]; strcpy(b, s); }\n"
    )
    assert _run(tmp_path) == []


def test_third_party_excluded(tmp_path):
    (tmp_path / "third_party").mkdir()
    (tmp_path / "third_party" / "json.c").write_text(
        "void f() { char b[8]; gets(b); }\n"
    )
    assert _run(tmp_path) == []


def test_extern_excluded(tmp_path):
    (tmp_path / "extern").mkdir()
    (tmp_path / "extern" / "foo.c").write_text(
        "void f(char *s) { char b[8]; strcpy(b, s); }\n"
    )
    assert _run(tmp_path) == []


def test_build_dist_excluded(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.c").write_text(
        "void f() { char b[8]; gets(b); }\n"
    )
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.c").write_text(
        "void f() { system(\"x\"); }\n"
    )
    assert _run(tmp_path) == []


def test_test_file_suffix_excluded(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "strcpy_test.c").write_text(
        "void f() { strcpy(b, s); }\n"
    )
    (tmp_path / "src" / "strcpy_test.cpp").write_text(
        "void f() { strcpy(b, s); }\n"
    )
    assert _run(tmp_path) == []


def test_tests_dir_excluded(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_unsafe.c").write_text(
        "void f() { char b[8]; gets(b); }\n"
    )
    assert _run(tmp_path) == []


# ── Schema & contract


def test_finding_schema_fields(tmp_path):
    (tmp_path / "x.c").write_text(
        "void f(char *s) { char b[8]; strcpy(b, s); }\n"
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    for key in ("finding_key", "rule_id", "severity", "line_number", "snippet"):
        assert key in f, f"missing key: {key}"
    assert f["rule_id"].startswith("GS046-")
    assert isinstance(f["line_number"], int) and f["line_number"] >= 1
    assert isinstance(f["finding_key"], str) and len(f["finding_key"]) == 12
    assert f["metadata"]["detector"] == "GS046"


def test_finding_key_is_sha256_prefix(tmp_path):
    # finding_key must be deterministic: same rule+file+snippet → same key.
    (tmp_path / "k.c").write_text("void f() { char b[8]; gets(b); }\n")
    a = _run(tmp_path)
    (tmp_path / "k.c").write_text("void f() { char b[8]; gets(b); }\n")
    b = _run(tmp_path)
    assert a and b
    assert a[0]["finding_key"] == b[0]["finding_key"]


def test_detect_returns_list_for_ctx(tmp_path):
    (tmp_path / "ok.c").write_text("int main() { return 0; }\n")
    result = _run(tmp_path)
    assert isinstance(result, list)


def test_detect_returns_list_via_class_api():
    # Direct detector API: detect(file_path, content) without ctx.
    result = _run_direct("main.c", "void f() { gets(b); }")
    assert isinstance(result, list)
    assert any(x["rule_id"] == "GS046-gets_unsafe" for x in result)


def test_multiple_findings_correct_line_numbers(tmp_path):
    src = (
        "#include <string.h>\n"          # line 1
        "#include <stdio.h>\n"           # line 2
        "#include <stdlib.h>\n"          # line 3
        "void f(char *s) {\n"            # line 4
        "    char b[8];\n"               # line 5
        "    strcpy(b, s);\n"            # line 6  → strcpy_buffer_overflow
        "    strcat(b, s);\n"            # line 7  → strcat_buffer_overflow
        "    gets(b);\n"                 # line 8  → gets_unsafe
        "    sprintf(b, \"%s\", s);\n"    # line 9  → sprintf_overflow
        "    system(s);\n"               # line 10 → system_command_injection
        "}\n"                            # line 11
    )
    (tmp_path / "multi.c").write_text(src)
    findings = _run(tmp_path)
    by_rule = {f["rule_id"]: f["line_number"] for f in findings}
    assert by_rule["GS046-strcpy_buffer_overflow"] == 6
    assert by_rule["GS046-strcat_buffer_overflow"] == 7
    assert by_rule["GS046-gets_unsafe"] == 8
    assert by_rule["GS046-sprintf_overflow"] == 9
    assert by_rule["GS046-system_command_injection"] == 10


def test_cpp_extension_h_detected(tmp_path):
    # .h and .hpp are also C/C++ source extensions.
    (tmp_path / "api.h").write_text(
        "void f(char *s) { char b[8]; strcpy(b, s); }\n"
    )
    (tmp_path / "api.hpp").write_text(
        "void f(char *s) { char b[8]; strcpy(b, s); }\n"
    )
    findings = _run(tmp_path)
    rule = "GS046-strcpy_buffer_overflow"
    paths = {f["file_path"] for f in findings if f["rule_id"] == rule}
    assert "api.h" in paths
    assert "api.hpp" in paths


# ── Module hygiene


def test_no_cyrillic_in_module():
    """The detector module must contain no Cyrillic text (only ASCII or
    the SPDX copyright header is allowed)."""
    mod_path = Path(g.__file__)
    text = mod_path.read_text(encoding="utf-8")
    # Strip the SPDX header line containing the author name (a single
    # Cyrillic substring is intentional and documented).
    lines = text.splitlines()
    non_spdx = "\n".join(
        ln for ln in lines if "Алексей Поляков" not in ln
    )
    cyrillic_count = sum(1 for ch in non_spdx if "Ѐ" <= ch <= "ӿ")
    assert cyrillic_count == 0, (
        f"Unexpected Cyrillic in module body: "
        f"{[ch for ch in non_spdx if 'Ѐ' <= ch <= 'ӿ'][:20]}"
    )


def test_module_constants():
    """Module-level RULE_ID/ECHELON/NOISE_TIER/description must match the
    registry contract (Echelon 1, sensitive noise tier, no LLM)."""
    assert g.RULE_ID == "GS046"
    assert g.ECHELON == 1
    assert g.NOISE_TIER == "sensitive"
    assert g.description.startswith("GS046:")
    assert g.GS046CppDetector.rule_id == "GS046"
    assert g.GS046CppDetector.requires_llm is False


def test_substring_function_names_not_flagged():
    """User-defined names that contain a target function as a substring
    (mystrcpy, fpopen, _system) must NOT fire — the negative lookbehind
    requires a non-identifier char before the function name."""
    content = (
        "int mystrcpy(char *d, const char *s);\n"
        "FILE *fpopen(const char *p, const char *m);\n"
        "int _system(const char *c);\n"
        "int my_sprintf(char *b, const char *f, ...);\n"
    )
    assert _run_direct("main.c", content) == []
