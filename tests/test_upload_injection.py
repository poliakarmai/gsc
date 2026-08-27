# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for YAML-UPLOAD001 — Insecure File Upload detector."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_core.gsc_detectors.yaml_rules import upload_injection as upload
from gsc_core.gsc_detectors.yaml_rules.upload_injection import (
    RULE_ID,
    ECHELON,
    NOISE_TIER,
    description,
    detector,
    detect,
)


# ── Metadata ────────────────────────────────────────────────────────────────

def test_rule_id_is_upload001():
    assert RULE_ID == "YAML-UPLOAD001"


def test_echelon_and_noise_tier():
    assert ECHELON == 2
    assert NOISE_TIER == "precise"


def test_description_mentions_rce():
    # description is a single string and must explain File Upload → RCE.
    assert isinstance(description, str)
    assert "upload" in description.lower()
    assert "rce" in description.lower() or "code execution" in description.lower()


def test_detector_severity_and_confidence():
    assert detector.severity == "HIGH"
    assert 0.0 < detector.confidence <= 1.0
    assert detector.rule_id == RULE_ID


def test_patterns_count_at_least_ten():
    # The detector must have at least 10 patterns per the design spec.
    assert len(detector._compiled) >= 10


def test_every_pattern_has_title():
    # Every (regex, title) pair must have a non-empty title.
    for pattern, title in detector._compiled:
        assert title, f"pattern {pattern.pattern!r} is missing a human title"


# ── True-positive cases per language / framework ────────────────────────────

def test_flask_request_files_indexed_save():
    # Pattern 1: request.files["x"].save(...)
    content = 'request.files["file"].save("/uploads/x")\n'
    findings = detect("app.py", content, "python")
    assert findings, "expected a finding for request.files[...].save()"
    assert findings[0]["rule_id"] == "YAML-UPLOAD001"
    assert findings[0]["severity"] == "HIGH"
    assert "Flask" in findings[0]["title"]


def test_flask_request_files_get_raw_access():
    # Pattern 2: request.files.get(...) — raw access, save is on a later line
    content = 'f = request.files.get("avatar")\n'
    findings = detect("app.py", content, "python")
    assert findings, "expected a finding for raw request.files.get()"
    assert findings[0]["rule_id"] == "YAML-UPLOAD001"


def test_flask_save_to_user_controlled_filename():
    # Pattern 3: file.save(os.path.join(..., file.filename))
    content = 'file.save(os.path.join(UPLOAD_DIR, file.filename))\n'
    findings = detect("app.py", content, "python")
    assert findings, "expected a finding for save() into user-controlled filename"
    titles = " ".join(f["title"] for f in findings)
    assert "user-controlled filename" in titles or "path traversal" in titles.lower()


def test_django_raw_request_files_access():
    # Pattern 4: request.FILES["..."]
    content = 'doc = request.FILES["document"]\n'
    findings = detect("views.py", content, "python")
    assert findings, "expected a finding for raw request.FILES access"
    titles = " ".join(f["title"] for f in findings)
    assert "Django" in titles


def test_django_filesystemstorage_save():
    # Pattern 5: FileSystemStorage().save(..., request.FILES[...])
    content = 'FileSystemStorage().save(name, request.FILES["f"])\n'
    findings = detect("views.py", content, "python")
    assert findings, "expected a finding for FileSystemStorage.save with raw request"
    titles = " ".join(f["title"] for f in findings)
    assert "Django" in titles


def test_node_multer_with_dest_no_filter():
    # Pattern 6: multer({ dest: "uploads/" })
    content = 'upload = multer({ dest: "uploads/" })\n'
    findings = detect("server.js", content, "javascript")
    assert findings, "expected a finding for multer with dest only"
    titles = " ".join(f["title"] for f in findings)
    assert "multer" in titles.lower()


def test_node_fs_writefile_to_upload_path():
    # Pattern 7: fs.writeFile(... req.file ...)
    content = 'fs.writeFile(uploadPath, data, cb) // uses req.files\n'
    findings = detect("server.js", content, "javascript")
    assert findings, "expected a finding for fs.writeFile to upload path"
    titles = " ".join(f["title"] for f in findings)
    assert "fs.writefile" in titles.lower() or "upload" in titles.lower()


def test_php_move_uploaded_file_raw_user_filename():
    # Pattern 8: move_uploaded_file(..., $_FILES['x']['name'])
    content = 'move_uploaded_file($tmp, $path . $_FILES["file"]["name"]);\n'
    findings = detect("upload.php", content, "php")
    assert findings, "expected a finding for move_uploaded_file with raw user filename"
    titles = " ".join(f["title"] for f in findings)
    assert "PHP" in titles or "move_uploaded_file" in titles


def test_go_formfile_without_validation():
    # Pattern 9: r.FormFile("upload")
    content = 'file, _, err := r.FormFile("upload")\n'
    findings = detect("main.go", content, "go")
    assert findings, "expected a finding for r.FormFile()"
    titles = " ".join(f["title"] for f in findings)
    assert "Go" in titles or "FormFile" in titles


def test_generic_save_to_executable_extension_php():
    # Pattern 10: .save("...php") — the strong RCE signal.
    content = 'f.save("/var/www/html/" + name + ".php")\n'
    findings = detect("app.py", content, "python")
    assert findings, "expected a finding for .save() with .php extension"
    titles = " ".join(f["title"] for f in findings)
    assert "executable" in titles.lower() or "rce" in titles.lower()


def test_generic_save_to_executable_extension_exe():
    # Pattern 10 (alt): os.rename(... .exe) → also caught.
    content = 'os.rename(src, "/tmp/payload.exe")\n'
    findings = detect("app.py", content, "python")
    assert findings, "expected a finding for os.rename with .exe extension"
    titles = " ".join(f["title"] for f in findings)
    assert "executable" in titles.lower() or "rce" in titles.lower()


# ── False-positive & robustness ──────────────────────────────────────────────

def test_safe_filename_with_secure_filename_no_finding():
    # Sanitized upload: secure_filename, no raw .save() on user input → no FP.
    content = (
        "from werkzeug.utils import secure_filename\n"
        "filename = secure_filename(file.filename)\n"
        'file.save(os.path.join(UPLOAD_DIR, filename))\n'
    )
    findings = detect("app.py", content, "python")
    # Pattern 3 looks for `file.save(os.path.join(..., file.filename))` —
    # here the basename is `filename` (sanitized) so it must NOT match.
    titles = " ".join(f["title"] for f in findings)
    assert "user-controlled filename" not in titles.lower(), (
        f"false positive on sanitized upload: {titles!r}"
    )


def test_empty_content_returns_empty_list():
    assert detect("app.py", "", "python") == []


def test_none_content_does_not_crash():
    # Even if a caller misuses the API with None, detect() must not raise.
    try:
        result = detect("app.py", None, "python")  # type: ignore[arg-type]
    except TypeError:
        # Acceptable: contract is that content is str. We only assert no other
        # exception (e.g. AttributeError) escapes.
        return
    assert result == []


def test_binary_content_does_not_crash():
    # Garbage / random bytes — regex must simply not match.
    content = "\x00\x01\x02\xff\xfeabc\x00def\x00"
    findings = detect("app.py", content, "python")
    assert findings == []


def test_detect_returns_list_not_generator():
    import types
    result = detect("app.py", 'request.files["x"].save("/u")\n', "python")
    assert isinstance(result, list)
    assert not isinstance(result, types.GeneratorType)


def test_finding_shape_has_required_fields():
    # Each finding must carry rule_id / severity / line_number / title.
    content = 'request.files["x"].save("/uploads/x")\n'
    findings = detect("app.py", content, "python")
    assert findings
    f = findings[0]
    assert f["rule_id"] == "YAML-UPLOAD001"
    assert f["severity"] == "HIGH"
    assert isinstance(f["title"], str) and f["title"]
    assert isinstance(f["line_number"], int) and f["line_number"] >= 1
    assert f["file_path"] == "app.py"


def test_finding_line_number_is_correct():
    # The pattern is on line 3 of the source — line_number must reflect that.
    content = (
        "import os\n"
        "UPLOAD = '/u'\n"
        'request.files["x"].save(UPLOAD + "/x")\n'
    )
    findings = detect("app.py", content, "python")
    assert findings
    assert findings[0]["line_number"] == 3


def test_multiple_patterns_in_one_snippet_produce_multiple_findings():
    # Two different vulnerable constructs in one file → two findings.
    content = (
        'request.files["a"].save("/x")\n'
        'request.files.get("b")\n'
    )
    findings = detect("app.py", content, "python")
    assert len(findings) >= 2, (
        f"expected ≥2 findings, got {len(findings)}: {[f['title'] for f in findings]}"
    )


def test_no_network_or_secrets_in_module():
    # Detector must be stdlib-only: no requests, no env reads, no socket.
    import inspect
    import gsc_core.gsc_detectors.yaml_rules.upload_injection as mod
    src = inspect.getsource(mod)
    forbidden = ["import requests", "import urllib", "import socket",
                 "import os", "os.environ", "getenv", "open("]
    for token in forbidden:
        assert token not in src, (
            f"upload_injection must not touch the outside world; found {token!r}"
        )


def test_detect_signature_matches_ssti_injection():
    # 1:1 structural parity with ssti_injection.detect(file_path, content, language="auto").
    import inspect
    sig = inspect.signature(detect)
    assert list(sig.parameters) == ["file_path", "content", "language"]
    assert sig.parameters["language"].default == "auto"
