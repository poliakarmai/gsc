# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

# YAML-UPLOAD001 — Insecure File Upload
# Based on: OWASP File Upload cheatsheet, PortSwigger file-upload labs, pentest cheatsheet
#
# Detects unsafe file-upload patterns: missing validation of extension / MIME /
# size, or saving under a user-controlled filename — which enables RCE when an
# attacker uploads an executable file (e.g. .php into a webroot, .py into a
# Python app, .jsp into Tomcat, .war into a Java container, .asp/.aspx on IIS).

from ..base import RegexDetector

RULE_ID = "YAML-UPLOAD001"
ECHELON = 2
NOISE_TIER = "precise"
description = (
    "Insecure file upload: user-supplied file saved without validating "
    "extension / MIME / size or saved under a user-controlled filename. "
    "Can lead to Remote Code Execution by uploading an executable file "
    "(.php / .jsp / .asp / .war / .py / .sh / .exe)."
)

patterns = [
    # 1. Flask: request.files["x"].save(...) — direct save without sanitization.
    [r"request\.files\[['\"][^'\"]+['\"]\]\.save\s*\(",
     "Flask upload: save() on request.files without filename sanitization"],

    # 2. Flask: raw request.files.get(...) access — usually the next step is
    #    f.save(user_path); flag the access itself, since pairing the get()
    #    with a save() on the next statement would slip the previous pattern.
    [r"request\.files\.get\s*\(",
     "Flask upload: raw request.files.get() — verify save() sanitizes filename"],

    # 3. Flask: save() into os.path.join(..., file.filename) — user controls
    #    the basename → path traversal or RCE via webroot.
    [r"\.save\s*\(\s*os\.path\.join\s*\([^,]+,\s*(?:file|uploaded_file)\.filename\s*\)",
     "Flask upload: save() to user-controlled filename (path traversal / RCE risk)"],

    # 4. Django: raw request.FILES[...] without a form/validation wrapper.
    [r"request\.FILES\[['\"][^'\"]+['\"]\]",
     "Django upload: raw request.FILES access without validation"],

    # 5. Django: FileSystemStorage(...).save(name, request.FILES[...]) without
    #    sanitizing `name` (extension validation, path traversal).
    [r"FileSystemStorage\([^)]*\)\.save\s*\([^,]+,\s*(?:request|file)",
     "Django upload: FileSystemStorage.save without sanitization"],

    # 6. Node/Express: multer with `dest` but no fileFilter / limits
    #    (multer() being passed an options object that ONLY configures `dest`
    #    is a strong signal of "save anywhere, no validation").
    [r"multer\s*\(\s*\{\s*dest",
     "Node upload: multer with dest but no fileFilter / limits"],

    # 7. Node: fs.writeFile / writeFileSync that touches req.file / req.files
    #    or an upload path — typically the manual upload sink.
    [r"(?:fs\.writeFile|fs\.writeFileSync)\s*\(\s*.*?(?:req\.file|req\.files|upload)",
     "Node upload: fs.writeFile to upload path without validation"],

    # 8. PHP: move_uploaded_file($tmp, ... $_FILES[...]['name']) — raw user
    #    filename, attacker controls the destination extension / path.
    [r"move_uploaded_file\s*\([^,]+,\s*[^)]*\$_(?:FILES|files)[^)]*\[['\"]name['\"]\]",
     "PHP upload: move_uploaded_file with raw user filename"],

    # 9. Go: r.FormFile("...") — caller has the *multipart.FileHeader in hand
    #    and is expected to validate extension / MIME before persisting.
    [r"\.FormFile\s*\(['\"][^'\"]+['\"]\)",
     "Go upload: r.FormFile without extension / MIME validation"],

    # 10. Generic sink: save / move / rename that targets an executable
    #     extension — strongest signal of an RCE-capable upload.
    [r"(?:\.save|shutil\.move|os\.rename|move_uploaded_file)\s*\([^)]*(?:\.py['\"]|\.php['\"]|\.jsp['\"]|\.sh['\"]|\.exe['\"]|\.asp['\"]|\.war['\"])",
     "Upload: save / move to executable extension (RCE risk)"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="upload-injection",
    patterns=patterns,
    severity="HIGH",
    confidence=0.88,
    languages=('python',),
)


def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
