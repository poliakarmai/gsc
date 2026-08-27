# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC LLM First-Pass Audit — Phase 2 (LLM precision ladder).

Pure, side-effect-free helpers that sit at the front of the LLM precision
ladder.  They do NOT call any LLM and do NOT perform file or network I/O:

  * ``select_relevant_files`` — filter a walked file list down to the source /
    config files that are worth sending to an LLM auditor.
  * ``build_first_pass_prompt`` — assemble the single-shot prompt string that
    is handed to the LLM layer.
  * ``parse_first_pass_response`` — normalise an LLM response (which may be
    wrapped in a ```json fence or mixed with prose) into validated candidate
    finding dicts and reject hallucinated file paths.

The module-level ``SEVERITIES`` tuple mirrors the canonical severity
vocabulary used across GSC findings (see ``gsc_revalidate.SEVERITY_RANK``).
It is kept here so the pure helpers stay self-contained and unit-testable
without importing the heavier ``Revalidator`` class.

Design notes
------------
* No filesystem access, no environment variables, no network, no LLM calls.
  Functions take plain data and return plain data.
* Defensive normalisation: bad / missing input yields a sane default rather
  than raising, so a single malformed LLM answer can't crash the triage loop.
* Only the stdlib ``json`` and ``re`` modules are used.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Set

# Canonical severity ladder (highest → lowest). Mirrors the contract used by
# ``gsc_detectors/base.make_finding`` and ``gsc_revalidate.SEVERITY_RANK``.
SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITY_ORD: Dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

# Default severity assigned to any finding whose severity is missing or
# unrecognised (defensive normalisation in ``parse_first_pass_response``).
_DEFAULT_SEVERITY: str = "INFO"

# ── Extension / path filters for ``select_relevant_files`` ──────────────────
# Lower-cased extensions of files that are NEVER relevant for an LLM source
# audit — binaries, generated artefacts, images, archives, fonts, docs, etc.
_EXCLUDED_EXT: frozenset[str] = frozenset({
    # binaries / images / archives / fonts / docs
    ".png", ".jpg", ".jpeg", ".svg", ".gif", ".bmp", ".ico", ".webp",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".7z", ".rar", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".md", ".markdown", ".rst", ".txt", ".adoc",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".class", ".jar", ".aar",
    # native / compiled binaries
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".obj",
    ".pyc", ".pyo", ".wasm",
    # web bundle / minified / sourcemap
    ".min.js", ".min.css",
    ".map",
    # lockfiles / vendored dependency manifests (noise for first-pass)
    ".lock",
})

# Lock-file basenames that are always excluded, regardless of extension.
_EXCLUDED_BASENAMES: frozenset[str] = frozenset({
    "package-lock.json",
    "yarn.lock",
    "cargo.lock",
    "go.sum",
    "poetry.lock",
    "composer.lock",
    "pipfile.lock",
    "dart_test.toml.lock",
})

# Path substrings (lowercased, matched on ``/``-split segments) that mark a
# file as living inside a directory we never want to feed to the LLM.
_EXCLUDED_DIR_SEGMENTS: frozenset[str] = frozenset({
    "vendor", "node_modules", ".git", "target", "build", "dist",
    ".venv", "venv", ".tox", "egg-info",
})

# Logfile extension — excluded as a source-of-noise signal.
_EXCLUDED_LOG_EXT: frozenset[str] = frozenset({".log"})


def _path_segments(path: str) -> List[str]:
    """Split a path into its ``/`` and ``\\``-delimited segments, lowercased."""
    # Normalise backslashes first so Windows-style paths split like POSIX.
    normalised = path.replace("\\", "/")
    return [seg for seg in normalised.split("/") if seg]


def _basename(path: str) -> str:
    """Return the final path component without touching the filesystem."""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _has_excluded_dir(path: str) -> bool:
    """True when any path segment is a known excluded directory."""
    for seg in _path_segments(path):
        low = seg.lower()
        if low in _EXCLUDED_DIR_SEGMENTS:
            return True
    return False


def _has_excluded_ext(path: str) -> bool:
    """True when the path's (lower-cased) extension is in the exclude set.

    Handles compound extensions like ``.min.js``: if the full lowercased path
    ends with ``.min.js`` (or any ``*.min.*``) we still catch the plain
    ``.js`` extension too, which keeps JS source *in* while keeping
    minified bundles *out``.
    """
    low = path.lower()
    # Compound / generated web artefacts checked first (most specific).
    if low.endswith(".min.js") or low.endswith(".min.css"):
        return True
    base = _basename(path)
    # Strip a single trailing extension (handles .js, .py, .lock, etc.).
    dot = base.rfind(".")
    if dot <= 0:  # no extension, or a dotfile with no real ext
        return False
    ext = base[dot:].lower()
    if ext in _EXCLUDED_EXT:
        return True
    if ext in _EXCLUDED_LOG_EXT:
        return True
    return False


def select_relevant_files(
    files: List[str],
    sizes: Dict[str, int] | None = None,
) -> List[str]:
    """Filter a walked file list down to LLM-first-pass audit candidates.

    Keeps source/config files and strips:

      * binaries & images & archives & fonts & docs (by extension),
      * ``*.log`` lock-style files,
      * lockfiles: ``package-lock.json``, ``yarn.lock``, ``Cargo.lock``,
        ``go.sum``, ``poetry.lock``, etc.,
      * anything under ``vendor/`` / ``node_modules/`` / ``.git/`` /
        ``target/`` / ``build/`` / ``dist/`` / ``.venv/`` / ``venv/`` /
        ``.tox/`` / ``egg-info`` (by path segment),
      * generated/minified: ``*.min.js``, ``*.min.css``, ``*.map``.

    ``sizes`` is accepted for API symmetry with future size-gated filtering
    but is not currently used — the function is purely path/extension based.

    The returned list is a *new* sorted list; the caller's input is never
    mutated.  Non-string entries are silently skipped (defensive).
    """
    if not files:
        return []

    keep: List[str] = []
    for f in files:
        if not isinstance(f, str) or not f:
            continue
        if _has_excluded_dir(f):
            continue
        if _has_excluded_ext(f):
            continue
        base = _basename(f)
        if base.lower() in _EXCLUDED_BASENAMES:
            continue
        keep.append(f)

    # Deterministic ordering (sorted, no input mutation).
    return sorted(keep)


# ── Prompt / response helpers ────────────────────────────────────────────────

# JSON code-fence wrappers we unwrap before parsing.
_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def _unwrap_fence(response: str) -> str:
    """Pull the inner content out of a ```json … ``` block if present.

    Falls back to the original text when no fence is found, so prose-prefixed
    or prose-suffixed JSON still parses.
    """
    if not response:
        return ""
    m = _FENCE_RE.search(response)
    if m:
        return m.group(1)
    return response


def _extract_json_object(text: str) -> str:
    """Extract the first balanced ``{ ... }`` JSON object embedded in prose.

    ``parse_first_pass_response`` uses this as a fallback when the whole
    response is not itself valid JSON (e.g. ``"Here is the result:\n{...}\n"``).
    Returns ``""`` when no balanced object exists.
    """
    if not text:
        return ""
    start = text.find("{")
    if start == -1:
        return ""
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return ""


def _normalise_severity(value: object) -> str:
    """Map an arbitrary severity token onto the canonical ladder.

    Unknown / empty values collapse to ``INFO`` (never raises).
    """
    if value is None:
        return _DEFAULT_SEVERITY
    sev = str(value).strip().upper()
    if sev in _SEVERITY_ORD:
        return sev
    # Loose match: strip a leading "S" prefix or trailing digits someone
    # might have accidentally included (e.g. "HIGH3" → "HIGH").
    cleaned = re.sub(r"[^A-Z]", "", sev)
    if cleaned in _SEVERITY_ORD:
        return cleaned
    return _DEFAULT_SEVERITY


def _to_int(value: object, default: int = 1) -> int:
    """Best-effort int coercion for line numbers; never raises."""
    if value is None:
        return default
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _to_float(value: object, default: float = 0.0) -> float:
    """Best-effort float coercion for confidence in [0, 1]; clamped."""
    if value is None:
        return default
    try:
        f = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    if f != f:  # NaN guard
        return default
    return max(0.0, min(1.0, f))


def _to_str(value: object) -> str:
    """Coerce to a non-None, stripped string (empty string fallback)."""
    if value is None:
        return ""
    return str(value).strip()


def build_first_pass_prompt(manifest: Dict) -> str:
    """Assemble the LLM first-pass audit prompt from a file manifest.

    ``manifest`` is a dict with a ``files`` key whose value is a list of
    file paths (strings).  The prompt instructs the LLM to return ONLY a
    JSON object whose ``findings`` array contains candidate findings.

    Each finding must reference a ``file_path`` drawn from the supplied file
    list — the prompt explicitly forbids hallucinating paths not in the list.
    The response schema is pinned to the canonical field names used by
    ``make_finding`` (``rule_id``, ``title``, ``severity``, ``file_path``,
    ``line``, ``detail``, ``confidence``) so downstream consumers need no
    renaming.

    The function is pure: it performs no I/O and no LLM call.  An empty or
    missing ``files`` list still yields a valid (instruction-only) prompt.
    """
    if not isinstance(manifest, dict):
        manifest = {}
    files_raw = manifest.get("files") or []
    if not isinstance(files_raw, (list, tuple)):
        files_raw = []

    file_list = [f for f in files_raw if isinstance(f, str) and f]
    file_count = len(file_list)

    files_block = "\n".join(f"  - {f}" for f in file_list) if file_list else "  (none)"

    prompt = f"""You are a security auditor performing an LLM first-pass audit (Phase 2 — LLM precision ladder).

You will receive a manifest of source / config files that have already been
pre-selected as audit candidates.  Your task is to scan each file for security
issues and report them as a JSON object.

CRITICAL INSTRUCTIONS:
- Reply ONLY with valid JSON. No prose, no preamble, no postamble.
- The JSON object MUST have a single top-level key: "findings".
- "findings" MUST be a JSON array. Each element is a JSON object with these
  exact keys and value types:
    * "rule"       (string)   — vulnerability category, e.g. "secrets",
      "injection", "crypto", "access-control", "xss", "idor", "ssrf", "misconfig".
    * "title"      (string)   — short human-readable summary (<=120 chars).
    * "severity"   (string)   — one of: CRITICAL, HIGH, MEDIUM, LOW, INFO.
    * "file_path"  (string)   — MUST be one of the file paths listed below.
      If you are not certain which file an issue lives in, do NOT invent a
      path.  Any finding whose "file_path" is NOT in the provided file list
      MUST be omitted entirely — hallucinated paths are strictly forbidden.
    * "line"       (integer)  — 1-based line number, or 1 if unknown.
    * "detail"     (string)   — what the issue is and why (1-3 sentences).
    * "confidence" (float)    — your confidence in [0.0, 1.0]; 0.0 = guessing,
      1.0 = certain.

AUDIT-CANDIDATE FILE MANIFEST (count={file_count}):
{files_block}

Return JSON only.
"""
    return prompt


def parse_first_pass_response(
    response: str,
    known_files: Set[str],
) -> List[Dict]:
    """Normalise an LLM first-pass response into validated finding dicts.

    ``response`` may be:

      * a raw JSON object ``{"findings": [...]}``
      * the same object wrapped in a ```json … ``` fenced block
      * prose with the JSON embedded anywhere inside it

    Each candidate finding is validated:

      * ``file_path`` must be a member of ``known_files`` (string membership);
        otherwise the finding is DROPPED — it is treated as a hallucination.
      * ``severity`` is mapped onto the canonical ladder; unknown values →
        ``"INFO"``.
      * ``line`` is coerced to int (non-numeric / missing → ``1``).
      * ``title`` and ``detail`` are coerced to str.
      * ``confidence`` is coerced to float in ``[0, 1]`` (invalid → ``0.0``).
      * ``rule_id`` is taken from ``rule`` (preferred) or ``rule_id``;
        missing → ``"UNKNOWN"``.

    Returns a list of dicts with keys:
      ``rule_id, title, severity, file_path, line, detail, confidence``.

    Tolerant: broken / empty JSON, a non-list ``findings``, missing keys, or
    non-dict elements all degrade gracefully to ``[]`` or per-item defaults
    rather than raising.
    """
    if not isinstance(response, str):
        return []
    if not response.strip():
        return []

    candidate = _unwrap_fence(response)
    candidate = candidate.strip()
    if not candidate:
        return []

    try:
        data = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        obj = _extract_json_object(candidate)
        if not obj:
            return []
        try:
            data = json.loads(obj)
        except (json.JSONDecodeError, ValueError):
            return []

    if not isinstance(data, dict):
        return []

    findings = data.get("findings")
    if not isinstance(findings, list):
        return []

    # Normalise known_files into a set of strings for O(1) membership tests.
    if not isinstance(known_files, set):
        known_files = set(known_files)
    # Defensive: drop non-string entries we can't match against.
    known: Set[str] = {f for f in known_files if isinstance(f, str)}

    out: List[Dict] = []
    for item in findings:
        if not isinstance(item, dict):
            continue

        file_path = _to_str(item.get("file_path"))
        if not file_path or file_path not in known:
            # Hallucination / missing path → drop.
            continue

        rule = item.get("rule", item.get("rule_id"))
        rule_id = _to_str(rule) if rule is not None else ""
        if not rule_id:
            rule_id = "UNKNOWN"

        title = _to_str(item.get("title"))
        if not title:
            title = ""

        severity = _normalise_severity(item.get("severity"))
        if not severity:
            severity = _DEFAULT_SEVERITY

        detail = _to_str(item.get("detail"))
        if not detail:
            detail = ""

        line = _to_int(item.get("line"), default=1)
        if line < 1:
            line = 1

        confidence = _to_float(item.get("confidence"), default=0.0)

        out.append({
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "file_path": file_path,
            "line": line,
            "detail": detail,
            "confidence": confidence,
        })

    return out
