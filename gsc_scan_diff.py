"""Compare two GSC scan JSON files → new / fixed / severity_changed / unchanged.

Inspired by deep-eye's ``core/scan_diff.py`` (MIT) — reimplemented against GSC's
finding shape (rule_id, file_path, line_number, title, category-as-severity).

Use case: track drift between two CI runs — what broke, what got fixed, what
changed severity — so the "heal" loop and release gates have a stable diff.
"""
from __future__ import annotations


def _identity(f: dict) -> tuple:
    """Stable identity for a finding across two scans."""
    rule = f.get("rule_id") or f.get("pattern_title") or f.get("title") or ""
    file_ = f.get("file_path") or f.get("file") or ""
    line = str(f.get("line_number") or f.get("line") or 0)
    title = f.get("title") or ""
    return (rule, file_, line, title)


def _severity(f: dict) -> str:
    return (f.get("severity") or f.get("category") or f.get("level") or "MEDIUM").upper()


def diff_scans(baseline: list[dict], current: list[dict]) -> dict:
    """Classify findings between a baseline and a current scan.

    Returns::
        {
          "new": [finding, ...],                     # only in current
          "fixed": [finding, ...],                   # only in baseline
          "severity_changed": [{finding, from_severity, to_severity}, ...],
          "unchanged": [finding, ...],
        }
    """
    base = {_identity(f): f for f in baseline}
    cur = {_identity(f): f for f in current}

    new, fixed, severity_changed, unchanged = [], [], [], []

    for ident, f in cur.items():
        if ident not in base:
            new.append(f)
        elif _severity(base[ident]) != _severity(f):
            severity_changed.append({
                "finding": f,
                "from_severity": _severity(base[ident]),
                "to_severity": _severity(f),
            })
        else:
            unchanged.append(f)

    for ident, f in base.items():
        if ident not in cur:
            fixed.append(f)

    return {
        "new": new,
        "fixed": fixed,
        "severity_changed": severity_changed,
        "unchanged": unchanged,
    }


def diff_summary(result: dict) -> dict:
    """Counts for a quick CI gate decision."""
    return {
        "new": len(result["new"]),
        "fixed": len(result["fixed"]),
        "severity_changed": len(result["severity_changed"]),
        "unchanged": len(result["unchanged"]),
    }
