# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Work-vs-Value report (Phase 5, "Work-vs-Value отчёт-доказательство").

A pure aggregator that turns a raw "N CRITICAL" red-panel number into an
actionable, evidence-based counter-argument for managers: out of N CRITICAL
findings, only ``reachable`` are really touched by the application, only
those NOT sitting in a dev container are exposed in production, and only
those with non-trivial EPSS are realistically exploitable. The remainder is
the "actionable" set the team actually has to fix this sprint.

This module is deliberately I/O-free so it can be unit-tested deterministically
and reused by any pipeline that has already materialised the per-finding
``reachable`` / ``deploy_context`` / ``epss_score`` signals (e.g. from
``gsc_reachability.is_reachable``, ``gsc_deploy_context.analyze_deploy_context``
and the EPSS cache). The function does not touch the database, the network,
or ``os.environ`` — the caller wires in the data.

Patterned after the existing pure helpers in
``gsc_cli.gsc_revalidate`` (``triage_score``, ``best_of_n_verdict``,
``aggregate_panel``): module-level constants, defensive normalisation, no
side effects.

Public surface:
    work_vs_value_report(findings, severities=("CRITICAL",)) -> dict
        Returns a dict with the numeric breakdown and a ready-to-render
        Markdown body (key ``"markdown"``).
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable

# Severity ladder (highest → lowest). Mirrors gsc_revalidate.SEVERITY_RANK
# but kept local so this module has no import-time dependency on
# gsc_revalidate (which would force-imports sqlite3 / subprocess / etc.).
SEVERITY_RANK = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITY_ORD = {s: i for i, s in enumerate(SEVERITY_RANK)}

# Default cutoff for "low exploitability" — aligned with EPSS convention
# where scores below 0.05 are commonly treated as noise / background risk
# (FIRST.org / EPSS API guidance: a score of 0.05 corresponds roughly to
# a 1-in-20 chance of exploitation in the next 30 days).
LOW_EPSS_THRESHOLD = 0.05


def _coerce_bool(value) -> bool:
    """Defensive bool coercion — accept bool, 0/1, "true"/"false", None."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y", "t")
    return False


def _coerce_float(value) -> float:
    """Defensive float coercion — return 0.0 on anything unparseable."""
    if value is None or isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _coerce_str(value) -> str:
    """Defensive str coercion — empty string for None / non-str."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def work_vs_value_report(
    findings: list[dict],
    severities: Iterable[str] = ("CRITICAL",),
    low_epss_threshold: float = LOW_EPSS_THRESHOLD,
) -> dict:
    """Build a Work-vs-Value summary that argues against the "red panel" number.

    Filters ``findings`` by the supplied severity set (default: just
    ``CRITICAL``), then partitions the kept findings into four buckets:

      * ``reachable``  — the vulnerable function/library is actually called
                         in the project (``finding["reachable"]`` is truthy).
      * ``dev_only``   — the finding lives in a dev container / test stage
                         (``finding["deploy_context"] == "dev"``).
      * ``low_epss``   — EPSS score is below ``low_epss_threshold`` (default
                         0.05) → realistically non-exploitable in the
                         next 30 days per FIRST.org convention.
      * ``actionable`` — the remaining work the team actually has to do:
                         ``reachable AND deploy_context != "dev"
                         AND epss_score >= low_epss_threshold``.

    The sets can overlap (e.g. a reachable finding that is also in a dev
    container). ``actionable`` is computed as the *difference* of
    ``reachable`` minus the union of ``dev_only`` and ``low_epss`` —
    matching the narrative "of the N CRITICAL, only this many actually
    need your engineers this sprint".

    Parameters
    ----------
    findings : list[dict]
        Each item should expose ``severity`` (str, case-insensitive),
        ``reachable`` (bool-ish), ``deploy_context`` (str; values other
        than ``"dev"`` are treated as production-side), and
        ``epss_score`` (float in ``[0.0, 1.0]``). Unknown keys / missing
        fields are tolerated and default conservatively (reachable=False,
        deploy_context="prod", epss_score=0.0).
    severities : Iterable[str], optional
        Severity labels to keep. Default ``("CRITICAL",)`` — the red-panel
        case. Pass ``("CRITICAL", "HIGH")`` to widen the lens.
    low_epss_threshold : float, optional
        Cutoff below which a finding is considered "low EPSS" noise.
        Default ``LOW_EPSS_THRESHOLD`` (0.05). Pass a custom value to
        match an org-specific threshold.

    Returns
    -------
    dict
        Numeric breakdown + a pre-rendered ``"markdown"`` body. Keys::

            {
                "total_crit":     int,  # size of the input set after filter
                "reachable":      int,  # ...with reachable=True
                "dev_only":       int,  # ...in dev container
                "low_epss":       int,  # ...with EPSS < threshold
                "actionable":     int,  # reachable AND NOT dev AND NOT low_epss
                "reachable_pct":  float,# share of total_crit that is reachable
                "actionable_pct": float,# share of total_crit that is actionable
                "noise_removed":  int,  # total_crit - actionable
                "by_severity":    dict, # severity → count, for context
                "deploy_breakdown": dict,  # deploy_context label → count
                "epss_breakdown":   dict,  # "low" / "high" → count
                "severities":     list,  # the kept severities (uppercased)
                "low_epss_threshold": float,
                "markdown":       str,  # pre-rendered report body
            }

        The function is total: it never raises on bad input. Empty input
        returns zeros and an empty Markdown body.

    >>> r = work_vs_value_report([
    ...     {"severity": "CRITICAL", "reachable": True,  "deploy_context": "prod",
    ...      "epss_score": 0.8},
    ...     {"severity": "CRITICAL", "reachable": True,  "deploy_context": "dev",
    ...      "epss_score": 0.9},
    ...     {"severity": "CRITICAL", "reachable": False, "deploy_context": "prod",
    ...      "epss_score": 0.0},
    ... ])
    >>> r["total_crit"], r["reachable"], r["dev_only"], r["low_epss"], r["actionable"]
    (3, 2, 1, 1, 1)
    """
    # ── 1. Normalise severity filter ──────────────────────────────────────
    keep_severities: tuple[str, ...] = tuple(
        (s or "").upper() for s in severities if s
    ) or ("CRITICAL",)
    # Anything outside the SEVERITY_RANK ladder is silently dropped to keep
    # the filter total (caller typos don't crash the report).
    keep_severities = tuple(
        s for s in keep_severities if s in _SEVERITY_ORD
    ) or ("CRITICAL",)

    # ── 2. Walk the findings, defensive normalisation ─────────────────────
    crit_records: list[dict] = []
    by_severity: Counter[str] = Counter()
    deploy_breakdown: Counter[str] = Counter()
    epss_breakdown: Counter[str] = Counter()  # "low" vs "high"

    for raw in findings or ():
        if not isinstance(raw, dict):
            # Non-dict entries (e.g. a stray None from a buggy pipeline)
            # are silently dropped. We never raise here.
            continue
        sev = _coerce_str(raw.get("severity")).upper() or "INFO"
        by_severity[sev] += 1
        if sev not in keep_severities:
            continue

        reachable = _coerce_bool(raw.get("reachable"))
        deploy_context = _coerce_str(raw.get("deploy_context")).lower() or "prod"
        if not deploy_context:
            deploy_context = "prod"
        epss_score = _coerce_float(raw.get("epss_score"))
        # Clamp EPSS into [0, 1] — defensive against bad upstream data.
        epss_score = max(0.0, min(1.0, epss_score))

        deploy_breakdown[deploy_context] += 1
        epss_breakdown["low" if epss_score < low_epss_threshold else "high"] += 1

        crit_records.append({
            "severity": sev,
            "reachable": reachable,
            "deploy_context": deploy_context,
            "epss_score": epss_score,
        })

    total_crit = len(crit_records)

    # ── 3. Bucket counts ─────────────────────────────────────────────────
    reachable_n = sum(1 for r in crit_records if r["reachable"])
    dev_only_n = sum(1 for r in crit_records if r["deploy_context"] == "dev")
    low_epss_n = sum(
        1 for r in crit_records if r["epss_score"] < low_epss_threshold
    )

    # actionable = reachable AND NOT dev AND NOT low_epss.
    # Computed explicitly so the set logic stays auditable.
    actionable_n = sum(
        1 for r in crit_records
        if r["reachable"]
        and r["deploy_context"] != "dev"
        and r["epss_score"] >= low_epss_threshold
    )

    # ── 4. Percentages (guard against /0) ────────────────────────────────
    def _pct(part: int) -> float:
        if total_crit <= 0:
            return 0.0
        return round(part * 100.0 / total_crit, 1)

    reachable_pct = _pct(reachable_n)
    actionable_pct = _pct(actionable_n)
    noise_removed = max(0, total_crit - actionable_n)

    # ── 5. Markdown body ──────────────────────────────────────────────────
    if total_crit == 0:
        body = (
            "## Work-vs-Value Report\n\n"
            f"No findings matched severities "
            f"{', '.join(keep_severities)} — nothing to triage.\n"
        )
    else:
        sev_label = "/".join(keep_severities)
        body = (
            "## Work-vs-Value Report\n\n"
            f"**Total {sev_label} findings:** {total_crit}\n\n"
            "| Bucket | Count | % of total | What it means |\n"
            "|---|---:|---:|---|\n"
            f"| Reachable (called in code) | {reachable_n} | {reachable_pct}% | "
            "Vulnerable function is actually invoked by the app |\n"
            f"| In dev container (not prod) | {dev_only_n} | "
            f"{_pct(dev_only_n)}% | Deploy context is dev — not exposed to users |\n"
            f"| Low EPSS (< {low_epss_threshold}) | {low_epss_n} | "
            f"{_pct(low_epss_n)}% | Realistically non-exploitable in 30d |\n"
            f"| **Actionable (work to do)** | **{actionable_n}** | "
            f"**{actionable_pct}%** | Reachable + prod + non-trivial EPSS |\n\n"
            f"**Noise removed:** {noise_removed} of {total_crit} "
            f"({_pct(noise_removed)}%) — defensible to defer.\n"
        )

    return {
        "total_crit": total_crit,
        "reachable": reachable_n,
        "dev_only": dev_only_n,
        "low_epss": low_epss_n,
        "actionable": actionable_n,
        "reachable_pct": reachable_pct,
        "actionable_pct": actionable_pct,
        "noise_removed": noise_removed,
        "by_severity": dict(by_severity),
        "deploy_breakdown": dict(deploy_breakdown),
        "epss_breakdown": dict(epss_breakdown),
        "severities": list(keep_severities),
        "low_epss_threshold": float(low_epss_threshold),
        "markdown": body,
    }
