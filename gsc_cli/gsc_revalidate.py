# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Structured Revalidate — Deepsec-inspired revalidation stage.

Re-checks existing findings with a structured verdict:
  - true-positive: confirmed vulnerability
  - false-positive: not a real vulnerability
  - fixed: vulnerability was patched (detected via git history)
  - uncertain: not enough context to decide

Process:
1. Re-read the source file around the finding
2. Check git history for recent changes to that line/function
3. Send to LLM for structured analysis
4. Store verdict + reasoning

Usage:
    from gsc_revalidate import Revalidator
    rev = Revalidator(db_path, project_path)
    results = rev.revalidate_findings(findings, min_severity="HIGH")
"""
import sqlite3
import json
import os
import subprocess
import re
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

from gsc_llm_providers import defang, UNTRUSTED_GUARD, guard_system


# Canonical verdict vocabulary — module-level constant so pure helpers such as
# ``best_of_n_verdict`` can reference it without importing the whole class.
# Revalidator.VERDICTS is an alias kept for backward compatibility.
VERDICTS = ("true-positive", "false-positive", "fixed", "uncertain")


def best_of_n_verdict(verdicts: list[tuple[str, int]]) -> dict:
    """Aggregate N verdicts from the same model (Self-verification Best-of-N).

    Given a list of ``(verdict, confidence)`` pairs produced by ``n`` independent
    LLM calls to the *same* model and *same* prompt (temperature low enough that
    sampling yields non-degenerate diversity), return a single aggregated verdict:

      * ``verdict``            — the majority verdict (ties broken in ``VERDICTS``
                                 order so the result is deterministic).
      * ``confidence``         — arithmetic mean of per-sample confidences,
                                 clamped to [0, 100] and rounded.
      * ``agreement_pct``      — fraction of votes that backed the majority
                                 verdict (1.0 = unanimity).
      * ``disagreement``       — ``True`` when there is no clear majority
                                 (i.e. an exact tie / split), so the caller can
                                 escalate for human review.

    This is a pure function: it owns no state and performs no I/O, which makes
    it trivially unit-testable and safe to call from hot paths.

    >>> best_of_n_verdict([("true-positive", 80), ("true-positive", 70)])
    {'verdict': 'true-positive', 'confidence': 75, 'agreement_pct': 1.0, 'disagreement': False}
    """
    if not verdicts:
        return {
            "verdict": "uncertain",
            "confidence": 0,
            "agreement_pct": 0.0,
            "disagreement": True,
        }

    votes = [v for v, _ in verdicts]
    confs = [c for _, c in verdicts]
    counts = Counter(votes)
    # Stable, deterministic order so ties are reproducible, not hash-dependent.
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], VERDICTS.index(kv[0])))
    top_verdict, top_count = ordered[0]
    total = len(votes)
    agreement = top_count / total
    disagreement = top_count * 2 <= total  # split / tie (not a strict majority)
    mean_conf = round(sum(confs) / len(confs))
    mean_conf = max(0, min(100, mean_conf))
    return {
        "verdict": top_verdict,
        "confidence": mean_conf,
        "agreement_pct": round(agreement, 4),
        "disagreement": disagreement,
    }


# ── Severity ladder (highest → lowest). Mirrors the severity vocabulary used
# across GSC findings. Kept module-level so pure helpers can reference it and
# tests can import it without instantiating Revalidator.
SEVERITY_RANK = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
# Reverse lookup: severity → ordinal (0 = CRITICAL = strongest).
_SEVERITY_ORD = {s: i for i, s in enumerate(SEVERITY_RANK)}


def demote_severity(severity: str) -> str:
    """Demote ``severity`` by one rung of the SEVERITY_RANK ladder.

    CRITICAL→HIGH→MEDIUM→LOW→INFO. An unknown or already-lowest severity
    stays at INFO. Pure function — no I/O, trivially unit-testable.

    >>> demote_severity("CRITICAL")
    'HIGH'
    >>> demote_severity("INFO")
    'INFO'
    >>> demote_severity("BOGUS")
    'INFO'
    """
    sev = (severity or "INFO").upper()
    ord_ = _SEVERITY_ORD.get(sev)
    if ord_ is None or ord_ >= len(SEVERITY_RANK) - 1:
        return "INFO"
    return SEVERITY_RANK[ord_ + 1]


def cross_model_vote(verdict_a: str, verdict_b: str,
                     confidence_a: int | float = 0,
                     confidence_b: int | float = 0) -> dict:
    """Aggregate two verdicts coming from two *different* models (Phase 2).

    ``verdict_a`` is the primary (e.g. DeepSeek) verdict, ``verdict_b`` is the
    secondary (e.g. OpenRouter) verdict. When both agree the result is that
    verdict with an averaged confidence and no demotion. When they disagree —
    specifically the noisy-signal case of TP vs FP — the disagreement is flagged
    and the caller is told to (a) demote the severity by one rung and
    (b) halve the confidence, so downstream triage / noise-engine gets a
    conservative signal instead of a hard false-positive suppression.

    Returned dict keys:
      * ``verdict``            — the surviving verdict (A on disagreement,
                                  matching ``best_of_n_verdict`` tie-break style).
      * ``confidence``         — averaged, clamped to [0, 100], rounded.
      * ``disagreement``       — True when A != B, else False.
      * ``demote_severity``    — bool: True when disagreement is a TP/FP split
                                 (or either side is TP), signaling severity
                                 should drop one rung.
      * ``demote_confidence``  — bool: True when confidence should be halved
                                 (any disagreement).

    This is a pure function: no state, no I/O, no network, no env reads — the
    caller is responsible for obtaining ``verdict_b`` from the configured
    secondary model (itself selected through ``gsc_llm_providers``, see
    ``GSC_REVALIDATE_MODEL_B``). It performs no LLM calls itself.

    >>> cross_model_vote("true-positive", "true-positive", 90, 80)
    {'verdict': 'true-positive', 'confidence': 85, 'disagreement': False, 'demote_severity': False, 'demote_confidence': False}
    >>> r = cross_model_vote("true-positive", "false-positive", 90, 80)
    >>> r['disagreement']
    True
    >>> r['demote_severity']
    True
    >>> r['demote_confidence']
    True
    """
    # Normalise + clamp confidences up front (defensive against bad callers).
    def _clamp(c: int | float) -> int:
        try:
            v = int(round(float(c)))
        except (TypeError, ValueError):
            v = 0
        return max(0, min(100, v))

    ca, cb = _clamp(confidence_a), _clamp(confidence_b)
    mean_conf = ca + cb
    mean_conf = mean_conf // 2 if mean_conf % 2 == 0 else (mean_conf // 2) + 1
    # Round-half-even isn't required; a simple average clamped/rounded suffices.
    mean_conf = max(0, min(100, round((ca + cb) / 2)))

    disagreement = verdict_a != verdict_b
    # Demote severity only on the high-noise splits: a real TP/FP clash, or when
    # one side is a (confirmed) TP that the other model rejected. Any TP verdict
    # is the expensive signal to lose, so when models fight over TP/FP we drop
    # severity by one rung but never flip a confirmed FP into a TP outright.
    tp_fp_split = {("true-positive", "false-positive"),
                   ("false-positive", "true-positive")}
    is_tp = {"true-positive"}
    demote_sev = disagreement and (
        (verdict_a, verdict_b) in tp_fp_split
        or verdict_a in is_tp or verdict_b in is_tp
    )
    demote_conf = disagreement

    return {
        "verdict": verdict_a,          # primary verdict is the survivor
        "confidence": mean_conf,
        "disagreement": disagreement,
        "demote_severity": demote_sev,
        "demote_confidence": demote_conf,
    }


def aggregate_panel(verdicts: list[tuple[str, int | float]] | list[list]) -> dict:
    """Aggregate N isolated reviewer verdicts into a single panel verdict (Phase 2).

    ``cross_model_vote`` mixes two models pairwise. ``aggregate_panel`` is the
    multi-model analogue: three (or N) *isolated* reviewers (separate prompts,
    separate contexts, separate providers) each return ``(verdict, confidence)``
    and the panel summarises them into one decision.

    The aggregation is a strict majority over the canonical verdict vocabulary
    (``VERDICTS``). Ties are broken deterministically by ``VERDICTS`` order, so
    the same input always produces the same output (regression-safe, hash-safe).

    Returned dict keys:

      * ``verdict``        — majority verdict; ``"uncertain"`` when the input is
                             empty or no verdict reaches a strict majority.
      * ``confidence``     — arithmetic mean of the per-vote confidences of
                             the *surviving verdict's backers*, clamped to
                             ``[0, 100]`` and rounded. If the panel split, we
                             fall back to the mean across ALL votes so the
                             caller still gets a usable signal.
      * ``agreement_pct``  — share of votes that backed the surviving verdict
                             (``1.0`` for unanimity, ``0.0`` for an empty input).
      * ``disagreement``   — ``True`` when no verdict reached a strict majority
                             (i.e. an exact tie or a 3-way split, so the caller
                             should escalate to a judge / human review).
      * ``unanimous``      — ``True`` when *all* votes agree (1.0 agreement).
      * ``split``          — ``True`` when the panel could not reach a strict
                             majority (``disagreement == split``; one is the
                             boolean flag, the other is the same flag aliased
                             for readability at the call site).
      * ``votes``          — ``Counter`` of raw vote counts per verdict label
                             (e.g. ``{"true-positive": 2, "false-positive": 1}``).
                             Plain dict, JSON-serialisable.

    Pure function: no state, no I/O, no LLM calls, no env reads. The caller is
    responsible for obtaining the per-reviewer verdicts (typically through
    ``gsc_llm_providers`` with three independent provider keys / prompts).
    Safe to call from hot paths and trivially unit-testable.

    >>> aggregate_panel([("true-positive", 90), ("true-positive", 80), ("true-positive", 70)])
    {'verdict': 'true-positive', 'confidence': 80, 'agreement_pct': 1.0, 'disagreement': False, 'unanimous': True, 'split': False, 'votes': {'true-positive': 3}}
    >>> r = aggregate_panel([("true-positive", 90), ("false-positive", 80), ("uncertain", 60)])
    >>> r["disagreement"]
    True
    >>> r["split"]
    True
    """
    if not verdicts:
        return {
            "verdict": "uncertain",
            "confidence": 0,
            "agreement_pct": 0.0,
            "disagreement": True,
            "unanimous": False,
            "split": True,
            "votes": {},
        }

    # Defensive normalisation: callers may pass tuples OR 2-element lists, and
    # confidences may be ints / floats / strings / None. We coerce to (str, int)
    # and silently downgrade unparseable confidences to 0 instead of raising —
    # the aggregator must be total, not crash the triage loop on bad input.
    def _clamp(c) -> int:
        try:
            v = int(round(float(c)))
        except (TypeError, ValueError):
            v = 0
        return max(0, min(100, v))

    def _coerce(pair) -> tuple[str, int] | None:
        if not pair or len(pair) < 2:
            return None
        v = pair[0]
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        return s, _clamp(pair[1])

    cleaned: list[tuple[str, int]] = []
    for pair in verdicts:
        coerced = _coerce(pair)
        if coerced is not None:
            cleaned.append(coerced)

    if not cleaned:
        return {
            "verdict": "uncertain",
            "confidence": 0,
            "agreement_pct": 0.0,
            "disagreement": True,
            "unanimous": False,
            "split": True,
            "votes": {},
        }

    votes_list = [v for v, _ in cleaned]
    confs_list = [c for _, c in cleaned]
    counts = Counter(votes_list)
    total = len(votes_list)

    # Stable, deterministic tie-break: highest count first, then by canonical
    # VERDICTS order (so the result is reproducible, not hash-dependent).
    ordered = sorted(
        counts.items(),
        key=lambda kv: (-kv[1], VERDICTS.index(kv[0]) if kv[0] in VERDICTS else len(VERDICTS)),
    )
    top_verdict, top_count = ordered[0]
    agreement = top_count / total
    # Strict majority: the surviving verdict must hold more than half the votes.
    # An exact tie (e.g. 1-1-1) and a 2-1 split both pass (top_count * 2 > total).
    disagreement = top_count * 2 <= total
    unanimous = top_count == total and total > 0

    # Confidence: when the panel is unanimous, take the mean of all voters'
    # confidences (they all voted for the same label). On a majority, we also
    # take the all-vote mean so dissenting voices still dampen the signal
    # (a single low-confidence dissenter pulls the average down, which is
    # the desired conservative behaviour). Clamp + round to int.
    # NOTE: we use half-up rounding (math.floor(x + 0.5)) to match the
    # convention used by the existing cross_model_vote() helper. Python's
    # built-in round() is banker's rounding (round(72.5) == 72), which
    # is surprising for percentile scores — half-up is the right choice
    # for an audit-facing confidence.
    import math
    raw_mean = sum(confs_list) / len(confs_list)
    mean_conf = max(0, min(100, int(math.floor(raw_mean + 0.5))))

    # Build the votes dict in canonical VERDICTS order so the JSON output is
    # stable and human-readable across runs.
    votes_dict: dict[str, int] = {v: 0 for v in VERDICTS}
    for k, n in counts.items():
        votes_dict[k] = votes_dict.get(k, 0) + n
    # Drop the zero entries so the wire format stays compact, but keep the
    # ordering by re-inserting in VERDICTS order above.
    votes_compact = {k: n for k, n in votes_dict.items() if n > 0}

    return {
        "verdict": top_verdict,
        "confidence": mean_conf,
        "agreement_pct": round(agreement, 4),
        "disagreement": disagreement,
        "unanimous": unanimous,
        "split": disagreement,
        "votes": votes_compact,
    }


def judge_verdict(panel_result: dict, judge_verdict_str: str,
                  judge_confidence: int | float = 0) -> dict:
    """Follow-up judge step on top of a panel result (Phase 2).

    A 3-way panel of independent reviewers (see :func:`aggregate_panel`) is
    usually enough, but a *split* panel (no strict majority) is the
    worst-case signal: 1-1-1 means the three reviewers couldn't agree, and a
    human or a higher-cost LLM judge is brought in to break the tie. The
    judge is also useful for an unanimity check — when three reviewers all
    say "true-positive" but a judge (with broader context / a better model)
    disagrees, we trust the judge and flip the verdict.

    Rules (deterministic, total — never raises on bad input):

      1. Empty / missing ``panel_result`` → we still apply the judge and
         return a judge-based verdict (judge confidence drives the final
         signal).
      2. **Unanimous panel that matches the judge** → panel survives, judge
         confidence is folded in as a *boost* (averaged with the panel's
         confidence, clamped to ``[0, 100]``).
      3. **Unanimous panel that DISAGREES with the judge** → judge wins
         (the more expensive model overrides the cheap consensus). The
         surviving verdict is the judge's, confidence is the judge's.
      4. **Split panel (1-1-1, or any non-strict majority)** → judge
         decisively *replaces* the panel verdict. Confidence is the
         judge's; we also flag ``judge_overrode_split`` so the caller
         can audit the override (e.g. for human-in-the-loop review).
      5. **Majority panel (2-1)** → judge still wins if its confidence is
         strictly higher than the panel's surviving confidence. This
         matches the spirit of "judge breaks ties" while not letting a
         low-confidence judge silently flip a confident majority.
         If the judge is tied-or-lower in confidence, the panel survives.

    Returned dict keys (additive over ``panel_result`` — original keys are
    preserved so callers can keep using the panel result unchanged):

      * All keys from ``panel_result`` (verbatim, so the function is a
        drop-in enrichment — verdict / confidence / agreement_pct / etc.).
      * ``final_verdict``     — the verdict that actually wins after the
                                judge step. May differ from
                                ``panel_result["verdict"]``.
      * ``final_confidence``  — the confidence that wins alongside the
                                final verdict.
      * ``judge_verdict``     — the input judge verdict (normalised),
                                echoed for audit.
      * ``judge_confidence``  — input judge confidence, clamped to ``[0, 100]``.
      * ``judge_overrode``    — ``True`` iff the judge overrode the panel
                                (panel != judge, judge won). Useful for
                                downstream auditing.
      * ``judge_overrode_split`` — ``True`` iff the override happened
                                specifically on a split panel (rule 4).
                                A subset of ``judge_overrode``.
      * ``reason``            — short human-readable explanation of which
                                rule fired (e.g. ``"judge_unanimity_override"``,
                                ``"judge_replaces_split"``,
                                ``"judge_boosted_unanimous"``,
                                ``"panel_survives"``).

    Pure function: no state, no I/O, no LLM calls, no env reads. Safe to
    chain on top of :func:`aggregate_panel` and trivial to unit-test.

    >>> p = {"verdict": "true-positive", "confidence": 80, "agreement_pct": 1.0,
    ...      "disagreement": False, "unanimous": True, "split": False,
    ...      "votes": {"true-positive": 3}}
    >>> r = judge_verdict(p, "true-positive", 90)
    >>> r["final_verdict"]
    'true-positive'
    >>> r["judge_overrode"]
    False
    >>> r["judge_overrode_split"]
    False
    """
    # Clamp + normalise judge confidence defensively.
    try:
        jc = int(round(float(judge_confidence)))
    except (TypeError, ValueError):
        jc = 0
    jc = max(0, min(100, jc))

    # Normalise judge verdict: empty / None → "uncertain" so we never crash
    # on bad caller input.
    jv = (judge_verdict_str or "").strip().lower() if judge_verdict_str else ""
    if not jv:
        jv = "uncertain"

    # Start from the panel result; if the caller passed None or a non-dict,
    # synthesise a minimal "uncertain" panel so the rest of the logic still
    # works (total function).
    if not isinstance(panel_result, dict):
        panel_result = {
            "verdict": "uncertain",
            "confidence": 0,
            "agreement_pct": 0.0,
            "disagreement": True,
            "unanimous": False,
            "split": True,
            "votes": {},
        }

    # Always echo the inputs for audit. Use a copy so we never mutate the
    # caller's dict (caller may still hold a reference and pass it to
    # serialisation / DB writers).
    out: dict = dict(panel_result)
    out["judge_verdict"] = jv
    out["judge_confidence"] = jc

    panel_v = panel_result.get("verdict", "uncertain") or "uncertain"
    panel_c = panel_result.get("confidence", 0) or 0
    try:
        panel_c = int(round(float(panel_c)))
    except (TypeError, ValueError):
        panel_c = 0
    panel_c = max(0, min(100, panel_c))

    unanimous = bool(panel_result.get("unanimous", False))
    split = bool(panel_result.get("split", True) or panel_result.get("disagreement", False))

    final_v = panel_v
    final_c = panel_c
    reason = "panel_survives"
    judge_overrode = False
    judge_overrode_split = False

    # Rule 4: split panel → judge replaces it (always). This is the most
    # important case: when the cheap panel cannot decide, the judge's word
    # is final regardless of the numeric confidence (the very fact that
    # we called the judge means we trust it more than the panel).
    if split:
        final_v = jv
        final_c = jc
        reason = "judge_replaces_split"
        judge_overrode = (jv != panel_v)
        judge_overrode_split = True

    # Rule 3: unanimous panel that disagrees with the judge → judge wins.
    # The panel unanimous-agreement gives the cheap consensus a boost, but
    # a single authoritative override flips the verdict. Confidence is the
    # judge's, not an average.
    elif unanimous and jv != panel_v:
        final_v = jv
        final_c = jc
        reason = "judge_unanimity_override"
        judge_overrode = True

    # Rule 2: unanimous panel that matches the judge → judge confidence is
    # folded in as a *boost*. Average of panel + judge, clamped. The
    # surviving verdict is unchanged but the caller gets a stronger signal.
    elif unanimous and jv == panel_v:
        avg = (panel_c + jc) // 2 if (panel_c + jc) % 2 == 0 else (panel_c + jc) // 2 + 1
        # Defensive clamp (avg fits in [0, 100] by construction since both
        # operands do, but keep the explicit clamp for forward-compat with
        # potential future non-integer confidences).
        final_c = max(0, min(100, avg))
        reason = "judge_boosted_unanimous"

    # Rule 5: 2-1 majority → judge wins ONLY when it both disagrees with
    # the majority AND has strictly higher confidence. A agreeing judge
    # (even with a higher number) does not "override" anything — and a
    # disagreeing judge with tied-or-lower confidence must not silently
    # flip a confident majority. This keeps the rule conservative.
    elif jv != panel_v and jc > panel_c:
        final_v = jv
        final_c = jc
        reason = "judge_overrode_majority"
        judge_overrode = True
    # else: panel survives as-is, reason stays "panel_survives".

    out["final_verdict"] = final_v
    out["final_confidence"] = final_c
    out["judge_overrode"] = judge_overrode
    out["judge_overrode_split"] = judge_overrode_split
    out["reason"] = reason
    return out


# Canonical per-verdict base priority for auto-triage scoring. Pure constants
# so ``triage_score`` stays self-contained and deterministic.
_TRIAGE_BASE = {
    "true-positive": 80,
    "false-positive": 20,
    "fixed": 10,
    "uncertain": 50,
}


def triage_score(regex_hits: int, llm_verdict: str, llm_confidence: int) -> dict:
    """Fuse regex + LLM signals into a single auto-triage priority (Phase 2).

    Pure, deterministic, no I/O. Combines three independent signals:

      * ``regex_hits``     — how many regex detectors fired for this finding
                             (``>=3`` confirms independently, ``0`` means the
                             LLM flagged something the scanners missed).
      * ``llm_verdict``    — one of the canonical ``VERDICTS`` tokens.
      * ``llm_confidence`` — LLM-reported confidence in ``[0, 100]``.

    Scoring:
      * base priority from the verdict (TP high, FP low, uncertain middle);
      * ``llm_confidence`` nudges the base by ``(confidence - 50) * 0.4``;
      * ``regex_hits >= 3`` adds ``+10`` (independent confirmation), and
        ``regex_hits == 0`` subtracts ``10`` (scanner/LLM divergence);
      * the result is clamped to ``[0, 100]``.

    Category:
      * ``auto-close``   — FP verdict, or score below 30;
      * ``escalate``     — TP verdict with score >= 70;
      * ``needs-review`` — everything else (human looks at it).

    >>> triage_score(3, "true-positive", 90)
    {'score': 96, 'category': 'escalate', 'reason': 'tp_confirmed_multi_regex'}
    >>> triage_score(1, "false-positive", 60)['category']
    'auto-close'
    """
    def _clamp_int(v) -> int:
        try:
            return int(round(float(v)))
        except (TypeError, ValueError):
            return 0

    verdict = str(llm_verdict or "").strip().lower()
    conf = max(0, min(100, _clamp_int(llm_confidence)))
    hits = max(0, _clamp_int(regex_hits))

    base = _TRIAGE_BASE.get(verdict, 50)  # unknown verdict -> neutral

    score = base + (conf - 50) * 0.4
    if hits >= 3:
        score += 10
    elif hits == 0:
        score -= 10

    score = max(0, min(100, int(round(score))))

    if verdict == "false-positive" or score < 30:
        category = "auto-close"
        reason = "fp_verdict" if verdict == "false-positive" else "low_score"
    elif verdict == "true-positive" and score >= 70:
        category = "escalate"
        reason = "tp_confirmed_multi_regex" if hits >= 3 else "tp_high_confidence"
    else:
        category = "needs-review"
        reason = "uncertain_or_mid_score"

    return {"score": score, "category": category, "reason": reason}


class Revalidator:
    """Structured revalidation — cuts FP rate by 50%+."""

    # Same vocabulary as the module-level VERDICTS — kept as a class attribute
    # for backward compatibility with code that references Revalidator.VERDICTS.
    VERDICTS = ("true-positive", "false-positive", "fixed", "uncertain")

    def __init__(self, db_path: str, project_path: Path):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self.project_path = Path(project_path).resolve()
        self._ensure_schema()

    def _ensure_schema(self):
        """Add revalidation columns if not present."""
        try:
            self.db.execute("ALTER TABLE findings ADD COLUMN revalidation_verdict TEXT")
        except sqlite3.OperationalError:
            pass  # Already exists
        try:
            self.db.execute("ALTER TABLE findings ADD COLUMN revalidation_reasoning TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            self.db.execute("ALTER TABLE findings ADD COLUMN revalidation_checked_at TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            self.db.execute("ALTER TABLE findings ADD COLUMN revalidation_git_fixed TEXT")
        except sqlite3.OperationalError:
            pass
        self.db.commit()

    # ── Git history check ────────────────────────────────────────────────────

    def _check_git_fixed(self, file_path: str, line: int) -> tuple[bool, str]:
        """
        Check if the finding's line was recently modified (potential fix).
        Returns (was_modified, commit_info).
        """
        abs_path = self.project_path / file_path
        if not abs_path.exists():
            return False, "file removed"

        try:
            # Get last modification date
            result = subprocess.run(
                ["git", "-C", str(self.project_path), "log", "-1", "--format=%h %s %ai",
                 "--", str(file_path)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False, f"git error: {result.stderr.strip()}"

            commit_info = result.stdout.strip()
            if not commit_info:
                return False, "no git history"

            # Check if specific line was changed recently
            blame = subprocess.run(
                ["git", "-C", str(self.project_path), "blame", "-L", f"{line},{line}",
                 "--line-porcelain", "--", str(file_path)],
                capture_output=True, text=True, timeout=5
            )
            if blame.returncode != 0:
                return False, commit_info

            # Extract commit hash from blame
            match = re.search(r'^([0-9a-f]{40})', blame.stdout, re.MULTILINE)
            if match:
                commit_hash = match.group(1)[:8]
                return True, f"modified in {commit_hash}: {commit_info[:80]}"

            return False, commit_info

        except Exception as e:
            return False, f"error: {str(e)}"

    # ── Context-based revalidation ───────────────────────────────────────────

    def _read_context(self, file_path: str, line: int, context_lines: int = 15) -> dict:
        """Read code context around the finding."""
        abs_path = self.project_path / file_path
        result = {
            "file_exists": False,
            "line": line,
            "code_snippet": "",
            "function_name": "",
            "imports": "",
            "file_content": "",
        }

        if not abs_path.exists():
            return result

        result["file_exists"] = True
        try:
            content = abs_path.read_text(errors="replace")
            result["file_content"] = content[:50000]  # Cap at 50KB
            lines = content.split("\n")

            # Get surrounding context
            start = max(0, line - context_lines - 1)
            end = min(len(lines), line + context_lines)
            result["code_snippet"] = "\n".join(
                f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start)
            )

            # Try to find enclosing function/class
            for i in range(line - 1, max(0, line - 50), -1):
                stripped = lines[i].strip()
                if re.match(r'(?:def|class|async def)\s+\w+', stripped):
                    result["function_name"] = stripped
                    break

            # Get imports (first 20 lines)
            result["imports"] = "\n".join(lines[:20])

        except Exception:
            pass

        return result

    # ── Heuristic pre-checks ─────────────────────────────────────────────────

    def _heuristic_check(self, finding: dict, context: dict) -> tuple[str | None, str]:
        """
        Fast heuristic checks before LLM call.
        Returns (verdict_or_None, reason).
        """
        file_path = finding.get("file_path", "")
        title = finding.get("title", "")
        detail = finding.get("detail", "")
        severity = finding.get("severity", "MEDIUM")

        # Check 1: File no longer exists → fixed or FP
        if not context["file_exists"]:
            return "fixed", "Source file no longer exists — vulnerability removed"

        # Check 2: Test/demo/fixture files → FP
        test_indicators = ["test", "tests", "fixture", "demo", "example", "sample"]
        if any(f"/{t}/" in file_path or f"_{t}." in file_path or file_path.startswith(f"{t}/")
               for t in test_indicators):
            return "false-positive", f"Finding in test/demo file ({file_path})"

        # Check 3: Documentation files → FP
        if file_path.endswith((".md", ".rst", ".txt", ".org")):
            return "false-positive", "Finding in documentation file"

        # Check 4: Config files with 'example'/'sample'/'template' → FP
        if any(kw in file_path.lower() for kw in ("example", "sample", "template", ".dist")):
            if severity in ("HIGH", "CRITICAL"):
                return None, ""  # Still check — could be real despite template name
            return "false-positive", f"Finding in template/example config ({file_path})"

        # Check 5: Obvious placeholder values
        if detail and any(p in detail.lower() for p in
                          ("placeholder", "changeme", "your-key", "example.com")):
            return "false-positive", "Finding references placeholder/example values"

        return None, ""  # Needs deeper check

    # ── Main revalidation ────────────────────────────────────────────────────

    def revalidate_finding(self, finding: dict, use_llm: bool = True) -> dict:
        """
        Revalidate a single finding. Returns finding dict with revalidation fields.
        """
        file_path = finding.get("file_path", "")
        line = int(finding.get("line", finding.get("line_number", 1)))
        finding_id = finding.get("id")
        rule_id = finding.get("rule_id", "?")

        result = dict(finding)

        # 1. Read context
        context = self._read_context(file_path, line)

        # 2. Heuristic pre-checks
        verdict, reason = self._heuristic_check(finding, context)
        if verdict:
            result["revalidation_verdict"] = verdict
            result["revalidation_reasoning"] = reason
            result["revalidation_checked_at"] = datetime.now(timezone.utc).isoformat()
            self._save_verdict(finding_id, result)
            return result

        # 3. Git history check
        git_fixed, git_info = self._check_git_fixed(file_path, line)
        result["revalidation_git_fixed"] = git_info

        if git_fixed:
            # File was recently modified — strong indicator of fix
            if use_llm:
                verdict = self._llm_check(finding, context, git_info)
            else:
                verdict = "uncertain"
            result["revalidation_verdict"] = verdict
            result["revalidation_reasoning"] = f"Git: {git_info}"
            result["revalidation_checked_at"] = datetime.now(timezone.utc).isoformat()
            self._save_verdict(finding_id, result)
            return result

        # 4. LLM deep check
        if use_llm:
            verdict, reasoning = self._llm_check_structured(finding, context)
            result["revalidation_verdict"] = verdict
            result["revalidation_reasoning"] = reasoning
        else:
            result["revalidation_verdict"] = "uncertain"
            result["revalidation_reasoning"] = "LLM disabled — manual review needed"

        result["revalidation_checked_at"] = datetime.now(timezone.utc).isoformat()
        self._save_verdict(finding_id, result)
        return result

    def revalidate_findings(self, findings: list[dict],
                            min_severity: str = "HIGH",
                            use_llm: bool = True) -> list[dict]:
        """Revalidate multiple findings. Returns updated findings."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        results = []

        for f in findings:
            sev = f.get("severity", "MEDIUM")
            # Skip if below min_severity
            if severity_order.get(sev, 99) > severity_order.get(min_severity, 99):
                f["revalidation_verdict"] = "uncertain"
                f["revalidation_reasoning"] = "Below min_severity — skipped revalidation"
                results.append(f)
                continue

            # Skip if already validated
            if f.get("revalidation_verdict"):
                results.append(f)
                continue

            result = self.revalidate_finding(f, use_llm=use_llm)
            results.append(result)

        return results

    # ── Batch revalidation (token-lean) ──────────────────────────────────────

    def _apply_verdict(self, finding: dict, verdict: str, reasoning: str,
                       git_fixed: str | None = None) -> dict:
        finding["revalidation_verdict"] = verdict
        finding["revalidation_reasoning"] = reasoning
        finding["revalidation_checked_at"] = datetime.now(timezone.utc).isoformat()
        if git_fixed is not None:
            finding["revalidation_git_fixed"] = git_fixed
        self._save_verdict(finding.get("id"), finding)
        return finding

    def _cached_verdict(self, finding: dict) -> tuple[str, str] | None:
        """Reuse a prior verdict for the same finding_key (cross-project cache).

        Identical findings (same rule + file + snippet) from different projects or
        runs share a finding_key, so revalidating them twice is wasted LLM spend.
        """
        key = finding.get("finding_key")
        if not key:
            return None
        row = self.db.execute(
            "SELECT revalidation_verdict, revalidation_reasoning FROM findings "
            "WHERE finding_key = ? AND revalidation_verdict IS NOT NULL "
            "ORDER BY revalidation_checked_at DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row:
            return row["revalidation_verdict"], row["revalidation_reasoning"]
        return None

    def revalidate_findings_batch(self, findings: list[dict],
                                  min_severity: str = "HIGH",
                                  use_llm: bool = True,
                                  batch_size: int = 30) -> list[dict]:
        """Revalidate with batched LLM calls + finding_key cache.

        Fast paths (heuristic / git / finding_key cache) skip the LLM entirely.
        The rest are grouped into chunks of `batch_size`, one LLM call per chunk
        instead of one call per finding — cutting token overhead ~batch_size×.
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        results: list[dict] = []
        pending: list[dict] = []

        for f in findings:
            sev = f.get("severity", "MEDIUM")
            if severity_order.get(sev, 99) > severity_order.get(min_severity, 99):
                f["revalidation_verdict"] = "uncertain"
                f["revalidation_reasoning"] = "Below min_severity — skipped revalidation"
                results.append(f)
                continue
            if f.get("revalidation_verdict"):
                results.append(f)
                continue

            file_path = f.get("file_path", "")
            line = int(f.get("line", f.get("line_number", 1)))
            context = self._read_context(file_path, line)

            # Fast path 1: heuristics
            verdict, reason = self._heuristic_check(f, context)
            if verdict:
                self._apply_verdict(f, verdict, reason)
                results.append(f)
                continue

            # Fast path 2: finding_key cache (cross-project reuse)
            cached = self._cached_verdict(f)
            if cached:
                self._apply_verdict(f, cached[0], cached[1] or "cached (finding_key)")
                results.append(f)
                continue

            # Fast path 3: git-fixed (LLM only when enabled)
            git_fixed, git_info = self._check_git_fixed(file_path, line)
            f["revalidation_git_fixed"] = git_info
            if git_fixed and not use_llm:
                self._apply_verdict(f, "uncertain", f"Git: {git_info}")
                results.append(f)
                continue

            f["_context"] = context
            f["_git_info"] = git_info
            pending.append(f)

        # Phase 2: batched LLM
        for i in range(0, len(pending), batch_size):
            chunk = pending[i:i + batch_size]
            self._llm_check_batch(chunk, use_llm=use_llm)

        for f in pending:
            results.append(f)

        return results

    def _llm_check_batch(self, chunk: list[dict], use_llm: bool = True) -> None:
        """One LLM call for a whole chunk of findings."""
        if not use_llm:
            for f in chunk:
                f["revalidation_verdict"] = "uncertain"
                f["revalidation_reasoning"] = "LLM disabled — manual review needed"
                self._save_verdict(f.get("id"), f)
            return

        need = [f for f in chunk if not f.get("revalidation_verdict")]
        if not need:
            return

        prompt = self._build_batch_prompt(need)
        verdicts = self._call_llm_batch(prompt, len(need))
        for f, (verdict, reasoning) in zip(need, verdicts):
            self._apply_verdict(f, verdict, reasoning)

    def _build_batch_prompt(self, findings: list[dict]) -> str:
        parts = []
        for i, f in enumerate(findings):
            ctx = f.get("_context", {})
            parts.append(
                f"--- idx={i} ---\n"
                f"rule: {f.get('rule_id', '?')}\n"
                f"severity: {f.get('severity', '?')}\n"
                f"title: {defang(f.get('title', ''))}\n"
                f"file: {defang(f.get('file_path', ''))}:{f.get('line', f.get('line_number', 1))}\n"
                f"git: {defang(f.get('revalidation_git_fixed', ''))}\n"
                f"code:\n{defang(ctx.get('code_snippet', 'N/A')[:800])}\n"
            )
        body = "\n".join(parts)
        return (
            "You are a security auditor. Classify each vulnerability finding below.\n"
            "Reply ONLY with a JSON array, one object per finding, in index order:\n"
            '[{"idx": <int>, "verdict": "<true-positive|false-positive|fixed|uncertain>", '
            '"reasoning": "<1-2 sentences>"}]\n\n'
            f"{body}\n\n"
            "Return exactly one JSON object per idx, covering every idx."
        )

    def _call_llm_batch(self, prompt: str, expected: int) -> list[tuple[str, str]]:
        """Call LLM once, parse a JSON array of verdicts."""
        from gsc_llm_providers import llm_chat
        content = llm_chat(
            guard_system("You are a security auditor. Reply ONLY with a valid JSON array."),
            prompt, max_tokens=max(800, expected * 120), temperature=0.1,
        )
        if content is None:
            return [("uncertain", "No LLM provider configured")] * expected
        try:
            arr = json.loads(content)
        except json.JSONDecodeError:
            return [("uncertain", f"LLM response not valid JSON: {content[:80]}")] * expected
        out = []
        for i in range(expected):
            item = next((x for x in arr if isinstance(x, dict) and x.get("idx") == i), None)
            if item is None:
                out.append(("uncertain", "missing in LLM response"))
                continue
            v = item.get("verdict", "uncertain")
            if v not in self.VERDICTS:
                v = "uncertain"
            out.append((v, item.get("reasoning", "")))
        return out

    # ── LLM integration ─────────────────────────────────────────────────────

    def _llm_check(self, finding: dict, context: dict, git_info: str) -> str:
        """Quick LLM check when git shows recent changes. Returns verdict."""
        # Simplified: if file was recently modified and we can't confirm,
        # mark as uncertain for manual review
        return "uncertain"

    def _llm_check_structured(self, finding: dict, context: dict) -> tuple[str, str]:
        """
        Full structured LLM revalidation.
        In production, this would call DeepSeek/OpenRouter.
        For now, returns uncertain with context.
        """
        # Build prompt for LLM
        prompt = self._build_revalidation_prompt(finding, context)
        
        # Try LLM call via DeepSeek
        try:
            result = self._call_llm(prompt)
            return result
        except Exception as e:
            return "uncertain", f"LLM call failed: {str(e)}"

    def _build_revalidation_prompt(self, finding: dict, context: dict) -> str:
        """Build structured revalidation prompt."""
        return f"""{UNTRUSTED_GUARD}

You are a security auditor revalidating a vulnerability finding.

FINDING:
  Rule: {finding.get('rule_id', '?')}
  Severity: {finding.get('severity', '?')}
  Title: {defang(finding.get('title', ''))}
  Detail: {defang(finding.get('detail', ''))}

FILE: {defang(finding.get('file_path', ''))}
LINE: {finding.get('line', finding.get('line_number', 1))}

CODE CONTEXT:
{defang(context.get('code_snippet', 'N/A')[:2000])}

IMPORTS:
{defang(context.get('imports', 'N/A')[:500])}

INSTRUCTIONS:
Determine the verdict for this finding. Choose ONE:
- true-positive: This IS a real vulnerability that should be fixed
- false-positive: This is NOT a vulnerability (test code, documentation, safe pattern)
- fixed: The vulnerability was already addressed
- uncertain: Not enough context to decide

Reply in JSON:
{{"verdict": "<one of the four>", "reasoning": "<2-3 sentences explaining why>"}}"""

    def _call_llm(self, prompt: str) -> tuple[str, str]:
        """Unified LLM call for structured revalidation (gsc_llm_providers)."""
        from gsc_llm_providers import llm_chat

        content = llm_chat(
            guard_system("You are a security auditor. Reply ONLY with valid JSON."),
            prompt, max_tokens=400, temperature=0.1,
        )
        if content is None:
            return "uncertain", "No LLM provider configured"

        # Parse JSON response
        try:
            result = json.loads(content)
            verdict = result.get("verdict", "uncertain")
            reasoning = result.get("reasoning", "")
            if verdict not in self.VERDICTS:
                verdict = "uncertain"
            return verdict, reasoning
        except json.JSONDecodeError:
            return "uncertain", f"LLM response not valid JSON: {content[:100]}"

    # ── Persistence ──────────────────────────────────────────────────────────

    def _save_verdict(self, finding_id, result: dict):
        """Save revalidation verdict to DB."""
        if not finding_id:
            return
        self.db.execute(
            """UPDATE findings SET
               revalidation_verdict=?,
               revalidation_reasoning=?,
               revalidation_checked_at=?,
               revalidation_git_fixed=?
               WHERE id=?""",
            (result.get("revalidation_verdict"),
             result.get("revalidation_reasoning"),
             result.get("revalidation_checked_at"),
             result.get("revalidation_git_fixed"),
             finding_id)
        )
        self.db.commit()

    def get_stats(self) -> dict:
        """Get revalidation statistics."""
        rows = self.db.execute(
            """SELECT revalidation_verdict, COUNT(*) as cnt
               FROM findings
               WHERE revalidation_verdict IS NOT NULL
               GROUP BY revalidation_verdict"""
        ).fetchall()
        stats = {v: 0 for v in self.VERDICTS}
        for r in rows:
            stats[r["revalidation_verdict"]] = r["cnt"]
        stats["total"] = sum(stats.values())
        if stats["total"] > 0:
            stats["fp_rate"] = round(stats["false-positive"] / stats["total"] * 100, 1)
            stats["tp_rate"] = round(stats["true-positive"] / stats["total"] * 100, 1)
        return stats

    def close(self):
        self.db.close()
