#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""
GSC Finding Router — label-driven FSM for finding lifecycle.

Inspired by triagebot-action's router.ts (withastro/triagebot-action).
Routes events to handlers based on current finding state + event type.

States (GitHub-label style):
  new → triage → confirmed → fix_pending → fix_verified
                  ↘ fp (false positive)
                  ↘ wontfix

Events:
  finding_created   — новый finding из сканера
  fp_reported       — пользователь пометил как FP
  fix_pushed        — PR с фиксом создан
  fix_confirmed     — фикс проверен репортёром
  fix_rejected      — фикс отклонён
  comment_added     — новый комментарий (для re-triage)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


# ── States ────────────────────────────────────────────────────────────

class FindingState(Enum):
    NEW = "new"                    # только создан, не проверен
    TRIAGE = "triage"              # в процессе триажа
    CONFIRMED = "confirmed"        # подтверждён — реальная уязвимость
    FP = "fp"                      # false positive
    WONTFIX = "wontfix"            # признан, но не будем чинить
    FIX_PENDING = "fix_pending"    # фикс готов, ждёт верификации
    FIX_VERIFIED = "fix_verified"  # фикс проверен репортёром
    FIX_REJECTED = "fix_rejected"  # фикс не работает
    CLOSED = "closed"              # закрыт (verified или fp/wontfix)
    FAILED = "failed"              # ошибка в процессе


# Allowed transitions
TRANSITIONS: dict[FindingState, set[FindingState]] = {
    FindingState.NEW:           {FindingState.TRIAGE, FindingState.FP, FindingState.CLOSED},
    FindingState.TRIAGE:        {FindingState.CONFIRMED, FindingState.FP, FindingState.WONTFIX, FindingState.FAILED},
    FindingState.CONFIRMED:     {FindingState.FIX_PENDING, FindingState.WONTFIX},
    FindingState.FP:            {FindingState.CLOSED, FindingState.TRIAGE},  # can re-triage
    FindingState.WONTFIX:       {FindingState.CLOSED},
    FindingState.FIX_PENDING:   {FindingState.FIX_VERIFIED, FindingState.FIX_REJECTED, FindingState.FAILED},
    FindingState.FIX_VERIFIED:  {FindingState.CLOSED},
    FindingState.FIX_REJECTED:  {FindingState.TRIAGE},  # back to triage with new info
    FindingState.CLOSED:        set(),  # terminal
    FindingState.FAILED:        {FindingState.TRIAGE},  # retry up to 3 times
}


# ── Events ────────────────────────────────────────────────────────────

@dataclass
class FindingEvent:
    type: str                    # finding_created | fp_reported | fix_pushed | ...
    finding_key: str
    finding_id: str = ""
    rule_id: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.0
    actor: str = ""              # who triggered (user/bot)
    comment: str = ""            # optional comment text
    pr_number: int = 0
    pr_url: str = ""
    attempt: int = 0             # retry counter for FAILED→TRIAGE
    metadata: dict = field(default_factory=dict)


@dataclass
class Action:
    type: str                    # auto_confirm | request_review | create_pr | ...
    finding_key: str
    target_state: FindingState
    reason: str = ""
    metadata: dict = field(default_factory=dict)

    SKIP = "skip"                # do nothing


# ── Router ────────────────────────────────────────────────────────────

class FindingRouter:
    """FSM router for finding lifecycle. Pure function: event + state → action."""

    def __init__(self, max_retries: int = 3, auto_confirm_threshold: float = 0.9):
        self.max_retries = max_retries
        self.auto_confirm_threshold = auto_confirm_threshold

    def route(self, event: FindingEvent, current_state: FindingState) -> Action:
        """Route event to action based on current state."""

        if event.type == "finding_created":
            return self._on_created(event, current_state)

        if event.type == "fp_reported":
            return self._on_fp(event, current_state)

        if event.type == "fix_pushed":
            return self._on_fix_pushed(event, current_state)

        if event.type == "fix_confirmed":
            return self._on_fix_confirmed(event, current_state)

        if event.type == "fix_rejected":
            return self._on_fix_rejected(event, current_state)

        if event.type == "comment_added":
            return self._on_comment(event, current_state)

        return Action(Action.SKIP, event.finding_key, current_state,
                      f"No handler for event '{event.type}' in state '{current_state.value}'")

    # ── Event handlers ──────────────────────────────────────────

    def _on_created(self, e: FindingEvent, s: FindingState) -> Action:
        if s != FindingState.NEW:
            return Action(Action.SKIP, e.finding_key, s, "Not in NEW state")

        # High confidence + high severity = auto-confirm
        if e.confidence >= self.auto_confirm_threshold and e.severity in ("CRITICAL", "HIGH"):
            return Action("auto_confirm", e.finding_key, FindingState.CONFIRMED,
                         f"Auto-confirmed: confidence={e.confidence:.2f}, severity={e.severity}")

        # Low confidence = might be FP, needs human review
        if e.confidence < 0.5:
            return Action("request_review", e.finding_key, FindingState.TRIAGE,
                         f"Low confidence ({e.confidence:.2f}) — needs human review",
                         metadata={"review_type": "manual", "reason": "low_confidence"})

        # Default: start triage
        return Action("start_triage", e.finding_key, FindingState.TRIAGE,
                     f"Starting triage: {e.rule_id}")

    def _on_fp(self, e: FindingEvent, s: FindingState) -> Action:
        if s in (FindingState.NEW, FindingState.TRIAGE, FindingState.FP):
            return Action("mark_fp", e.finding_key, FindingState.FP,
                         f"Marked as false positive by {e.actor}",
                         metadata={"fp_source": e.actor, "fp_reason": e.comment})
        return Action(Action.SKIP, e.finding_key, s, f"Can't mark FP from '{s.value}' state")

    def _on_fix_pushed(self, e: FindingEvent, s: FindingState) -> Action:
        if s != FindingState.CONFIRMED:
            return Action(Action.SKIP, e.finding_key, s,
                         f"Can't push fix from '{s.value}' — must be CONFIRMED")
        return Action("verify_fix", e.finding_key, FindingState.FIX_PENDING,
                     f"Fix pushed: PR #{e.pr_number} — awaiting verification",
                     metadata={"pr_number": e.pr_number, "pr_url": e.pr_url})

    def _on_fix_confirmed(self, e: FindingEvent, s: FindingState) -> Action:
        if s != FindingState.FIX_PENDING:
            return Action(Action.SKIP, e.finding_key, s, "Not in FIX_PENDING")
        return Action("close_verified", e.finding_key, FindingState.FIX_VERIFIED,
                     f"Fix verified by {e.actor}")

    def _on_fix_rejected(self, e: FindingEvent, s: FindingState) -> Action:
        if s != FindingState.FIX_PENDING:
            return Action(Action.SKIP, e.finding_key, s, "Not in FIX_PENDING")
        return Action("reopen_triage", e.finding_key, FindingState.FIX_REJECTED,
                     f"Fix rejected by {e.actor}: {e.comment}",
                     metadata={"rejection_reason": e.comment})

    def _on_comment(self, e: FindingEvent, s: FindingState) -> Action:
        # Re-triageable states: FP, WONTFIX, FIX_REJECTED, FAILED
        retriageable = {FindingState.FP, FindingState.WONTFIX,
                        FindingState.FIX_REJECTED, FindingState.FAILED}

        if s == FindingState.FAILED:
            if e.attempt >= self.max_retries:
                return Action("give_up", e.finding_key, FindingState.WONTFIX,
                             f"Max retries ({self.max_retries}) reached — giving up")
            # Retry with incremented attempt counter
            return Action("retry_triage", e.finding_key, FindingState.TRIAGE,
                         f"Retry #{e.attempt + 1}/{self.max_retries}",
                         metadata={"attempt": e.attempt + 1})

        if s in retriageable:
            return Action("retriage", e.finding_key, FindingState.TRIAGE,
                         f"Re-triaging from '{s.value}' — new comment with info",
                         metadata={"previous_state": s.value})

        return Action(Action.SKIP, e.finding_key, s,
                     f"State '{s.value}' is not re-triageable")


# ── Integration helpers ───────────────────────────────────────────────

def transition_is_valid(from_state: FindingState, to_state: FindingState) -> bool:
    """Check if transition is allowed."""
    return to_state in TRANSITIONS.get(from_state, set())


def next_state(action: Action) -> FindingState:
    """Extract target state from action."""
    return action.target_state
