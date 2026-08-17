#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единый источник подписи GSC для PR и commit-сообщений.

Используется во всех местах, где GSC создаёт PR или коммит:
- gsc_selfhealing.py (Self-Healing CI)
- gsc_proofoffix.py (Proof-of-Fix с --create-pr)
- gsc_github_adapter.py (GitHub PR Adapter)

Поведение управляется через env (читается в рантайме, не на уровне модуля):
- GSC_SIGNATURE_ENABLED  "0" отключает подпись (по умолчанию включена)
- GSC_SIGNATURE_MODE     "short" | "full" (по умолчанию full)
- GSC_SIGNATURE_URL      переопределяет URL репозитория
- GSC_SIGNATURE_COAUTHOR строка "Name <email>" для Co-authored-by трейлера
                         (пусто по умолчанию — no-op до создания GitHub App gsc-bot)
"""
from __future__ import annotations

import os
from typing import Literal

DEFAULT_REPO_URL = "https://github.com/poliakarmai/gsc"
DEFAULT_MODE = "full"


def _enabled() -> bool:
    return os.environ.get("GSC_SIGNATURE_ENABLED", "1") == "1"


def _repo_url() -> str:
    return os.environ.get("GSC_SIGNATURE_URL", DEFAULT_REPO_URL)


def _mode() -> str:
    return os.environ.get("GSC_SIGNATURE_MODE", DEFAULT_MODE)


def _version() -> str:
    """Версия приложения — SSOT в gsc_meta._read_version() (файл VERSION)."""
    try:
        from gsc_meta import _read_version
        return _read_version()
    except Exception:
        return "unknown"


def pr_signature(
    *,
    verified: bool = False,
    poc_success: bool = False,
    rule_id: str | None = None,
    mode: Literal["short", "full"] | None = None,
) -> str:
    """Markdown-подпись для body PR.

    Args:
        verified: PoF-вердикт verified.
        poc_success: PoC сработал до фикса и не сработал после.
        rule_id: идентификатор детектора (GS005, GS020, ...).
        mode: переопределение режима (short/full).

    Returns:
        Пустая строка, если подпись отключена; иначе markdown-блок.
    """
    if not _enabled():
        return ""

    mode = mode or _mode()
    repo_link = f"[GSC]({_repo_url()})"

    if mode == "short":
        return (
            f"\n\n---\n"
            f"🔒 Powered by {repo_link} — self-learning AppSec platform"
        )

    lines = [
        "",
        "---",
        f"🔒 **Powered by {repo_link}**",
        "",
        "<sub>",
        f"This fix was automatically generated and verified by GSC ({_version()}).",
    ]

    if verified and poc_success:
        lines.append(
            "**Proof-of-Fix**: exploit was generated, patch applied, "
            "and re-exploitation failed in an isolated sandbox — the fix "
            "is provably effective."
        )
    elif verified:
        lines.append("**Proof-of-Fix**: patch was verified by GSC sandbox.")
    elif poc_success:
        lines.append(
            "**PoC**: exploit was generated to confirm the vulnerability "
            "before the patch."
        )

    if rule_id:
        lines.append(f"Detected by rule `{rule_id}`.")

    lines.append("GSC is free and open-source.")
    lines.append("</sub>")

    return "\n".join(lines)


def commit_signature() -> str:
    """Подпись для commit message (trailer)."""
    if not _enabled():
        return ""
    return f"GSC-Signed-By: {_repo_url()}"


def co_author_trailer() -> str:
    """Co-authored-by трейлер.

    Пуст, пока не задан GSC_SIGNATURE_COAUTHOR — до создания GitHub App gsc-bot
    это тихий no-op (несуществующий аккаунт GitHub не линкует).
    """
    if not _enabled():
        return ""
    bot = os.environ.get("GSC_SIGNATURE_COAUTHOR", "")
    if not bot:
        return ""
    return f"Co-authored-by: {bot}"


def label_name() -> str:
    """Имя label'а, который GSC ставит на свои верифицированные PR."""
    return "gsc-verified" if _enabled() else ""


def badge_markdown() -> str:
    """Опциональный badge для PR body (shields.io)."""
    if not _enabled():
        return ""
    return (
        f"[![GSC verified]"
        f"(https://img.shields.io/badge/GSC-verified-2ea44f?logo=github)]"
        f"({_repo_url()})"
    )


def comment_signature() -> str:
    """Короткая подпись для PR-комментариев гейта (не fix-отчётов).

    В отличие от pr_signature (🔒 verified fix) — здесь GSC выступает
    сканером чужих PR, поэтому подпись «Scanned by», без Proof-of-Fix.
    """
    if not _enabled():
        return ""
    return (
        f"\n\n---\n"
        f"🔍 Scanned by [GSC]({_repo_url()}) — self-learning AppSec platform"
    )


def sign_commit_message(message: str, *, add_coauthor: bool = False) -> str:
    """Добавляет GSC-трейлеры к commit message.

    Args:
        message: исходное сообщение.
        add_coauthor: добавлять Co-authored-by (False по умолчанию — бота пока нет).
    """
    trailers = [commit_signature()]
    if add_coauthor:
        trailers.append(co_author_trailer())
    trailers_text = "\n".join(t for t in trailers if t)
    if not trailers_text:
        return message
    return f"{message.rstrip()}\n\n{trailers_text}"
