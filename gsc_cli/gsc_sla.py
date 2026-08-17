"""MTTFV SLA — Mean Time To Verified Fix, скорость реагирования организации.

archaeology (gsc_archaeology.py) меряет ВОЗРАСТ уязвимости: introduced→fixed
через git blame (сколько баг жил в коде). Этот модуль меряет СКОРОСТЬ РЕАГИРОВАНИЯ:
сколько прошло от ДЕТЕКЦИИ (findings.created_at) до ВЕРИФИЦИРОВАННОГО фикса
(findings.resolved_at). Комплементарная метрика — не дублирует archaeology.

SLA-пороги (отраслевой стандарт): CRITICAL 1д, HIGH 7д, MEDIUM 30д, LOW 90д.
`sla_compliance` = доля фиксов, уложившихся в порог своего severity.

CLI: gsc.py sla [--days 90] [--by category|rule|project]
"""
from __future__ import annotations

import sqlite3
import statistics
from datetime import datetime
from pathlib import Path
from typing import Optional

SLA_THRESHOLDS_DAYS = {"CRITICAL": 1, "HIGH": 7, "MEDIUM": 30, "LOW": 90}
DEFAULT_DB = Path.home() / ".hermes" / "state" / "gsc_audit.db"


def _parse_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def load_resolved(db_path: Optional[str] = None) -> list[dict]:
    """Все устранённые находки (resolved_at не пуст). Сырые строки, без парсинга."""
    path = Path(db_path) if db_path else DEFAULT_DB
    if not path.exists():
        return []
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute(
                "SELECT category, rule_id, project, created_at, resolved_at "
                "FROM findings WHERE resolved_at IS NOT NULL AND resolved_at != ''"
            ).fetchall()
        except sqlite3.OperationalError:
            # старые схемы без колонки project
            rows = conn.execute(
                "SELECT category, rule_id, created_at, resolved_at "
                "FROM findings WHERE resolved_at IS NOT NULL AND resolved_at != ''"
            ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _time_to_fix_days(row: dict, days_window: Optional[int]) -> Optional[float]:
    created = _parse_ts(row.get("created_at"))
    resolved = _parse_ts(row.get("resolved_at"))
    if not created or not resolved or resolved < created:
        return None
    if days_window is not None and days_window >= 0:
        age = (datetime.now() - created).total_seconds() / 86400.0
        if age > days_window:
            return None
    return (resolved - created).total_seconds() / 86400.0


def _bucket(days: list[float], threshold: Optional[float]) -> dict:
    if not days:
        return {"count": 0, "mean_days": None, "median_days": None,
                "p90_days": None, "sla_compliance": None}
    s = sorted(days)
    p90 = s[min(len(s) - 1, int(len(s) * 0.9))]
    out = {
        "count": len(days),
        "mean_days": round(statistics.mean(days), 1),
        "median_days": round(statistics.median(days), 1),
        "p90_days": round(p90, 1),
    }
    out["sla_compliance"] = (round(sum(1 for d in days if d <= threshold) / len(days), 3)
                             if threshold is not None else None)
    return out


def compute_mttfv(rows: list[dict], group_by: str = "category",
                  days_window: Optional[int] = None) -> dict:
    """Агрегирует time-to-fix по группам. rows — сырые dict из load_resolved.

    threshold применяется только при group_by == 'category' (SLA-порог по severity).
    """
    groups: dict[str, list[float]] = {}
    total: list[float] = []
    field = "rule_id" if group_by == "rule" else group_by
    for r in rows:
        d = _time_to_fix_days(r, days_window)
        if d is None:
            continue
        total.append(d)
        key = str(r.get(field) or "unknown")
        groups.setdefault(key, []).append(d)

    by_group = {}
    for k, v in sorted(groups.items()):
        threshold = SLA_THRESHOLDS_DAYS.get(k.upper()) if group_by == "category" else None
        by_group[k] = _bucket(v, threshold)

    return {
        "group_by": group_by,
        "total": _bucket(total, None),
        "groups": by_group,
        "thresholds_days": SLA_THRESHOLDS_DAYS,
    }


def sla_report(days: int = 90, group_by: str = "category",
               db_path: Optional[str] = None) -> dict:
    return compute_mttfv(load_resolved(db_path), group_by=group_by, days_window=days)
