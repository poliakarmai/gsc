"""Тесты gsc_sla — MTTFV SLA (скорость реагирования организации)."""
import sqlite3

from gsc_sla import load_resolved, compute_mttfv, sla_report, _parse_ts


def _row(category, created, resolved, rule_id="GS001", project="p"):
    return {"category": category, "rule_id": rule_id, "project": project,
            "created_at": created, "resolved_at": resolved}


def test_parse_ts_formats():
    assert _parse_ts("2026-08-01 00:00:00") is not None
    assert _parse_ts("2026-08-01T00:00:00+00:00") is not None
    assert _parse_ts("2026-08-01T00:00:00Z") is not None
    assert _parse_ts(None) is None
    assert _parse_ts("") is None


def test_critical_within_sla():
    rows = [_row("CRITICAL", "2026-08-01 00:00:00", "2026-08-01 12:00:00")]  # 0.5д
    r = compute_mttfv(rows)
    g = r["groups"]["CRITICAL"]
    assert g["count"] == 1
    assert g["median_days"] == 0.5
    assert g["sla_compliance"] == 1.0  # 0.5 <= 1д


def test_high_partial_compliance():
    rows = [
        _row("HIGH", "2026-08-01 00:00:00", "2026-08-04 00:00:00"),   # 3д  <= 7д
        _row("HIGH", "2026-08-01 00:00:00", "2026-08-10 00:00:00"),   # 9д  > 7д
    ]
    g = compute_mttfv(rows)["groups"]["HIGH"]
    assert g["count"] == 2
    assert g["median_days"] == 6.0
    assert g["mean_days"] == 6.0
    assert g["sla_compliance"] == 0.5


def test_resolved_before_created_skipped():
    rows = [_row("LOW", "2026-08-10 00:00:00", "2026-08-01 00:00:00")]
    assert compute_mttfv(rows)["total"]["count"] == 0


def test_group_by_rule():
    rows = [
        _row("HIGH", "2026-08-01 00:00:00", "2026-08-02 00:00:00", rule_id="GS001"),
        _row("HIGH", "2026-08-01 00:00:00", "2026-08-03 00:00:00", rule_id="GS029"),
    ]
    r = compute_mttfv(rows, group_by="rule")
    assert set(r["groups"]) == {"GS001", "GS029"}
    # при group_by != category SLA-порог не применяется
    assert r["groups"]["GS001"]["sla_compliance"] is None


def test_load_resolved_from_db(tmp_path):
    db = tmp_path / "t.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE findings (category TEXT, rule_id TEXT, project TEXT, "
                 "created_at TEXT, resolved_at TEXT)")
    conn.execute("INSERT INTO findings VALUES "
                 "('HIGH','GS001','p','2026-08-01 00:00:00','2026-08-05 00:00:00')")
    conn.execute("INSERT INTO findings VALUES "
                 "('HIGH','GS001','p','2026-08-01 00:00:00',NULL)")
    conn.commit()
    conn.close()
    rows = load_resolved(str(db))
    assert len(rows) == 1
    assert rows[0]["category"] == "HIGH"
    assert rows[0]["resolved_at"] == "2026-08-05 00:00:00"


def test_sla_report_end_to_end(tmp_path):
    db = tmp_path / "t.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE findings (category TEXT, rule_id TEXT, project TEXT, "
                 "created_at TEXT, resolved_at TEXT)")
    conn.execute("INSERT INTO findings VALUES "
                 "('CRITICAL','GS029','p','2026-08-01 00:00:00','2026-08-01 06:00:00')")
    conn.commit()
    conn.close()
    r = sla_report(db_path=str(db), days=90, group_by="category")
    assert r["total"]["count"] == 1
    assert r["groups"]["CRITICAL"]["sla_compliance"] == 1.0
