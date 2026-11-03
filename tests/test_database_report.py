import json
from datetime import datetime

from database import get_connection, create_tables, save_events, save_alerts
from report import build_report


def make_event(raw):
    return {
        "timestamp": datetime(2026, 11, 2, 10, 0, 0),
        "server": "server01",
        "program": "sshd",
        "status": "Failed",
        "user": "admin",
        "ip": "1.1.1.1",
        "port": 22,
        "raw": raw,
    }


def make_alert():
    return {
        "rule": "Repeated failed logins",
        "ip": "1.1.1.1",
        "attempts": 5,
        "first_seen": datetime(2026, 11, 2, 10, 0, 0),
        "last_seen": datetime(2026, 11, 2, 10, 0, 5),
        "users_tried": ["admin"],
        "evidence": ["line one"],
    }


def count_rows(conn, table):
    return conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]


# ---------- Database tests ----------
def test_events_are_saved(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    create_tables(conn)
    save_events(conn, [make_event("a"), make_event("b")])
    assert count_rows(conn, "events") == 2
    conn.close()


def test_duplicate_events_are_ignored(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    create_tables(conn)
    save_events(conn, [make_event("a")])
    save_events(conn, [make_event("a")])
    assert count_rows(conn, "events") == 1
    conn.close()


def test_duplicate_alerts_are_ignored(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    create_tables(conn)
    save_alerts(conn, [make_alert()])
    save_alerts(conn, [make_alert()])
    assert count_rows(conn, "alerts") == 1
    conn.close()


# ---------- Report tests ----------
def test_report_with_no_alerts():
    text = build_report([])
    assert "Total incidents: 0" in text
    assert "No suspicious activity" in text


def test_report_contains_alert_details():
    row = {
        "rule": "Repeated failed logins",
        "ip": "9.9.9.9",
        "attempts": 6,
        "first_seen": "2026-11-02 10:00:00",
        "last_seen": "2026-11-02 10:00:05",
        "users_tried": json.dumps(["admin", "root"]),
        "evidence": json.dumps(["line one", "line two"]),
    }
    text = build_report([row])
    assert "Total incidents: 1" in text
    assert "9.9.9.9" in text
    assert "admin, root" in text
    assert "line one" in text
    assert "line two" in text


def test_report_counts_multiple_incidents():
    row = {
        "rule": "Repeated failed logins",
        "ip": "9.9.9.9",
        "attempts": 5,
        "first_seen": "2026-11-02 10:00:00",
        "last_seen": "2026-11-02 10:00:05",
        "users_tried": json.dumps(["admin"]),
        "evidence": json.dumps(["x"]),
    }
    text = build_report([row, row])
    assert "Total incidents: 2" in text
    assert "Incident 2" in text