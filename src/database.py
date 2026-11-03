import sqlite3
import json
from parser import parse_file
from detector import detect_bruteforce

DB_PATH = "logsentry.db"


def get_connection(db_path=DB_PATH):
    return sqlite3.connect(db_path)


def create_tables(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            server TEXT,
            program TEXT,
            status TEXT NOT NULL,
            user TEXT,
            ip TEXT NOT NULL,
            port INTEGER,
            raw TEXT NOT NULL UNIQUE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule TEXT NOT NULL,
            ip TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            users_tried TEXT,
            evidence TEXT,
            UNIQUE (rule, ip, first_seen, last_seen)
        )
    """)
    conn.commit()


def save_events(conn, events):
    for e in events:
        conn.execute(
            "INSERT OR IGNORE INTO events "
            "(timestamp, server, program, status, user, ip, port, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(e["timestamp"]), e["server"], e["program"], e["status"],
             e["user"], e["ip"], e["port"], e["raw"]),
        )
    conn.commit()


def save_alerts(conn, alerts):
    for a in alerts:
        conn.execute(
            "INSERT OR IGNORE INTO alerts "
            "(rule, ip, attempts, first_seen, last_seen, users_tried, evidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (a["rule"], a["ip"], a["attempts"], str(a["first_seen"]),
             str(a["last_seen"]), json.dumps(a["users_tried"]),
             json.dumps(a["evidence"])),
        )
    conn.commit()


def get_alerts(conn):
    rows = conn.execute(
        "SELECT rule, ip, attempts, first_seen, last_seen, users_tried "
        "FROM alerts ORDER BY first_seen"
    ).fetchall()
    return rows


if __name__ == "__main__":
    events, malformed, blank_count = parse_file("data/sample_logs/auth_sample.log")
    alerts = detect_bruteforce(events, threshold=5, window_seconds=60)

    conn = get_connection()
    create_tables(conn)
    save_events(conn, events)
    save_alerts(conn, alerts)

    event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print("Events in database:", event_count)
    print("Alerts in database:", alert_count)
    for row in get_alerts(conn):
        print(row)
    conn.close()