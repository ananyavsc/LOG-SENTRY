import json
import os
import sqlite3
from datetime import datetime

DB_PATH = "logsentry.db"
REPORT_PATH = "reports/incident_report.md"


def load_alerts(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(
        "SELECT rule, ip, attempts, first_seen, last_seen, users_tried, evidence "
        "FROM alerts ORDER BY first_seen"
    )]
    conn.close()
    return rows


def build_report(alerts):
    lines = []
    lines.append("# LogSentry Incident Report")
    lines.append("")
    lines.append("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")
    lines.append("Total incidents: " + str(len(alerts)))
    lines.append("")

    if not alerts:
        lines.append("No suspicious activity was detected in the analysed logs.")
        return "\n".join(lines)

    for number, a in enumerate(alerts, start=1):
        users = json.loads(a["users_tried"])
        evidence = json.loads(a["evidence"])

        lines.append("## Incident " + str(number) + ": " + a["rule"])
        lines.append("")
        lines.append("- **Source IP:** " + a["ip"])
        lines.append("- **Failed attempts:** " + str(a["attempts"]))
        lines.append("- **First seen:** " + a["first_seen"])
        lines.append("- **Last seen:** " + a["last_seen"])
        lines.append("- **Usernames tried:** " + ", ".join(users))
        lines.append("")
        lines.append("### What happened")
        lines.append(
            "The IP address " + a["ip"] + " made " + str(a["attempts"])
            + " failed login attempts between " + a["first_seen"] + " and "
            + a["last_seen"] + ", trying these usernames: " + ", ".join(users)
            + ". Many failures from one address in a short time is a common "
            "sign of a brute-force password guessing attempt."
        )
        lines.append("")
        lines.append("### Detection rule")
        lines.append(
            "An alert is raised when one IP address has at least the "
            "configured number of failed logins inside the configured time "
            "window (default: 5 failures within 60 seconds)."
        )
        lines.append("")
        lines.append("### Evidence")
        lines.append("```")
        lines.extend(evidence)
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def save_report(text, path=REPORT_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        file.write(text)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("Database not found. Run this first: python src/database.py")
    else:
        report_text = build_report(load_alerts())
        save_report(report_text)
        print("Report saved to", REPORT_PATH)