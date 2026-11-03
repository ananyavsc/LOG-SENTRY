import json
import os
import sqlite3
import sys

import streamlit as st

# Let the dashboard import our code from the src folder
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from report import build_report

DB_PATH = "logsentry.db"

st.set_page_config(page_title="LogSentry", layout="wide")
st.title("LogSentry Dashboard")

# Stop with a clear message if the database is missing
if not os.path.exists(DB_PATH):
    st.error("Database not found. Run this first: python src/database.py")
    st.stop()

# Read data from SQLite
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
events = [dict(r) for r in conn.execute(
    "SELECT timestamp, server, status, user, ip, port FROM events ORDER BY timestamp"
)]
alerts = [dict(r) for r in conn.execute(
    "SELECT rule, ip, attempts, first_seen, last_seen, users_tried, evidence "
    "FROM alerts ORDER BY first_seen"
)]
conn.close()

# ---------- Sidebar filters ----------
st.sidebar.header("Filters")

status_options = sorted(set(e["status"] for e in events))
ip_options = sorted(set(e["ip"] for e in events))
user_options = sorted(set(e["user"] for e in events))

selected_status = st.sidebar.multiselect("Status", status_options, default=status_options)
selected_ips = st.sidebar.multiselect("IP address", ip_options, default=ip_options)
selected_users = st.sidebar.multiselect("User", user_options, default=user_options)

filtered_events = [
    e for e in events
    if e["status"] in selected_status
    and e["ip"] in selected_ips
    and e["user"] in selected_users
]

# ---------- Summary numbers (follow the filters) ----------
failed_count = sum(1 for e in filtered_events if e["status"] == "Failed")
col1, col2, col3 = st.columns(3)
col1.metric("Events shown", len(filtered_events))
col2.metric("Failed logins shown", failed_count)
col3.metric("Alerts (all)", len(alerts))

# ---------- Download report ----------
st.download_button(
    label="Download incident report",
    data=build_report(alerts),
    file_name="incident_report.md",
    mime="text/markdown",
)

# ---------- Alerts with evidence ----------
st.header("Alerts")
if not alerts:
    st.info("No alerts found.")
for alert in alerts:
    title = f"{alert['rule']} | IP {alert['ip']} | {alert['attempts']} attempts"
    with st.expander(title, expanded=True):
        st.write("**From:**", alert["first_seen"], " **To:**", alert["last_seen"])
        st.write("**Users tried:**", ", ".join(json.loads(alert["users_tried"])))
        st.write("**Evidence:**")
        st.code("\n".join(json.loads(alert["evidence"])))

# ---------- Events table ----------
st.header("Events")
if filtered_events:
    st.dataframe(filtered_events, use_container_width=True)
else:
    st.warning("No events match the selected filters.")