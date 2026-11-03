# LogSentry

A beginner-friendly, defensive security tool that reads SSH-style login logs, detects repeated failed logins, shows alerts with evidence, and writes a plain-English incident report.

Built as a learning project using only synthetic logs. Everything is rule-based and free.

## Features
- Parses SSH-style authentication logs and safely skips malformed lines
- Detects repeated failed logins from one IP (configurable threshold and time window)
- Stores events and alerts in SQLite without duplicates
- Streamlit dashboard with alerts, evidence, filters and a report download
- Generates a Markdown incident report
- 14 automated tests with pytest

## Architecture
See [docs/architecture.md](docs/architecture.md).

## Screenshots
![Dashboard](docs/dashboard.png)
![Filtered dashboard](docs/dashboard_filtered.png)

## How to run
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src/database.py
streamlit run dashboard/app.py
python src/report.py
pytest
```

## Detection rule
An alert is raised when one IP has at least 5 failed logins within 60 seconds. Both values can be changed in `detect_bruteforce()`.

## Limitations
Tested only on a small synthetic log file and unit tests. No accuracy figures are claimed. See [docs/limitations.md](docs/limitations.md).

## Tech stack
Python, SQLite, Streamlit, pytest, Git and GitHub.