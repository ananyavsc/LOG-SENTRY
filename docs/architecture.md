# LogSentry Architecture

```mermaid
flowchart TD
    A[Log files<br/>data/sample_logs] --> B[Parser<br/>src/parser.py]
    B --> C[Detector<br/>src/detector.py]
    C --> D[(SQLite database<br/>logsentry.db)]
    B --> D
    D --> E[Streamlit dashboard<br/>dashboard/app.py]
    D --> F[Incident report<br/>src/report.py]
```

- **Parser:** turns each valid line into a structured event and skips bad lines.
- **Detector:** finds many failed logins from one IP in a short time.
- **Database:** stores events and alerts, and blocks duplicates.
- **Dashboard:** shows alerts, evidence and filters, with a report download.
- **Report:** writes a plain-English incident report.
