from datetime import timedelta
from parser import parse_file


def detect_bruteforce(events, threshold=5, window_seconds=60):
    """Find IPs with `threshold` or more failed logins inside the time window."""
    # 1. Group failed logins by IP
    failed_by_ip = {}
    for event in events:
        if event["status"] == "Failed":
            failed_by_ip.setdefault(event["ip"], []).append(event)

    alerts = []
    window = timedelta(seconds=window_seconds)

    for ip, failures in failed_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])

        start = 0
        alert_made = False
        for end in range(len(failures)):
            # Move the start forward until the window is small enough
            while failures[end]["timestamp"] - failures[start]["timestamp"] > window:
                start += 1

            count = end - start + 1
            if count >= threshold and not alert_made:
                evidence = failures[start:end + 1]
                alerts.append({
                    "rule": "Repeated failed logins",
                    "ip": ip,
                    "attempts": count,
                    "first_seen": evidence[0]["timestamp"],
                    "last_seen": evidence[-1]["timestamp"],
                    "users_tried": sorted(set(e["user"] for e in evidence)),
                    "evidence": [e["raw"] for e in evidence],
                })
                alert_made = True  # one alert per IP for now

    return alerts


if __name__ == "__main__":
    events, malformed, blank_count = parse_file("data/sample_logs/auth_sample.log")
    alerts = detect_bruteforce(events, threshold=8, window_seconds=60)

    print("Alerts found:", len(alerts))
    for alert in alerts:
        print()
        print("Rule:", alert["rule"])
        print("IP:", alert["ip"])
        print("Attempts:", alert["attempts"])
        print("From:", alert["first_seen"], "To:", alert["last_seen"])
        print("Users tried:", alert["users_tried"])
        print("Evidence:")
        for line in alert["evidence"]:
            print("  ", line)