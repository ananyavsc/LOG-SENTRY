import re
from datetime import datetime

# One pattern that matches a valid SSH login line
LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "   # timestamp
    r"(\S+) "                                    # server name
    r"(\S+): "                                   # program, e.g. sshd
    r"(Accepted|Failed) password for "           # status
    r"(?:invalid user )?"                        # optional text
    r"(\S+) from "                               # username
    r"(\d{1,3}(?:\.\d{1,3}){3}) "                # IP address
    r"port (\d+)$"                               # port
)


def parse_line(line):
    """Return a dict for a valid line, or None for a bad line."""
    match = LOG_PATTERN.match(line.strip())
    if match is None:
        return None

    timestamp_text, server, program, status, user, ip, port = match.groups()

    # Check the date is real (this rejects 2026-13-45 99:99:99)
    try:
        timestamp = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "server": server,
        "program": program,
        "status": status,
        "user": user,
        "ip": ip,
        "port": int(port),
        "raw": line.strip(),
    }


def parse_file(path):
    """Read a log file. Return (events, malformed, blank_count)."""
    events = []
    malformed = []
    blank_count = 0

    with open(path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if line.strip() == "":
                blank_count += 1
                continue
            event = parse_line(line)
            if event is None:
                malformed.append((line_number, line.strip()))
            else:
                events.append(event)

    return events, malformed, blank_count


if __name__ == "__main__":
    events, malformed, blank_count = parse_file("data/sample_logs/auth_sample.log")
    print("Parsed events:", len(events))
    print("Malformed lines:", len(malformed))
    print("Blank lines skipped:", blank_count)
    print()
    print("First event:")
    print(events[0])
    print()
    print("Malformed line details:")
    for number, text in malformed:
        print("  Line", number, "->", text)