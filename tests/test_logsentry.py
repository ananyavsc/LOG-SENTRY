from datetime import datetime
from parser import parse_line, parse_file
from detector import detect_bruteforce


def make_failed(ip, second):
    """Helper: build a fake failed-login event."""
    return {
        "timestamp": datetime(2026, 11, 2, 10, 0, second),
        "status": "Failed",
        "user": "admin",
        "ip": ip,
        "raw": "fake line " + str(second),
    }


# ---------- Parser tests ----------
def test_valid_line_is_parsed():
    line = "2026-11-02 10:05:03 server01 sshd: Failed password for alice from 192.168.1.10 port 22"
    event = parse_line(line)
    assert event["status"] == "Failed"
    assert event["user"] == "alice"
    assert event["ip"] == "192.168.1.10"
    assert event["port"] == 22


def test_broken_line_returns_none():
    assert parse_line("this line is broken and has no proper format") is None


def test_impossible_date_returns_none():
    line = "2026-13-45 99:99:99 server01 sshd: Failed password for bob from 192.168.1.11 port 22"
    assert parse_line(line) is None


def test_sample_file_counts():
    events, malformed, blank_count = parse_file("data/sample_logs/auth_sample.log")
    assert len(events) == 15
    assert len(malformed) == 2
    assert blank_count == 1


# ---------- Detector tests ----------
def test_attack_is_detected():
    events = [make_failed("1.1.1.1", s) for s in range(0, 6)]  # 6 failures in 5 seconds
    alerts = detect_bruteforce(events, threshold=5, window_seconds=60)
    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 6


def test_normal_activity_not_flagged():
    events = [make_failed("2.2.2.2", s) for s in range(0, 3)]  # only 3 failures
    alerts = detect_bruteforce(events, threshold=5, window_seconds=60)
    assert alerts == []


def test_slow_failures_not_flagged():
    # 5 failures, but each 30 seconds apart (outside a 60 second window)
    events = [make_failed("3.3.3.3", s) for s in (0, 30)]
    events += [
        {**make_failed("3.3.3.3", 0), "timestamp": datetime(2026, 11, 2, 10, m, 0)}
        for m in (1, 2, 3)
    ]
    alerts = detect_bruteforce(events, threshold=5, window_seconds=60)
    assert alerts == []


def test_threshold_is_configurable():
    events = [make_failed("4.4.4.4", s) for s in range(0, 4)]  # 4 failures
    assert detect_bruteforce(events, threshold=5, window_seconds=60) == []
    assert len(detect_bruteforce(events, threshold=4, window_seconds=60)) == 1