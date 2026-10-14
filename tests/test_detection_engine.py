from datetime import datetime, timedelta

from detection_engine import detect_bruteforce


def make_event(minutes, ip="192.168.1.50", user="admin"):
    base = datetime(
        2026, 10, 14, 10, 0, 0
    )

    return {
        "timestamp": base + timedelta(minutes=minutes),
        "ip": ip,
        "user": user
    }


def test_four_attempts_no_alert():
    events = [
        make_event(0),
        make_event(1),
        make_event(2),
        make_event(3),
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 0


def test_five_attempts_trigger_alert():
    events = [
        make_event(0),
        make_event(1),
        make_event(2),
        make_event(3),
        make_event(4),
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["failed_attempts"] == 5


def test_attempts_outside_window_no_alert():
    events = [
        make_event(0),
        make_event(10),
        make_event(20),
        make_event(30),
        make_event(40),
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 0


def test_multiple_ips():
    events = [
        make_event(0, "192.168.1.50"),
        make_event(1, "192.168.1.50"),
        make_event(2, "192.168.1.50"),
        make_event(3, "192.168.1.50"),
        make_event(4, "192.168.1.50"),

        make_event(0, "192.168.1.80"),
        make_event(1, "192.168.1.80"),
        make_event(2, "192.168.1.80"),
        make_event(3, "192.168.1.80"),
        make_event(4, "192.168.1.80"),
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 2


def test_different_users_are_separate():
    events = [
        make_event(0, user="admin"),
        make_event(1, user="admin"),
        make_event(2, user="admin"),

        make_event(0, user="root"),
        make_event(1, user="root"),
        make_event(2, user="root"),
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 0