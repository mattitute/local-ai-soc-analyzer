from collections import defaultdict, deque


def detect_bruteforce(events, threshold=5, window_minutes=5):
    windows = defaultdict(deque)
    alerts = []
    seen = set()

    events = sorted(
        events,
        key=lambda x: x["timestamp"]
    )

    for event in events:
        key = (
            event["ip"],
            event["user"]
        )

        current_time = event["timestamp"]

        windows[key].append(current_time)

        while windows[key]:
            oldest = windows[key][0]

            difference_seconds = (
                current_time - oldest
            ).total_seconds()

            if difference_seconds > window_minutes * 60:
                windows[key].popleft()
            else:
                break

        attempt_count = len(windows[key])

        if attempt_count >= threshold and key not in seen:

            if attempt_count >= 10:
                severity = "Critical"
            else:
                severity = "High"

            alerts.append({
                "detection_type": "Possible Brute Force",
                "source_ip": event["ip"],
                "target_user": event["user"],
                "failed_attempts": attempt_count,
                "window_minutes": window_minutes,
                "detection_threshold": threshold,
                "first_attempt": windows[key][0].isoformat(),
                "last_attempt": windows[key][-1].isoformat(),
                "severity": severity,
                "mitre_technique": "T1110 - Brute Force",
                "mitre_subtechnique": "T1110.001 - Password Guessing",
                "log_source": event.get(
                    "log_source",
                    "unknown"
                )
            })

            seen.add(key)

    return alerts