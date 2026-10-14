from collections import defaultdict, deque


def detect_bruteforce(events, threshold=5, window_minutes=5):
    windows = defaultdict(deque)
    alerts = []

    events = sorted(
        events,
        key=lambda x: x["timestamp"]
    )

    seen = set()

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

            severity = (
                "Critical"
                if attempt_count >= 10
                else "High"
            )

            alerts.append({
                "source_ip": event["ip"],
                "target_user": event["user"],
                "failed_attempts": attempt_count,
                "window_minutes": window_minutes,
                "severity": severity
            })

            seen.add(key)

    return alerts