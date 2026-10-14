import re
import json
import requests
from collections import defaultdict, deque
from datetime import datetime

LOG_FILE = "sample_security_log.log"
REPORT_FILE = "soc_report.json"

THRESHOLD = 5
WINDOW_MINUTES = 5

pattern = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}) Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

events = []

# Read logs
with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        match = pattern.search(line)

        if match:
            timestamp = datetime.strptime(
                match.group(1),
                "%Y-%m-%d %H:%M"
            )

            user = match.group(2)
            ip = match.group(3)

            events.append({
                "timestamp": timestamp,
                "user": user,
                "ip": ip
            })

events.sort(key=lambda x: x["timestamp"])

windows = defaultdict(deque)
alerts = {}

# Detection engine
for event in events:
    key = (event["ip"], event["user"])
    current_time = event["timestamp"]

    windows[key].append(current_time)

    while windows[key]:
        oldest = windows[key][0]

        if (current_time - oldest).total_seconds() > WINDOW_MINUTES * 60:
            windows[key].popleft()
        else:
            break

    if len(windows[key]) >= THRESHOLD:

        if key not in alerts:
            attempt_count = len(windows[key])

            if attempt_count >= 10:
                severity = "Critical"
            else:
                severity = "High"

            alerts[key] = {
                "detection_type": "Possible Brute Force",
                "source_ip": event["ip"],
                "target_user": event["user"],
                "failed_attempts": attempt_count,
                "window_minutes": WINDOW_MINUTES,
                "first_attempt": windows[key][0].isoformat(),
                "last_attempt": windows[key][-1].isoformat(),
                "severity": severity,
		"mitre_technique": "T1110 - Brute Force"
            }

if not alerts:
    print("No suspicious brute-force activity detected.")
    raise SystemExit

report = []

# AI analysis
for key, alert in alerts.items():

    print("=" * 60)
    print("DETECTED EVENT")
    print("=" * 60)

    print(f"Source IP: {alert['source_ip']}")
    print(f"Target User: {alert['target_user']}")
    print(f"Failed Attempts: {alert['failed_attempts']}")
    print(f"Severity: {alert['severity']}")
    print()

    facts = f"""
CONFIRMED FACTS:
- Detection Type: {alert['detection_type']}
- Source IP: {alert['source_ip']}
- Target User: {alert['target_user']}
- Failed Attempts: {alert['failed_attempts']}
- Time Window: {alert['window_minutes']} minutes
- First Attempt: {alert['first_attempt']}
- Last Attempt: {alert['last_attempt']}
- Detection Threshold: {THRESHOLD}
- Severity: {alert['severity']}
"""

    prompt = f"""
You are assisting a SOC analyst.

Analyze ONLY the confirmed facts below.

Rules:
- Do not invent information.
- Do not claim compromise unless proven.
- Do not claim malicious intent as confirmed.
- Clearly separate confirmed evidence from possible interpretation.

{facts}

Return exactly these sections:

1. Summary
2. Confirmed Evidence
3. Possible Interpretation
4. Recommended Investigation Steps
"""

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "qwen3:8b",
            "prompt": prompt,
            "stream": False
        },
        timeout=300
    )

    response.raise_for_status()

    ai_analysis = response.json()["response"]

    print("AI ANALYSIS")
    print("-" * 60)
    print(ai_analysis)
    print()

    alert["ai_analysis"] = ai_analysis
    report.append(alert)

# Export JSON
with open(REPORT_FILE, "w", encoding="utf-8") as file:
    json.dump(report, file, indent=4)

print("=" * 60)
print(f"Report saved to: {REPORT_FILE}")