import re
import json
import argparse
import logging
import requests

from datetime import datetime
from pathlib import Path

from detection_engine import detect_bruteforce


# --------------------------------------------------
# Constants
# --------------------------------------------------

CONFIG_FILE = "config.json"
REPORT_FILE = "soc_report.json"

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

APP_LOG_FILE = LOG_DIR / "app.log"


# --------------------------------------------------
# Application Logging
# --------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(
            APP_LOG_FILE,
            encoding="utf-8"
        ),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("local_ai_soc")


# --------------------------------------------------
# Configuration
# --------------------------------------------------

def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except FileNotFoundError:
        logger.error(
            "Config file not found: %s",
            CONFIG_FILE
        )
        raise SystemExit(1)

    except json.JSONDecodeError as error:
        logger.error(
            "Invalid JSON in %s: %s",
            CONFIG_FILE,
            error
        )
        raise SystemExit(1)

    except OSError as error:
        logger.error(
            "Could not read config file: %s",
            error
        )
        raise SystemExit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Local AI SOC Analyzer - "
            "Brute-force authentication detector"
        )
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        help="Failed login threshold"
    )

    parser.add_argument(
        "--window",
        type=int,
        help="Detection window in minutes"
    )

    return parser.parse_args()


config = load_config()
args = parse_args()

LOG_FILE = args.log

THRESHOLD = (
    args.threshold
    if args.threshold is not None
    else config.get("threshold", 5)
)

WINDOW_MINUTES = (
    args.window
    if args.window is not None
    else config.get("window_minutes", 5)
)

OLLAMA_MODEL = config.get(
    "ollama_model",
    "qwen3:8b"
)

OLLAMA_URL = config.get(
    "ollama_url",
    "http://localhost:11434/api/generate"
)


# --------------------------------------------------
# Validate Configuration
# --------------------------------------------------

if THRESHOLD <= 0:
    logger.error(
        "Threshold must be greater than 0."
    )
    raise SystemExit(1)

if WINDOW_MINUTES <= 0:
    logger.error(
        "Window must be greater than 0."
    )
    raise SystemExit(1)


# --------------------------------------------------
# Log Patterns
# --------------------------------------------------

# Linux SSH auth.log
#
# Oct 14 12:31:07 ubuntu sshd[1234]:
# Failed password for root from 192.168.1.50 port 55231 ssh2

linux_pattern = re.compile(
    r"(?P<month>[A-Z][a-z]{2}) "
    r"(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


# Simple/sample format
#
# 2026-10-14 13:01
# Failed password for admin from 192.168.1.80

simple_pattern = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2}) "
    r"(?P<time>\d{2}:\d{2}) "
    r"Failed password for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


# --------------------------------------------------
# Log Parser
# --------------------------------------------------

def parse_log_line(line):

    # Linux auth.log
    match = linux_pattern.search(line)

    if match:
        current_year = datetime.now().year

        timestamp_text = (
            f"{current_year} "
            f"{match.group('month')} "
            f"{match.group('day')} "
            f"{match.group('time')}"
        )

        try:
            timestamp = datetime.strptime(
                timestamp_text,
                "%Y %b %d %H:%M:%S"
            )

        except ValueError:
            logger.warning(
                "Invalid Linux timestamp: %s",
                timestamp_text
            )
            return None

        return {
            "timestamp": timestamp,
            "user": match.group("user"),
            "ip": match.group("ip"),
            "log_source": "linux_auth"
        }

    # Simple/sample format
    match = simple_pattern.search(line)

    if match:
        timestamp_text = (
            f"{match.group('date')} "
            f"{match.group('time')}"
        )

        try:
            timestamp = datetime.strptime(
                timestamp_text,
                "%Y-%m-%d %H:%M"
            )

        except ValueError:
            logger.warning(
                "Invalid sample timestamp: %s",
                timestamp_text
            )
            return None

        return {
            "timestamp": timestamp,
            "user": match.group("user"),
            "ip": match.group("ip"),
            "log_source": "simple"
        }

    return None


# --------------------------------------------------
# Program Start
# --------------------------------------------------

logger.info(
    "Local AI SOC Analyzer started"
)

logger.info(
    "Input log file: %s",
    LOG_FILE
)

logger.info(
    "Detection threshold: %s",
    THRESHOLD
)

logger.info(
    "Detection window: %s minutes",
    WINDOW_MINUTES
)

logger.info(
    "Ollama model: %s",
    OLLAMA_MODEL
)


# --------------------------------------------------
# Read Log File
# --------------------------------------------------

events = []
ignored_lines = 0

try:
    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            event = parse_log_line(line)

            if event:
                events.append(event)

            else:
                ignored_lines += 1

                logger.debug(
                    "Ignored unsupported line %s",
                    line_number
                )

except FileNotFoundError:
    logger.error(
        "Log file not found: %s",
        LOG_FILE
    )
    raise SystemExit(1)

except PermissionError:
    logger.error(
        "Permission denied reading log file: %s",
        LOG_FILE
    )
    raise SystemExit(1)

except OSError as error:
    logger.error(
        "Could not read log file: %s",
        error
    )
    raise SystemExit(1)


events.sort(
    key=lambda x: x["timestamp"]
)


logger.info(
    "Log parsing complete: "
    "%s events parsed, %s lines ignored",
    len(events),
    ignored_lines
)


# --------------------------------------------------
# Console Summary
# --------------------------------------------------

print("=" * 60)
print("LOCAL AI SOC ANALYZER")
print("=" * 60)

print(f"Log File: {LOG_FILE}")
print(f"Threshold: {THRESHOLD}")
print(
    f"Window: {WINDOW_MINUTES} minutes"
)
print(f"AI Model: {OLLAMA_MODEL}")

print()

print("=" * 60)
print("LOG PARSING")
print("=" * 60)

print(
    f"Parsed Events: {len(events)}"
)

print(
    f"Ignored Lines: {ignored_lines}"
)

print()


if not events:
    logger.info(
        "No supported authentication events found."
    )

    print(
        "No supported authentication events found."
    )

    raise SystemExit(0)


# --------------------------------------------------
# Shared Detection Engine
# --------------------------------------------------

try:
    alerts = detect_bruteforce(
        events,
        threshold=THRESHOLD,
        window_minutes=WINDOW_MINUTES
    )

except Exception as error:
    logger.exception(
        "Detection engine failed: %s",
        error
    )
    raise SystemExit(1)


logger.info(
    "Detection complete: %s alerts generated",
    len(alerts)
)


# --------------------------------------------------
# No Alerts
# --------------------------------------------------

if not alerts:

    print("=" * 60)
    print("DETECTION RESULT")
    print("=" * 60)

    print(
        "No suspicious brute-force "
        "activity detected."
    )

    logger.info(
        "No suspicious brute-force "
        "activity detected."
    )

    raise SystemExit(0)


# --------------------------------------------------
# AI Analysis
# --------------------------------------------------

report = []

for alert_number, alert in enumerate(
    alerts,
    start=1
):

    print("=" * 60)

    print(
        f"DETECTED EVENT #{alert_number}"
    )

    print("=" * 60)

    print(
        f"Source IP: "
        f"{alert['source_ip']}"
    )

    print(
        f"Target User: "
        f"{alert['target_user']}"
    )

    print(
        f"Failed Attempts: "
        f"{alert['failed_attempts']}"
    )

    print(
        f"Window: "
        f"{alert['window_minutes']} minutes"
    )

    print(
        f"Severity: "
        f"{alert['severity']}"
    )

    print(
        f"Log Source: "
        f"{alert['log_source']}"
    )

    print(
        f"MITRE ATT&CK: "
        f"{alert['mitre_technique']}"
    )

    print(
        f"MITRE Sub-technique: "
        f"{alert['mitre_subtechnique']}"
    )

    print(
        f"First Attempt: "
        f"{alert['first_attempt']}"
    )

    print(
        f"Last Attempt: "
        f"{alert['last_attempt']}"
    )

    print()


    # --------------------------------------------------
    # Confirmed Facts
    # --------------------------------------------------

    facts = f"""
CONFIRMED FACTS:

Detection Type:
{alert['detection_type']}

Source IP:
{alert['source_ip']}

Target User:
{alert['target_user']}

Failed Attempts:
{alert['failed_attempts']}

Detection Threshold:
{alert['detection_threshold']}

Time Window:
{alert['window_minutes']} minutes

First Attempt:
{alert['first_attempt']}

Last Attempt:
{alert['last_attempt']}

Severity:
{alert['severity']}

MITRE ATT&CK:
{alert['mitre_technique']}

MITRE Sub-technique:
{alert['mitre_subtechnique']}

Log Source:
{alert['log_source']}
"""


    prompt = f"""
You are assisting a Security Operations Center analyst.

Analyze ONLY the confirmed facts provided below.

STRICT RULES:

- Do not invent information.
- Do not invent indicators of compromise.
- Do not claim the system is compromised
  unless evidence proves it.
- Do not claim malicious intent as confirmed.
- Do not change the severity assigned
  by the detector.
- Do not invent usernames, IP addresses,
  ports, hosts, or timestamps.
- Clearly separate confirmed evidence
  from possible interpretation.
- Explain what additional evidence
  should be checked.

{facts}

Return exactly these sections:

1. Summary

2. Confirmed Evidence

3. Possible Interpretation

4. Recommended Investigation Steps
"""


    # --------------------------------------------------
    # Ollama API
    # --------------------------------------------------

    try:
        logger.info(
            "Requesting AI analysis for %s -> %s",
            alert["source_ip"],
            alert["target_user"]
        )

        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )

        response.raise_for_status()

        response_data = response.json()

        ai_analysis = response_data.get(
            "response",
            "AI returned no analysis."
        )

        ai_status = "success"

        logger.info(
            "AI analysis completed for %s -> %s",
            alert["source_ip"],
            alert["target_user"]
        )


    except requests.Timeout as error:

        ai_analysis = (
            "AI analysis unavailable.\n\n"
            "The local AI request timed out.\n\n"
            "The rule-based detector completed "
            "successfully."
        )

        ai_status = "timeout"

        logger.warning(
            "AI request timed out for %s -> %s: %s",
            alert["source_ip"],
            alert["target_user"],
            error
        )


    except requests.ConnectionError as error:

        ai_analysis = (
            "AI analysis unavailable.\n\n"
            "Could not connect to the local "
            "Ollama service.\n\n"
            "The rule-based detector completed "
            "successfully."
        )

        ai_status = "connection_error"

        logger.warning(
            "Could not connect to Ollama "
            "for %s -> %s: %s",
            alert["source_ip"],
            alert["target_user"],
            error
        )


    except requests.RequestException as error:

        ai_analysis = (
            "AI analysis unavailable.\n\n"
            "The rule-based detector completed "
            "successfully.\n\n"
            f"Error: {error}"
        )

        ai_status = "unavailable"

        logger.warning(
            "AI analysis unavailable "
            "for %s -> %s: %s",
            alert["source_ip"],
            alert["target_user"],
            error
        )


    except ValueError as error:

        ai_analysis = (
            "AI response could not be decoded.\n\n"
            "The rule-based detector completed "
            "successfully."
        )

        ai_status = "invalid_response"

        logger.warning(
            "Invalid AI response "
            "for %s -> %s: %s",
            alert["source_ip"],
            alert["target_user"],
            error
        )


    # --------------------------------------------------
    # Display AI Result
    # --------------------------------------------------

    print("AI ANALYSIS")
    print("-" * 60)

    print(ai_analysis)
    print()

    alert["ai_status"] = ai_status
    alert["ai_analysis"] = ai_analysis

    report.append(alert)


# --------------------------------------------------
# Export JSON Report
# --------------------------------------------------

try:
    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

except PermissionError:
    logger.error(
        "Permission denied writing report: %s",
        REPORT_FILE
    )
    raise SystemExit(1)

except OSError as error:
    logger.error(
        "Could not write report: %s",
        error
    )
    raise SystemExit(1)


logger.info(
    "SOC report saved to %s",
    REPORT_FILE
)


# --------------------------------------------------
# Final Summary
# --------------------------------------------------

print("=" * 60)
print("ANALYSIS COMPLETE")
print("=" * 60)

print(
    f"Alerts Generated: {len(report)}"
)

print(
    f"Report Saved: {REPORT_FILE}"
)

print(
    f"Application Log: {APP_LOG_FILE}"
)

print(
    f"AI Model: {OLLAMA_MODEL}"
)

print("=" * 60)


logger.info(
    "Analysis completed successfully"
)

logger.info(
    "Alerts generated: %s",
    len(report)
)