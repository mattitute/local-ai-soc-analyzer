\# Local AI SOC Analyzer



A local cybersecurity monitoring project that combines

rule-based detection with a locally hosted Large Language Model.



\## Features



\- Parses authentication logs

\- Detects brute-force login attempts

\- Uses sliding time-window detection

\- Supports multiple IP addresses and users

\- Assigns severity levels

\- Maps detections to MITRE ATT\&CK

\- Uses local Qwen LLM through Ollama

\- Generates AI-assisted SOC investigation reports

\- Exports structured JSON alerts

\- Displays results in a Streamlit dashboard



\## Architecture



Security Logs

↓

Python Detection Engine

↓

Sliding Window Analysis

↓

Confirmed Security Event

↓

Local Ollama API

↓

Qwen LLM

↓

SOC Analysis

↓

JSON Report

↓

Streamlit Dashboard



\## Detection Rule



Brute force detection triggers when:



\- 5 or more failed login attempts

\- Same source IP

\- Same target user

\- Within 5 minutes



\## MITRE ATT\&CK



T1110 - Brute Force



\## Technology Stack



\- Python

\- Ollama

\- Qwen 8B

\- Streamlit

\- Pandas

\- JSON

\- Regular Expressions



\## Privacy



All AI inference runs locally using Ollama.

Security logs do not need to be sent to external cloud AI services.



\## Example



Source IP: 192.168.1.50



Target User: admin



Failed Attempts: 6



Severity: High



MITRE ATT\&CK: T1110 - Brute Force

