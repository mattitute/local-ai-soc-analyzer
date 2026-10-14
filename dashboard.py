import json
import pandas as pd
import streamlit as st

REPORT_FILE = "soc_report.json"

st.set_page_config(
    page_title="Local AI SOC Dashboard",
    layout="wide"
)

st.title("Local AI SOC Dashboard")
st.caption("Rule-based detection + Local LLM analysis")

try:
    with open(REPORT_FILE, "r", encoding="utf-8") as file:
        alerts = json.load(file)

except FileNotFoundError:
    st.error("soc_report.json not found. Run detector.py first.")
    st.stop()

if not alerts:
    st.success("No security alerts detected.")
    st.stop()

# ----------------------
# Overview
# ----------------------

st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

total_alerts = len(alerts)

high_count = sum(
    1 for alert in alerts
    if alert["severity"] == "High"
)

critical_count = sum(
    1 for alert in alerts
    if alert["severity"] == "Critical"
)

unique_ips = len(
    set(alert["source_ip"] for alert in alerts)
)

col1.metric("Total Alerts", total_alerts)
col2.metric("High Severity", high_count)
col3.metric("Critical Severity", critical_count)
col4.metric("Unique Source IPs", unique_ips)

st.divider()

# ----------------------
# Alert Table
# ----------------------

table_data = []

for alert in alerts:
    table_data.append({
        "Severity": alert["severity"],
        "Source IP": alert["source_ip"],
        "Target User": alert["target_user"],
        "Failed Attempts": alert["failed_attempts"],
        "MITRE ATT&CK": alert.get(
            "mitre_technique",
            "Not mapped"
        )
    })

df = pd.DataFrame(table_data)

st.subheader("Detected Events")
st.dataframe(df, use_container_width=True)

st.divider()

# ----------------------
# Charts
# ----------------------

st.subheader("Alert Analytics")

col1, col2 = st.columns(2)

with col1:
    st.write("Failed Attempts by Source IP")

    ip_chart = (
        df.groupby("Source IP")["Failed Attempts"]
        .sum()
        .sort_values(ascending=False)
    )

    st.bar_chart(ip_chart)

with col2:
    st.write("Alerts by Severity")

    severity_chart = (
        df["Severity"]
        .value_counts()
    )

    st.bar_chart(severity_chart)

st.divider()

# ----------------------
# AI Reports
# ----------------------

st.subheader("AI Investigation Reports")

for index, alert in enumerate(alerts, start=1):

    title = (
        f"Alert {index} | "
        f"{alert['severity']} | "
        f"{alert['source_ip']} → "
        f"{alert['target_user']}"
    )

    with st.expander(title):

        st.write("### Event Information")

        st.write(
            f"**Detection:** "
            f"{alert['detection_type']}"
        )

        st.write(
            f"**Source IP:** "
            f"{alert['source_ip']}"
        )

        st.write(
            f"**Target User:** "
            f"{alert['target_user']}"
        )

        st.write(
            f"**Failed Attempts:** "
            f"{alert['failed_attempts']}"
        )

        st.write(
            f"**Severity:** "
            f"{alert['severity']}"
        )

        st.write(
            f"**MITRE ATT&CK:** "
            f"{alert.get('mitre_technique', 'Not mapped')}"
        )

        st.write("### Local AI Analysis")

        st.markdown(
            alert["ai_analysis"]
        )