import streamlit as st
import pandas as pd
from detector import simulate, parse_line, detect, triage

st.set_page_config(
    page_title="Security Hunter",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Security Hunter")
st.subheader("Cybersecurity Incident Response & Threat Hunting")

st.write(
    "Analyze server logs, detect suspicious activity, "
    "and generate incident reports."
)

st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Choose a section",
    ["Dashboard", "Threat Detection", "Incident Reports", "About"]
)

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "events" not in st.session_state:
    st.session_state.events = []

if page == "Dashboard":

    st.header("Security Overview")

    st.info(
        "Run the threat detection engine to analyze "
        "simulated or uploaded server logs."
    )

    if st.button("Run Threat Detection", type="primary"):

        lines = simulate()

        events = sorted(
            filter(None, map(parse_line, lines)),
            key=lambda e: e["ts"]
        )

        alerts = detect(events)

        st.session_state.events = events
        st.session_state.alerts = alerts

        st.success("Threat detection completed successfully!")

    alerts = st.session_state.alerts

    total_events = len(st.session_state.events)
    total_alerts = len(alerts)
    unique_ips = len(set(a["ip"] for a in alerts))

    severities = [
        triage([a for a in alerts if a["ip"] == ip])
        for ip in set(a["ip"] for a in alerts)
    ]

    critical = severities.count("Critical")
    high = severities.count("High")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Logs Analyzed", total_events)
    col2.metric("Threat Alerts", total_alerts)
    col3.metric("Source IPs", unique_ips)
    col4.metric("High/Critical IPs", high + critical)

    st.divider()

    st.subheader("Recent Security Alerts")

    if alerts:

        df = pd.DataFrame(alerts)

        st.dataframe(
            df[["ip", "type", "detail", "time"]],
            use_container_width=True
        )

    else:
        st.write("No alerts available. Run threat detection first.")

elif page == "Threat Detection":

    st.header("Threat Detection")

    uploaded_file = st.file_uploader(
        "Upload a server log file",
        type=["log", "txt"]
    )

    if st.button("Analyze Uploaded Logs"):

        if uploaded_file is None:

            st.warning("Please upload a log file first.")

        else:

            lines = uploaded_file.getvalue().decode(
                "utf-8",
                errors="ignore"
            ).splitlines()

            events = sorted(
                filter(None, map(parse_line, lines)),
                key=lambda e: e["ts"]
            )

            alerts = detect(events)

            st.session_state.events = events
            st.session_state.alerts = alerts

            st.success(
                f"Analyzed {len(events)} events "
                f"and detected {len(alerts)} alerts."
            )

    if st.session_state.alerts:

        st.dataframe(
            pd.DataFrame(st.session_state.alerts),
            use_container_width=True
        )

elif page == "Incident Reports":

    st.header("Incident Reports")

    alerts = st.session_state.alerts

    if alerts:

        report = []

        for ip in sorted(set(a["ip"] for a in alerts)):

            ip_alerts = [
                a for a in alerts
                if a["ip"] == ip
            ]

            report.append({
                "Source IP": ip,
                "Severity": triage(ip_alerts),
                "Alert Count": len(ip_alerts),
                "Threat Types": ", ".join(
                    sorted(set(a["type"] for a in ip_alerts))
                )
            })

        df = pd.DataFrame(report)

        st.dataframe(
            df,
            use_container_width=True
        )

        st.download_button(
            "Download Incident Report",
            data=df.to_csv(index=False),
            file_name="incident_report.csv",
            mime="text/csv"
        )

    else:

        st.info("Run threat detection to generate a report.")

elif page == "About":

    st.header("About the Project")

    st.write("""
    *Project:* Cybersecurity Incident Response
    and Threat Hunting Practical Guide

    *Technologies Used:*
    - Python
    - Streamlit
    - Pandas
    - Regular Expressions
    - Docker

    *Main Objectives:*
    - Detect suspicious server activity.
    - Identify brute-force login attempts.
    - Detect web application attacks.
    - Generate incident reports.
    - Preserve security evidence.
    """)