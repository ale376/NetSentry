from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from netsentry.analysis import analyze_file
from netsentry.reports import render_json_report, render_text_report


st.set_page_config(page_title="NetSentry", page_icon="N", layout="wide")

st.title("NetSentry")
st.caption("Network traffic anomaly detection and security reporting")

with st.sidebar:
    st.header("Analysis Settings")
    input_format = st.selectbox("Input format", ["csv", "zeek-conn"])
    spike_threshold = st.slider("Spike threshold", min_value=2, max_value=50, value=5)
    spike_window = st.slider("Spike window (seconds)", min_value=10, max_value=300, value=60, step=10)
    port_threshold = st.slider("Unusual port threshold", min_value=1, max_value=20, value=2)
    talker_threshold = st.slider("High-volume source threshold", min_value=1, max_value=20, value=3)

uploaded_file = st.file_uploader(
    "Upload a network log file",
    type=["csv", "log"],
    help="Use a normalized CSV file or a Zeek conn.log file.",
)

if uploaded_file is None:
    st.info("Upload a CSV or Zeek conn.log file to start the analysis.")
    st.stop()

suffix = Path(uploaded_file.name).suffix or ".csv"
with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_handle:
    temp_handle.write(uploaded_file.getbuffer())
    temp_path = Path(temp_handle.name)

try:
    try:
        events, findings, summary = analyze_file(
            temp_path,
            input_format=input_format,
            spike_threshold=spike_threshold,
            spike_window_seconds=spike_window,
            unusual_port_threshold=port_threshold,
            talker_threshold=talker_threshold,
        )
    except ValueError as exc:
        st.error(str(exc))
        st.info(
            "For CSV input, you can upload either a NetSentry-formatted CSV "
            "or a raw Wireshark CSV export."
        )
        st.stop()
finally:
    temp_path.unlink(missing_ok=True)

high_count = sum(1 for finding in findings if finding["severity"] == "high")
medium_count = sum(1 for finding in findings if finding["severity"] == "medium")

metric_cols = st.columns(4)
metric_cols[0].metric("Events", summary["total_events"])
metric_cols[1].metric("Findings", summary["total_findings"])
metric_cols[2].metric("High Severity", high_count)
metric_cols[3].metric("Medium Severity", medium_count)

left, right = st.columns([1.2, 1])

with left:
    st.subheader("Findings")
    if findings:
        st.dataframe(findings, use_container_width=True)
    else:
        st.success("No anomalies detected for this file.")

with right:
    st.subheader("Top Sources")
    st.dataframe(summary["top_sources"], use_container_width=True)
    st.subheader("Top Destinations")
    st.dataframe(summary["top_destinations"], use_container_width=True)
    st.subheader("Protocols")
    st.json(summary["protocols"])

json_report = render_json_report(summary, findings)
text_report = render_text_report(summary, findings)

download_cols = st.columns(2)
download_cols[0].download_button(
    "Download JSON Report",
    data=json_report,
    file_name="netsentry_report.json",
    mime="application/json",
)
download_cols[1].download_button(
    "Download Text Report",
    data=text_report,
    file_name="netsentry_report.txt",
    mime="text/plain",
)
