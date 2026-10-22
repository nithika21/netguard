"""
NetGuard — Network Traffic Analysis for Anomaly Detection
Streamlit Web Application
"""

import os
import io
import time
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Allow `streamlit run frontend/app.py` from the project root.
import sys
from pathlib import Path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from backend.config import (
    DB_PATH,
    SAMPLE_PCAP_PATH,
    ML_MODEL_PATH,
    DATASET_CSV_PATH,
    SAMPLE_CSV_PATH,
    HIGH_PACKET_RATE_THRESHOLD,
    HIGH_PACKET_RATE_WINDOW_SECONDS,
    PORT_SCAN_PORT_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    REPEATED_CONN_THRESHOLD,
    REPEATED_CONN_WINDOW_SECONDS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    STATUS_ACTIVE,
    STATUS_ACKNOWLEDGED,
    STATUS_RESOLVED,
    DEFAULT_PAGE_SIZE,
    DEFAULT_CSV_PAGE_SIZE
)
from backend import database, packet_analyzer, anomaly_detector, ml_detector


# -------------------------------------------------------------
# Streamlit Page Setup
# -------------------------------------------------------------
st.set_page_config(
    page_title="NetGuard — Network Traffic Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database
database.init_db()


# -------------------------------------------------------------
# Session State Initialization
# -------------------------------------------------------------
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Dashboard"

if "analyzed" not in st.session_state:
    st.session_state["analyzed"] = False

if "pcap_filename" not in st.session_state:
    st.session_state["pcap_filename"] = None

if "pcap_filesize" not in st.session_state:
    st.session_state["pcap_filesize"] = 0

if "df_packets" not in st.session_state:
    st.session_state["df_packets"] = None

if "traffic_stats" not in st.session_state:
    st.session_state["traffic_stats"] = None

if "alerts" not in st.session_state:
    st.session_state["alerts"] = []

if "selected_alert_id" not in st.session_state:
    st.session_state["selected_alert_id"] = None

if "selected_packet_id" not in st.session_state:
    st.session_state["selected_packet_id"] = 1

if "packet_page_num" not in st.session_state:
    st.session_state["packet_page_num"] = 1

if "explorer_mode" not in st.session_state:
    st.session_state["explorer_mode"] = "📦 PCAP Packet Analysis (Rule-Based Heuristics)"

if "csv_analyzed" not in st.session_state:
    st.session_state["csv_analyzed"] = False

if "csv_filename" not in st.session_state:
    st.session_state["csv_filename"] = None

if "csv_filesize" not in st.session_state:
    st.session_state["csv_filesize"] = 0

if "df_csv_results" not in st.session_state:
    st.session_state["df_csv_results"] = None

if "csv_stats" not in st.session_state:
    st.session_state["csv_stats"] = None

if "csv_warnings" not in st.session_state:
    st.session_state["csv_warnings"] = []

if "csv_page_num" not in st.session_state:
    st.session_state["csv_page_num"] = 1

if "selected_csv_flow_id" not in st.session_state:
    st.session_state["selected_csv_flow_id"] = 1


# -------------------------------------------------------------
# Custom CSS for UI Match with Screenshots
# -------------------------------------------------------------
CUSTOM_CSS = """
<style>
/* Font and Base Theme */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1e293b;
}

/* App Background */
.stApp {
    background-color: #f8fafc;
}

/* Sidebar Styling matching screenshots */
[data-testid="stSidebar"] {
    background-color: #0d1b2a;
    border-right: 1px solid #1e293b;
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] {
    color: #e2e8f0;
}

/* Sidebar Custom Brand */
.sidebar-brand-container {
    padding: 18px 14px 20px 14px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    margin-bottom: 20px;
}

.sidebar-logo {
    display: flex;
    align-items: center;
    gap: 10px;
}

.sidebar-title {
    font-size: 20px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -0.3px;
    margin: 0;
}

.sidebar-subtitle {
    font-size: 11px;
    color: #8da4b5;
    margin-top: 4px;
    line-height: 1.3;
}

/* Navigation Buttons */
.nav-btn {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 10px 14px;
    margin-bottom: 6px;
    border-radius: 8px;
    font-size: 13.5px;
    font-weight: 500;
    color: #94a3b8;
    background: transparent;
    border: none;
    cursor: pointer;
    text-align: left;
    transition: all 0.15s ease-in-out;
}

.nav-btn:hover {
    color: #ffffff;
    background: rgba(255, 255, 255, 0.05);
}

.nav-btn.active {
    color: #ffffff;
    background: rgba(13, 148, 136, 0.25);
    border-left: 3px solid #0d9488;
    font-weight: 600;
}

/* Sidebar navigation buttons */
[data-testid="stSidebar"] [data-testid="stButton"] > button {
    background: #183247 !important;
    color: #e2e8f0 !important;
    border: 1px solid #31516a !important;
    border-radius: 10px;
    min-height: 44px;
    font-weight: 600;
    transition: background-color 0.15s ease, border-color 0.15s ease;
}

[data-testid="stSidebar"] [data-testid="stButton"] > button:hover {
    background: #24465e !important;
    color: #ffffff !important;
    border-color: #38bdf8 !important;
}

[data-testid="stSidebar"] [data-testid="stButton"] > button[kind="primary"] {
    background: #0d9488 !important;
    color: #ffffff !important;
    border-color: #2dd4bf !important;
    box-shadow: 0 3px 10px rgba(13, 148, 136, 0.22);
}

[data-testid="stSidebar"] [data-testid="stButton"] > button[kind="primary"]:hover {
    background: #0f766e !important;
    border-color: #5eead4 !important;
}

/* Top Banner Notice */
.context-banner {
    background-color: #ecfdf5;
    border: 1px solid #a7f3d0;
    border-left: 4px solid #0d9488;
    padding: 10px 16px;
    border-radius: 8px;
    margin-bottom: 16px;
    font-size: 13px;
    color: #065f46;
    display: flex;
    align-items: center;
    gap: 10px;
}

/* Header Container */
.page-header-container {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 14px;
}

.page-title {
    font-size: 24px;
    font-weight: 700;
    color: #0f172a;
    margin: 0;
    letter-spacing: -0.4px;
}

.page-subtitle {
    font-size: 13px;
    color: #64748b;
    margin-top: 4px;
}

.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    font-weight: 600;
    color: #047857;
    background: #d1fae5;
    padding: 4px 10px;
    border-radius: 20px;
    border: 1px solid #6ee7b7;
}

.status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background-color: #10b981;
}

/* File Info Bar */
.file-info-bar {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 12px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 18px;
}

.file-info-left {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
    color: #334155;
}

.file-name-tag {
    font-weight: 600;
    color: #0f172a;
}

/* Metric Cards */
.metric-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 18px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    position: relative;
    height: 100%;
}

.metric-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.metric-title {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #64748b;
}

.metric-icon {
    font-size: 16px;
    color: #0d9488;
}

.metric-value {
    font-size: 28px;
    font-weight: 700;
    color: #0f172a;
    line-height: 1.1;
    margin-bottom: 6px;
}

.metric-value.red {
    color: #ef4444;
}

.metric-desc {
    font-size: 11.5px;
    color: #94a3b8;
}

/* Content Cards */
.content-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
}

/* Keep native Packet Explorer controls readable on the light cards. */
[data-testid="stAppViewContainer"] h1,
[data-testid="stAppViewContainer"] h2,
[data-testid="stAppViewContainer"] h3,
[data-testid="stAppViewContainer"] h4,
[data-testid="stAppViewContainer"] h5,
[data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] p,
[data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] label,
[data-testid="stAppViewContainer"] [data-testid="stRadio"] label,
[data-testid="stAppViewContainer"] [data-testid="stFileUploader"] label,
[data-testid="stAppViewContainer"] [data-testid="stFileUploader"] section,
[data-testid="stAppViewContainer"] [data-testid="stFileUploader"] small {
    color: #1e293b !important;
}

[data-testid="stAppViewContainer"] [data-testid="stFileUploader"] section {
    background-color: #ffffff !important;
    border: 1px dashed #94a3b8 !important;
}

[data-testid="stAppViewContainer"] [data-testid="stFileUploader"] button,
[data-testid="stAppViewContainer"] [data-testid="stFileUploader"] button * {
    color: #ffffff !important;
    background-color: #0f766e !important;
    border-color: #0f766e !important;
}

/* Shared contrast rules for every page and native Streamlit widget. */
[data-testid="stAppViewContainer"] {
    color: #1e293b;
}

[data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"],
[data-testid="stAppViewContainer"] [data-testid="stWidgetLabel"],
[data-testid="stAppViewContainer"] [data-testid="stWidgetLabel"] *,
[data-testid="stAppViewContainer"] [data-testid="stRadio"] label,
[data-testid="stAppViewContainer"] [data-testid="stCheckbox"] label,
[data-testid="stAppViewContainer"] [data-testid="stSelectbox"] label,
[data-testid="stAppViewContainer"] [data-testid="stMultiSelect"] label,
[data-testid="stAppViewContainer"] [data-testid="stTextInput"] label,
[data-testid="stAppViewContainer"] [data-testid="stNumberInput"] label,
[data-testid="stAppViewContainer"] [data-testid="stSlider"] label,
[data-testid="stAppViewContainer"] [data-testid="stDateInput"] label,
[data-testid="stAppViewContainer"] [data-testid="stTimeInput"] label {
    color: #1e293b !important;
}

/* Light surfaces use dark text, including dropdowns, inputs, and tables. */
[data-testid="stAppViewContainer"] input,
[data-testid="stAppViewContainer"] textarea,
[data-testid="stAppViewContainer"] [role="listbox"],
[data-testid="stAppViewContainer"] [role="option"],
[data-testid="stAppViewContainer"] [data-testid="stDataFrame"],
[data-testid="stAppViewContainer"] [data-testid="stTable"] {
    color: #1e293b !important;
}

/* BaseWeb selectboxes inherit dark-theme colors unless both layers are set. */
[data-testid="stAppViewContainer"] [data-baseweb="select"] > div {
    background-color: #ffffff !important;
    border-color: #94a3b8 !important;
    color: #1e293b !important;
}

[data-testid="stAppViewContainer"] [data-baseweb="select"] *,
[data-testid="stAppViewContainer"] [data-baseweb="popover"] *,
[data-testid="stAppViewContainer"] [role="listbox"] *,
[data-testid="stAppViewContainer"] [role="option"] * {
    color: #1e293b !important;
}

[data-testid="stAppViewContainer"] [data-baseweb="popover"],
[data-testid="stAppViewContainer"] [role="listbox"],
[data-testid="stAppViewContainer"] [role="option"] {
    background-color: #ffffff !important;
}

/* Streamlit mounts open dropdown menus in a portal outside the app container. */
[data-baseweb="popover"],
[data-baseweb="popover"] *,
[role="listbox"],
[role="listbox"] *,
[role="option"],
[role="option"] * {
    background-color: #ffffff !important;
    color: #1e293b !important;
}

[role="option"]:hover,
[role="option"][aria-selected="true"] {
    background-color: #e2e8f0 !important;
    color: #0f172a !important;
}

[data-testid="stAppViewContainer"] [data-baseweb="select"] [aria-selected="true"],
[data-testid="stAppViewContainer"] [role="option"]:hover {
    background-color: #e2e8f0 !important;
    color: #0f172a !important;
}

/* Text inputs and search fields stay readable on the light app surface. */
[data-testid="stAppViewContainer"] [data-baseweb="input"],
[data-testid="stAppViewContainer"] [data-baseweb="textarea"],
[data-testid="stAppViewContainer"] [data-baseweb="input"] > div,
[data-testid="stAppViewContainer"] [data-baseweb="textarea"] > div {
    background-color: #ffffff !important;
    border-color: #94a3b8 !important;
    color: #1e293b !important;
}

[data-testid="stAppViewContainer"] [data-baseweb="input"] input,
[data-testid="stAppViewContainer"] [data-baseweb="textarea"] textarea {
    background-color: #ffffff !important;
    color: #1e293b !important;
    -webkit-text-fill-color: #1e293b !important;
}

[data-testid="stAppViewContainer"] [data-baseweb="input"] input::placeholder,
[data-testid="stAppViewContainer"] [data-baseweb="textarea"] textarea::placeholder {
    color: #64748b !important;
    -webkit-text-fill-color: #64748b !important;
    opacity: 1;
}

/* Dark code chips (for IP addresses and filenames) need light text. */
[data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] code {
    background-color: #1e293b !important;
    color: #f8fafc !important;
    -webkit-text-fill-color: #f8fafc !important;
}

[data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] code * {
    color: #f8fafc !important;
    -webkit-text-fill-color: #f8fafc !important;
}

/* Buttons switch to white text whenever hover/focus changes them to teal. */
[data-testid="stAppViewContainer"] [data-testid="stButton"] > button,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button,
[data-testid="stAppViewContainer"] [data-testid="stLinkButton"] > a {
    background-color: #0d9488 !important;
    border-color: #0d9488 !important;
    color: #ffffff !important;
}

[data-testid="stAppViewContainer"] [data-testid="stButton"] > button *,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button *,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button *,
[data-testid="stAppViewContainer"] [data-testid="stLinkButton"] > a * {
    color: #ffffff !important;
}

[data-testid="stAppViewContainer"] [data-testid="stButton"] > button:hover,
[data-testid="stAppViewContainer"] [data-testid="stButton"] > button:focus-visible,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button:hover,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button:focus-visible,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button:hover,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button:focus-visible,
[data-testid="stAppViewContainer"] [data-testid="stLinkButton"] > a:hover,
[data-testid="stAppViewContainer"] [data-testid="stLinkButton"] > a:focus-visible {
    background-color: #0f766e !important;
    border-color: #0f766e !important;
    color: #ffffff !important;
}

[data-testid="stAppViewContainer"] [data-testid="stButton"] > button:hover *,
[data-testid="stAppViewContainer"] [data-testid="stButton"] > button:focus-visible *,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button:hover *,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button:focus-visible *,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button:hover *,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button:focus-visible *,
[data-testid="stAppViewContainer"] [data-testid="stLinkButton"] > a:hover *,
[data-testid="stAppViewContainer"] [data-testid="stLinkButton"] > a:focus-visible * {
    color: #ffffff !important;
}

[data-testid="stAppViewContainer"] [data-testid="stButton"] > button[kind="primary"],
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button[kind="primary"],
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button[kind="primary"] {
    background-color: #0d9488 !important;
    border-color: #0d9488 !important;
    color: #ffffff !important;
}

[data-testid="stAppViewContainer"] [data-testid="stButton"] > button[kind="primary"]:hover,
[data-testid="stAppViewContainer"] [data-testid="stDownloadButton"] > button[kind="primary"]:hover,
[data-testid="stAppViewContainer"] [data-testid="stFormSubmitButton"] > button[kind="primary"]:hover {
    background-color: #0f766e !important;
    color: #ffffff !important;
}

[data-testid="stAppViewContainer"] input:focus,
[data-testid="stAppViewContainer"] textarea:focus {
    color: #0f172a !important;
    caret-color: #0f766e;
}

/* Preserve the dark sidebar's white-on-dark contrast, including hover states. */
[data-testid="stSidebar"],
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] *,
[data-testid="stSidebar"] [data-testid="stWidgetLabel"],
[data-testid="stSidebar"] label {
    color: #e2e8f0 !important;
}

[data-testid="stSidebar"] [data-testid="stButton"] > button,
[data-testid="stSidebar"] [data-testid="stButton"] > button * {
    color: #ffffff !important;
}

[data-testid="stSidebar"] .sidebar-title,
[data-testid="stSidebar"] .sidebar-subtitle {
    color: #ffffff !important;
}

[data-testid="stSidebar"] [data-testid="stButton"] > button:hover,
[data-testid="stSidebar"] [data-testid="stButton"] > button:focus-visible {
    color: #ffffff !important;
}

.card-title-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
}

.card-title {
    font-size: 15px;
    font-weight: 600;
    color: #0f172a;
    margin: 0;
}

.card-subtitle {
    font-size: 11.5px;
    color: #64748b;
    margin-top: 2px;
}

/* Badges */
.badge {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
    text-align: center;
}

.badge-critical {
    background-color: #fee2e2;
    color: #b91c1c;
    border: 1px solid #fca5a5;
}

.badge-high {
    background-color: #ffedd5;
    color: #c2410c;
    border: 1px solid #fdba74;
}

.badge-medium {
    background-color: #fef3c7;
    color: #b45309;
    border: 1px solid #fcd34d;
}

.badge-low {
    background-color: #e0f2fe;
    color: #0369a1;
    border: 1px solid #bae6fd;
}

.badge-active {
    background-color: #e0f2fe;
    color: #0284c7;
    border: 1px solid #7dd3fc;
}

.badge-ack {
    background-color: #fef3c7;
    color: #d97706;
    border: 1px solid #fde68a;
}

.badge-resolved {
    background-color: #dcfce7;
    color: #15803d;
    border: 1px solid #86efac;
}

.badge-flagged {
    background-color: #fee2e2;
    color: #dc2626;
    border: 1px solid #fca5a5;
}

.badge-normal {
    background-color: #f1f5f9;
    color: #64748b;
    border: 1px solid #e2e8f0;
}

.badge-ml-suspicious {
    background-color: #fee2e2;
    color: #b91c1c;
    border: 1px solid #f87171;
    font-weight: 600;
}

.badge-ml-normal {
    background-color: #ecfdf5;
    color: #047857;
    border: 1px solid #6ee7b7;
    font-weight: 600;
}

.badge-ml-model {
    background-color: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    font-weight: 600;
}

.badge-ml-confidence {
    background-color: #f8fafc;
    color: #334155;
    border: 1px solid #cbd5e1;
    font-weight: 500;
}

/* Detail Box */
.detail-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px;
    margin-top: 12px;
}

.detail-label {
    font-size: 11px;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.detail-value {
    font-size: 13.5px;
    font-weight: 600;
    color: #0f172a;
    margin-top: 3px;
}

/* Custom Table Styles */
.custom-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 12.5px;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    overflow: hidden;
}

.custom-table th {
    background-color: #f8fafc;
    color: #475569;
    font-weight: 600;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
    font-size: 11.5px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}

.custom-table td {
    padding: 10px 14px;
    border-bottom: 1px solid #f1f5f9;
    color: #334155;
}

.custom-table tr:hover td {
    background-color: #f8fafc;
}

/* Hide default streamlit decoration */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
div[data-testid="stDecoration"] {visibility: hidden;}
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# -------------------------------------------------------------
# Analysis Pipeline Function
# -------------------------------------------------------------
def run_analysis(file_source, filename):
    """Parses capture file, extracts metadata, calculates stats, runs anomaly detection, and saves to SQLite."""
    with st.spinner(f"Analyzing {filename} with Scapy packet engine..."):
        df_packets, err = packet_analyzer.parse_pcap_file(file_source, filename=filename)
        if err:
            st.error(f"⚠️ {err}")
            return False

        stats = packet_analyzer.calculate_traffic_statistics(df_packets)
        df_flagged, alerts = anomaly_detector.run_anomaly_detection(df_packets)

        # Get file size
        if hasattr(file_source, "size"):
            filesize = file_source.size
        elif isinstance(file_source, str) and os.path.exists(file_source):
            filesize = os.path.getsize(file_source)
        else:
            filesize = stats["total_volume_bytes"]

        # Persist to SQLite
        database.record_capture(filename, filesize, len(df_packets), len(alerts))
        database.save_alerts(alerts, filename)

        # Update Session State
        st.session_state["analyzed"] = True
        st.session_state["pcap_filename"] = filename
        st.session_state["pcap_filesize"] = filesize
        st.session_state["df_packets"] = df_flagged
        st.session_state["traffic_stats"] = stats
        st.session_state["alerts"] = alerts
        st.session_state["selected_alert_id"] = alerts[0]["alert_id"] if alerts else None
        st.session_state["selected_packet_id"] = 1
        st.session_state["packet_page_num"] = 1
        return True


def run_csv_analysis(file_source, filename="traffic_data.csv"):
    """Parses network flow CSV, applies ML preprocessing pipeline, predicts Normal/Suspicious, and updates session state."""
    with st.spinner(f"Analyzing {filename} with Random Forest Classifier..."):
        try:
            if hasattr(file_source, "getvalue"):
                df_raw = pd.read_csv(file_source)
                filesize = file_source.size if hasattr(file_source, "size") else len(file_source.getvalue())
            elif isinstance(file_source, str) and os.path.exists(file_source):
                df_raw = pd.read_csv(file_source)
                filesize = os.path.getsize(file_source)
            elif isinstance(file_source, pd.DataFrame):
                df_raw = file_source.copy()
                filesize = 0
            else:
                st.error("Invalid CSV file source.")
                return False

            res_df, stats, warnings, err = ml_detector.preprocess_and_predict(df_raw)
            if err:
                st.error(f"⚠️ {err}")
                return False

            st.session_state["csv_analyzed"] = True
            st.session_state["csv_filename"] = filename
            st.session_state["csv_filesize"] = filesize
            st.session_state["df_csv_results"] = res_df
            st.session_state["csv_stats"] = stats
            st.session_state["csv_warnings"] = warnings
            st.session_state["csv_page_num"] = 1
            st.session_state["selected_csv_flow_id"] = 1
            return True
        except Exception as e:
            st.error(f"⚠️ Failed to analyze CSV dataset: {str(e)}")
            return False


# -------------------------------------------------------------
# Auto-load Sample PCAP & CSV Datasets on First Launch if present
# -------------------------------------------------------------
if not st.session_state["analyzed"] and os.path.exists(SAMPLE_PCAP_PATH):
    run_analysis(SAMPLE_PCAP_PATH, "sample_traffic.pcap")

if not st.session_state["csv_analyzed"] and os.path.exists(SAMPLE_CSV_PATH):
    run_csv_analysis(SAMPLE_CSV_PATH, "sample_traffic_test.csv")


# -------------------------------------------------------------
# Sidebar Navigation & Branding
# -------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand-container">
        <div class="sidebar-logo">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00b4d8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M12 8v4"/>
                <path d="M12 16h.01"/>
            </svg>
            <div class="sidebar-title">NetGuard</div>
        </div>
        <div class="sidebar-subtitle">Network Traffic Analysis & Anomaly Detection</div>
    </div>
    """, unsafe_allow_html=True)

    # Navigation Buttons
    pages = ["Dashboard", "Anomaly Detection & Alerts", "Packet Explorer"]

    for p_name in pages:
        is_current_page = st.session_state["current_page"] == p_name
        if st.button(
            p_name,
            key=f"nav_{p_name}",
            type="primary" if is_current_page else "secondary",
            use_container_width=True,
        ):
            st.session_state["current_page"] = p_name
            st.rerun()


# -------------------------------------------------------------
# Context Notice Banner (Shown on all pages)
# -------------------------------------------------------------
def render_context_banner():
    st.markdown("""
    <div class="context-banner">
        <span>ℹ️</span>
        <div><b>Analysis Context:</b> Offline packet capture analysis from Scapy. No live network interface packets.</div>
    </div>
    """, unsafe_allow_html=True)


# -------------------------------------------------------------
# Packet Explorer View Renderers (PCAP & ML CSV)
# -------------------------------------------------------------
def render_pcap_explorer():
    """Renders the original rule-based PCAP analysis view."""
    # Upload Section
    st.markdown("""
    <div class="content-card">
        <div class="card-title-row">
            <div>
                <h4 class="card-title">Upload PCAP File</h4>
                <div class="card-subtitle">Upload network capture files (.pcap, .pcapng) to parse packet metadata and run detection rules</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    up_col1, up_col2 = st.columns([1.5, 1])
    with up_col1:
        uploaded_file = st.file_uploader(
            "Choose a PCAP / PCAPNG file",
            type=["pcap", "pcapng"],
            help="Upload recorded packet capture (up to 50MB)"
        )
        if uploaded_file is not None:
            # Check if it's already analyzed in this session
            if (st.session_state["pcap_filename"] != uploaded_file.name):
                success = run_analysis(uploaded_file, uploaded_file.name)
                if success:
                    st.success(f"Capture {uploaded_file.name} successfully analyzed!")
                    st.rerun()

    with up_col2:
        if st.session_state["analyzed"]:
            filesize_str = packet_analyzer.format_bytes(st.session_state["pcap_filesize"])
            st.markdown(f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
                <div style="font-size: 13px; font-weight: 600; color: #0f172a; margin-bottom: 6px;">
                    📄 Active File: <code>{st.session_state['pcap_filename']}</code>
                </div>
                <div style="font-size: 12px; color: #64748b; margin-bottom: 4px;">
                    File Size: <b>{filesize_str}</b> | Packets: <b>{len(st.session_state['df_packets']):,}</b>
                </div>
                <div style="font-size: 12px; color: #059669; font-weight: 500; margin-bottom: 10px;">
                    ● Processing Status: Analyzed Successfully
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
                <div style="font-size: 12.5px; color: #64748b;">
                    No file currently loaded. You can upload a <code>.pcap</code> file or load the university sample dataset.
                </div>
            </div>
            """, unsafe_allow_html=True)

        if st.button("🚀 Load Sample Dataset (sample_traffic.pcap)", use_container_width=True):
            if os.path.exists(SAMPLE_PCAP_PATH):
                run_analysis(SAMPLE_PCAP_PATH, "sample_traffic.pcap")
                st.rerun()
            else:
                st.error("Sample PCAP file not found.")

    st.markdown("</div>", unsafe_allow_html=True)

    if st.session_state["analyzed"] and st.session_state["df_packets"] is not None:
        df = st.session_state["df_packets"]
        stats = st.session_state["traffic_stats"]

        # 4 Summary Metric Cards
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Total Packets</span>
                    <span class="metric-icon">📦</span>
                </div>
                <div class="metric-value">{len(df):,}</div>
                <div class="metric-desc">Available packet records</div>
            </div>
            """, unsafe_allow_html=True)

        with p2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Unique Source IPs</span>
                    <span class="metric-icon">🌐</span>
                </div>
                <div class="metric-value">{stats['unique_src_ips']}</div>
                <div class="metric-desc">Distinct transmitting hosts</div>
            </div>
            """, unsafe_allow_html=True)

        with p3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Unique Dest IPs</span>
                    <span class="metric-icon">🎯</span>
                </div>
                <div class="metric-value">{stats['unique_dst_ips']}</div>
                <div class="metric-desc">Distinct destination hosts</div>
            </div>
            """, unsafe_allow_html=True)

        with p4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Protocols Detected</span>
                    <span class="metric-icon">📡</span>
                </div>
                <div class="metric-value">{stats['detected_protocols_count']}</div>
                <div class="metric-desc">TCP, UDP, ICMP, ARP, etc.</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # Filters Bar for Packets
        st.markdown("""
        <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 16px; margin-bottom: 16px;">
        """, unsafe_allow_html=True)

        pf1, pf2, pf3, pf4, pf5 = st.columns([2, 1.2, 1.4, 1.4, 1.5])
        with pf1:
            pkt_search = st.text_input("Search Packets", placeholder="Search IP or Port...", label_visibility="collapsed")
        with pf2:
            proto_options = ["All Protocols"] + sorted(list(df["protocol"].unique()))
            proto_filter = st.selectbox("Protocol", proto_options, label_visibility="collapsed")
        with pf3:
            src_ip_options = ["All Source IPs"] + sorted([ip for ip in df["src_ip"].unique() if ip != "N/A"])
            src_filter = st.selectbox("Source IP", src_ip_options, label_visibility="collapsed")
        with pf4:
            dst_ip_options = ["All Destination IPs"] + sorted([ip for ip in df["dst_ip"].unique() if ip != "N/A"])
            dst_filter = st.selectbox("Destination IP", dst_ip_options, label_visibility="collapsed")
        with pf5:
            anomaly_filter = st.selectbox("Anomaly Status", ["All Packets", "Flagged as Anomaly Only", "Normal Traffic Only"], label_visibility="collapsed")
        st.markdown("</div>", unsafe_allow_html=True)

        # Apply Filters to DataFrame
        filtered_df = df.copy()

        if pkt_search:
            search_val = pkt_search.strip()
            filtered_df = filtered_df[
                filtered_df["src_ip"].str.contains(search_val, case=False, na=False) |
                filtered_df["dst_ip"].str.contains(search_val, case=False, na=False) |
                filtered_df["protocol"].str.contains(search_val, case=False, na=False) |
                filtered_df["src_port"].astype(str).str.contains(search_val, na=False) |
                filtered_df["dst_port"].astype(str).str.contains(search_val, na=False)
            ]

        if proto_filter != "All Protocols":
            filtered_df = filtered_df[filtered_df["protocol"] == proto_filter]

        if src_filter != "All Source IPs":
            filtered_df = filtered_df[filtered_df["src_ip"] == src_filter]

        if dst_filter != "All Destination IPs":
            filtered_df = filtered_df[filtered_df["dst_ip"] == dst_filter]

        if anomaly_filter == "Flagged as Anomaly Only":
            filtered_df = filtered_df[filtered_df["anomaly_status"] == "Flagged"]
        elif anomaly_filter == "Normal Traffic Only":
            filtered_df = filtered_df[filtered_df["anomaly_status"] == "Normal"]

        total_filtered = len(filtered_df)

        # Table & Pagination
        st.markdown(f"""
        <div class="content-card">
            <div class="card-title-row">
                <div>
                    <h4 class="card-title">Packet Records</h4>
                    <div class="card-subtitle">Displaying {total_filtered:,} packet records matching current criteria</div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        if total_filtered > 0:
            page_size = DEFAULT_PAGE_SIZE
            total_pages = max(1, (total_filtered + page_size - 1) // page_size)
            curr_page = min(st.session_state["packet_page_num"], total_pages)

            # Pagination Controls
            pg_col1, pg_col2, pg_col3, pg_col4 = st.columns([1, 1, 2, 2])
            with pg_col1:
                if st.button("◀ Prev Page", disabled=(curr_page <= 1)):
                    st.session_state["packet_page_num"] = max(1, curr_page - 1)
                    st.rerun()
            with pg_col2:
                if st.button("Next Page ▶", disabled=(curr_page >= total_pages)):
                    st.session_state["packet_page_num"] = min(total_pages, curr_page + 1)
                    st.rerun()
            with pg_col3:
                st.markdown(f"<div style='padding-top: 8px; font-size: 12.5px; color: #64748b;'>Page <b>{curr_page}</b> of <b>{total_pages}</b></div>", unsafe_allow_html=True)

            start_idx = (curr_page - 1) * page_size
            end_idx = min(start_idx + page_size, total_filtered)
            page_df = filtered_df.iloc[start_idx:end_idx]

            packet_records = page_df.rename(columns={
                "packet_id": "Packet #",
                "time_formatted": "Time",
                "src_ip": "Source address",
                "src_port": "Source port",
                "dst_ip": "Destination address",
                "dst_port": "Destination port",
                "protocol": "Protocol",
                "length": "Size (bytes)",
                "tcp_flags": "TCP flags",
                "anomaly_status": "Review status",
            })[
                [
                    "Packet #", "Time", "Source address", "Source port",
                    "Destination address", "Destination port", "Protocol",
                    "Size (bytes)", "TCP flags", "Review status",
                ]
            ].copy()
            for port_column in ["Source port", "Destination port"]:
                    packet_records[port_column] = packet_records[port_column].map(
                        lambda value: str(int(value)) if pd.notna(value) else "—"
                    )
            packet_records["TCP flags"] = packet_records["TCP flags"].replace("", "—").fillna("—")
            packet_records["Review status"] = packet_records["Review status"].replace(
                {"Flagged": "Needs review", "Normal": "No rule triggered"}
            )
            st.dataframe(
                packet_records,
                hide_index=True,
                width="stretch",
                height=min(620, 38 + 35 * len(packet_records)),
            )

            # Detailed Packet Inspection Selector
            st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 6px;'>SELECT PACKET NUMBER TO INSPECT METADATA:</div>", unsafe_allow_html=True)
            
            page_pkt_ids = list(page_df["packet_id"])
            selected_pkt_id = st.selectbox(
                "Select Packet #",
                page_pkt_ids,
                index=0 if page_pkt_ids else 0,
                label_visibility="collapsed"
            )

            # Selected Packet Metadata Card
            sel_pkt_row = df[df["packet_id"] == selected_pkt_id].iloc[0]
            is_pkt_flagged = (sel_pkt_row["anomaly_status"] == "Flagged")
            badge_html = f'<span class="badge badge-flagged">Flagged: {sel_pkt_row["anomaly_type"]}</span>' if is_pkt_flagged else '<span class="badge badge-normal">Normal Packet</span>'

            st.markdown(f"""
            <div class="content-card" style="border-left: 4px solid {'#ef4444' if is_pkt_flagged else '#0d9488'}; margin-top: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div>
                        <span style="font-size: 15px; font-weight: 700; color: #0f172a;">
                            Selected Packet: #{sel_pkt_row['packet_id']} [{sel_pkt_row['protocol']}]
                        </span>
                        <div style="font-size: 12px; color: #64748b; margin-top: 2px;">
                            Detailed header fields and anomaly association
                        </div>
                    </div>
                    <div>{badge_html}</div>
                </div>
            """, unsafe_allow_html=True)

            pk_c1, pk_c2, pk_c3, pk_c4 = st.columns(4)
            with pk_c1:
                st.markdown(f"""
                <div class="detail-label">Source Endpoint</div>
                <div class="detail-value"><code>{sel_pkt_row['src_ip']}:{sel_pkt_row['src_port'] or '-'}</code></div>
                """, unsafe_allow_html=True)
            with pk_c2:
                st.markdown(f"""
                <div class="detail-label">Destination Endpoint</div>
                <div class="detail-value"><code>{sel_pkt_row['dst_ip']}:{sel_pkt_row['dst_port'] or '-'}</code></div>
                """, unsafe_allow_html=True)
            with pk_c3:
                st.markdown(f"""
                <div class="detail-label">Protocol & Length</div>
                <div class="detail-value">{sel_pkt_row['protocol']} ({sel_pkt_row['length']} bytes)</div>
                """, unsafe_allow_html=True)
            with pk_c4:
                st.markdown(f"""
                <div class="detail-label">TCP Flags / Info</div>
                <div class="detail-value">{sel_pkt_row['tcp_flags'] or 'N/A'}</div>
                """, unsafe_allow_html=True)

            if is_pkt_flagged:
                st.markdown(f"""
                <div class="detail-box" style="border-left: 3px solid #ef4444; background: #fff5f5;">
                    <div class="detail-label" style="color: #b91c1c;">Associated Detection Rule:</div>
                    <div style="font-size: 13px; color: #7f1d1d; margin-top: 2px;">
                        This packet was transmitted during a detected <b>{sel_pkt_row['anomaly_type']}</b> window (Alert ID: <b>{sel_pkt_row.get('alert_id') or 'N/A'}</b>).
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("No packets found matching the selected filters.")

        st.markdown("</div>", unsafe_allow_html=True)


def render_csv_explorer():
    """Renders the Machine Learning CSV Dataset Analysis mode inside Packet Explorer."""
    # Context Notice
    st.markdown("""
    <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-left: 4px solid #16a34a; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 13px; color: #166534;">
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 16px;">🤖</span>
            <div>
                <b>Machine Learning Flow Classifier:</b> Supervised <b>Random Forest</b> model trained on the <b>CICIDS2017</b> benchmark dataset (Canadian Institute for Cybersecurity). 
                Evaluates statistical network flow features (flow durations, packet lengths, TCP window sizes, inter-arrival times) to classify traffic as <b>Normal</b> or <b>Suspicious</b>. 
                Distinct from Scapy packet header heuristics.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # -------------------------------------------------------------
    # 1. Model Evaluation Metrics on Held-Out Test Set
    # -------------------------------------------------------------
    metrics = ml_detector.get_model_evaluation_metrics()
    if metrics:
        st.markdown(f"""
        <div class="content-card">
            <div class="card-title-row">
                <div>
                    <h4 class="card-title">Model Evaluation Metrics (Held-Out Test Set)</h4>
                    <div class="card-subtitle">
                        Rigorous evaluation on <b>{metrics['test_size']:,}</b> unseen CICIDS2017 test records (20% stratified holdout, class-balanced Random Forest)
                    </div>
                </div>
                <span class="badge badge-ml-model">Trained: {metrics['trained_at']}</span>
            </div>
        """, unsafe_allow_html=True)

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Test Accuracy</span>
                    <span class="metric-icon">🎯</span>
                </div>
                <div class="metric-value">{metrics['accuracy'] * 100:.2f}%</div>
                <div class="metric-desc">Overall correct predictions on unseen test set</div>
            </div>
            """, unsafe_allow_html=True)

        with m2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Precision (Suspicious)</span>
                    <span class="metric-icon">🔍</span>
                </div>
                <div class="metric-value">{metrics['precision_suspicious'] * 100:.2f}%</div>
                <div class="metric-desc">Low false alarms: {metrics['confusion_matrix']['fp']} false positives</div>
            </div>
            """, unsafe_allow_html=True)

        with m3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Recall (Suspicious)</span>
                    <span class="metric-icon">🛡️</span>
                </div>
                <div class="metric-value">{metrics['recall_suspicious'] * 100:.2f}%</div>
                <div class="metric-desc">Detected {metrics['confusion_matrix']['tp']:,} attacks</div>
            </div>
            """, unsafe_allow_html=True)

        with m4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">F1-Score (Suspicious)</span>
                    <span class="metric-icon">⚖️</span>
                </div>
                <div class="metric-value">{metrics['f1_suspicious'] * 100:.2f}%</div>
                <div class="metric-desc">Harmonic mean of precision & recall</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        # Side-by-side: Confusion Matrix & Feature Importances
        cm_col, fi_col = st.columns([1, 1])

        with cm_col:
            st.markdown("<div style='font-size: 13px; font-weight: 600; color: #1e293b; margin-bottom: 6px;'>Confusion Matrix (Held-Out Test Set)</div>", unsafe_allow_html=True)
            cm_matrix = metrics['confusion_matrix']['matrix']
            tn = metrics['confusion_matrix']['tn']
            fp = metrics['confusion_matrix']['fp']
            fn = metrics['confusion_matrix']['fn']
            tp = metrics['confusion_matrix']['tp']

            cm_text = [
                [f"<b>{tn:,}</b><br>True Normal ({tn/(tn+fp)*100:.1f}%)", f"<b>{fp:,}</b><br>False Suspicious ({fp/(tn+fp)*100:.1f}%)"],
                [f"<b>{fn:,}</b><br>False Normal ({fn/(fn+tp)*100:.1f}%)", f"<b>{tp:,}</b><br>True Suspicious ({tp/(fn+tp)*100:.1f}%)"]
            ]

            fig_cm = go.Figure(data=go.Heatmap(
                z=cm_matrix,
                x=["Pred: Normal", "Pred: Suspicious"],
                y=["Actual: Normal", "Actual: Suspicious"],
                text=cm_text,
                texttemplate="%{text}",
                colorscale=[[0, "#f0fdf4"], [0.5, "#99f6e4"], [1.0, "#0d9488"]],
                showscale=False
            ))
            fig_cm.update_layout(
                height=260,
                margin=dict(l=40, r=20, t=20, b=30),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(tickfont=dict(size=12, color="#334155")),
                yaxis=dict(tickfont=dict(size=12, color="#334155"), autorange="reversed")
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with fi_col:
            st.markdown("<div style='font-size: 13px; font-weight: 600; color: #1e293b; margin-bottom: 6px;'>Top 10 Feature Importances (Random Forest)</div>", unsafe_allow_html=True)
            top_features = metrics['top_features'][:10]
            feat_names = [f['feature'] for f in reversed(top_features)]
            feat_scores = [f['importance'] * 100 for f in reversed(top_features)]

            fig_fi = go.Figure(go.Bar(
                x=feat_scores,
                y=feat_names,
                orientation="h",
                marker=dict(
                    color="#0d9488",
                    line=dict(color="#0f766e", width=1)
                ),
                text=[f"{s:.1f}%" for s in feat_scores],
                textposition="outside"
            ))
            fig_fi.update_layout(
                height=260,
                margin=dict(l=20, r=40, t=20, b=30),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(title="Importance (%)", title_font=dict(size=11), tickfont=dict(size=10)),
                yaxis=dict(tickfont=dict(size=11, color="#334155"))
            )
            st.plotly_chart(fig_fi, use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------------------------------------------
    # 2. Upload CSV File Card
    # -------------------------------------------------------------
    st.markdown("""
    <div class="content-card">
        <div class="card-title-row">
            <div>
                <h4 class="card-title">Upload Network Traffic CSV Dataset</h4>
                <div class="card-subtitle">Upload compatible network flow records (CICIDS2017 / CICFlowMeter schema) to run preprocessing and ML classification</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    csv_col1, csv_col2 = st.columns([1.5, 1])
    with csv_col1:
        uploaded_csv = st.file_uploader(
            "Choose a network traffic CSV file",
            type=["csv"],
            help="Upload network flow dataset in CSV format (e.g. CICIDS2017 export)"
        )
        if uploaded_csv is not None:
            if st.session_state["csv_filename"] != uploaded_csv.name:
                success = run_csv_analysis(uploaded_csv, uploaded_csv.name)
                if success:
                    st.success(f"Dataset {uploaded_csv.name} successfully analyzed!")
                    st.rerun()

    with csv_col2:
        if st.session_state["csv_analyzed"] and st.session_state["df_csv_results"] is not None:
            filesize_str = packet_analyzer.format_bytes(st.session_state["csv_filesize"])
            st.markdown(f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
                <div style="font-size: 13px; font-weight: 600; color: #0f172a; margin-bottom: 6px;">
                    📄 Active Dataset: <code>{st.session_state['csv_filename']}</code>
                </div>
                <div style="font-size: 12px; color: #64748b; margin-bottom: 4px;">
                    Size: <b>{filesize_str}</b> | Flow Records: <b>{len(st.session_state['df_csv_results']):,}</b>
                </div>
                <div style="font-size: 12px; color: #059669; font-weight: 500; margin-bottom: 10px;">
                    ● Processing Status: Preprocessed & Classified Successfully
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
                <div style="font-size: 12.5px; color: #64748b;">
                    No dataset currently loaded. Upload a <code>.csv</code> file or load the CICIDS2017 test sample.
                </div>
            </div>
            """, unsafe_allow_html=True)

        if st.button("🚀 Load Sample CSV Dataset (sample_traffic_test.csv)", use_container_width=True):
            if os.path.exists(SAMPLE_CSV_PATH):
                run_csv_analysis(SAMPLE_CSV_PATH, "sample_traffic_test.csv")
                st.rerun()
            else:
                st.error("Sample CSV file not found. Run `python train_model.py` to generate it.")

    # Schema & Preprocessing guide expander
    with st.expander("ℹ️ Dataset Compatibility & Preprocessing Pipeline Guide"):
        st.markdown("""
        **Pipeline Preprocessing Steps Applied Automatically:**
        1. **Feature Matching:** Validates against the 77 network flow features learned from CICIDS2017 (e.g. *Flow Duration, Total Fwd Packets, Packet Length Mean, TCP Flags, Window Sizes, IAT stats*).
        2. **Missing Feature Imputation:** If uploaded records lack certain features, missing columns are automatically imputed with training set median values.
        3. **Infinite & NaN Handling:** Zero-duration division artifacts (`np.inf`, `-np.inf`) and missing numbers are replaced with median values.
        4. **Binary Inference:** Random Forest evaluates tree decisions and outputs class probability $P(\\text{Suspicious})$ and $P(\\text{Normal})$.
        """)

    st.markdown("</div>", unsafe_allow_html=True)

    # -------------------------------------------------------------
    # 3. Predictions and Summary Statistics
    # -------------------------------------------------------------
    if st.session_state["csv_analyzed"] and st.session_state["df_csv_results"] is not None:
        df_csv = st.session_state["df_csv_results"]
        stats = st.session_state["csv_stats"]

        # Display any imputation notices
        if st.session_state["csv_warnings"]:
            for w in st.session_state["csv_warnings"]:
                st.info(f"ℹ️ {w}")

        # 4 Summary Metric Cards
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Total Records</span>
                    <span class="metric-icon">📊</span>
                </div>
                <div class="metric-value">{stats['total_records']:,}</div>
                <div class="metric-desc">Available flow records</div>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Predicted Suspicious</span>
                    <span class="metric-icon" style="color: #ef4444;">⚠️</span>
                </div>
                <div class="metric-value red">{stats['suspicious_count']:,}</div>
                <div class="metric-desc">Flagged as anomalous flows</div>
            </div>
            """, unsafe_allow_html=True)

        with c3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Predicted Normal</span>
                    <span class="metric-icon" style="color: #0d9488;">✓</span>
                </div>
                <div class="metric-value" style="color: #0d9488;">{stats['normal_count']:,}</div>
                <div class="metric-desc">Benign network traffic</div>
            </div>
            """, unsafe_allow_html=True)

        with c4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Suspicious Ratio</span>
                    <span class="metric-icon">📈</span>
                </div>
                <div class="metric-value">{stats['suspicious_ratio']:.1f}%</div>
                <div class="metric-desc">Avg Confidence: {stats['avg_confidence']:.1f}%</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # Visualizations: Donut & Confidence Distribution
        ch1, ch2 = st.columns(2)
        with ch1:
            st.markdown("""
            <div class="content-card">
                <div class="card-title-row">
                    <div>
                        <h4 class="card-title">Prediction Class Distribution</h4>
                        <div class="card-subtitle">Normal vs Suspicious traffic ratio in analyzed CSV</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            donut_fig = go.Figure(data=[go.Pie(
                labels=["Normal", "Suspicious"],
                values=[stats["normal_count"], stats["suspicious_count"]],
                hole=0.55,
                marker=dict(colors=["#0d9488", "#ef4444"]),
                textinfo="label+percent",
                hoverinfo="label+value+percent"
            )])
            donut_fig.update_layout(
                height=240,
                margin=dict(l=20, r=20, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.15, xanchor="center", x=0.5)
            )
            st.plotly_chart(donut_fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with ch2:
            st.markdown("""
            <div class="content-card">
                <div class="card-title-row">
                    <div>
                        <h4 class="card-title">Model Prediction Confidence</h4>
                        <div class="card-subtitle">Distribution of Random Forest decision confidence</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            conf_bins = pd.cut(df_csv["confidence"] * 100, bins=[50, 70, 80, 90, 95, 100], labels=["50-70%", "70-80%", "80-90%", "90-95%", "95-100%"])
            conf_counts = conf_bins.value_counts().sort_index()
            conf_fig = go.Figure(go.Bar(
                x=conf_counts.index.astype(str),
                y=conf_counts.values,
                marker=dict(color="#0284c7"),
                text=conf_counts.values,
                textposition="auto"
            ))
            conf_fig.update_layout(
                height=240,
                margin=dict(l=20, r=20, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(title="Confidence Range", tickfont=dict(size=11)),
                yaxis=dict(title="Record Count", tickfont=dict(size=11))
            )
            st.plotly_chart(conf_fig, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # Ground Truth Validation (if Label exists in CSV)
        if stats.get("has_ground_truth") and stats.get("batch_eval"):
            b_eval = stats["batch_eval"]
            st.markdown(f"""
            <div class="content-card" style="border-left: 4px solid #0d9488;">
                <div class="card-title-row">
                    <div>
                        <h4 class="card-title">Ground Truth Batch Validation</h4>
                        <div class="card-subtitle">
                            This uploaded CSV contains labeled traffic (<code>{stats['ground_truth_col']}</code>). Model validation performance on this batch:
                        </div>
                    </div>
                    <span class="badge badge-normal">Accuracy: {b_eval['accuracy'] * 100:.2f}%</span>
                </div>
            """, unsafe_allow_html=True)
            gv1, gv2, gv3, gv4 = st.columns(4)
            with gv1:
                st.markdown(f"<div style='font-size: 11px; color: #64748b;'>BATCH ACCURACY</div><div style='font-size: 18px; font-weight: 700; color: #0f172a;'>{b_eval['accuracy'] * 100:.2f}%</div>", unsafe_allow_html=True)
            with gv2:
                st.markdown(f"<div style='font-size: 11px; color: #64748b;'>BATCH PRECISION</div><div style='font-size: 18px; font-weight: 700; color: #0f172a;'>{b_eval['precision'] * 100:.2f}%</div>", unsafe_allow_html=True)
            with gv3:
                st.markdown(f"<div style='font-size: 11px; color: #64748b;'>BATCH RECALL</div><div style='font-size: 18px; font-weight: 700; color: #0f172a;'>{b_eval['recall'] * 100:.2f}%</div>", unsafe_allow_html=True)
            with gv4:
                st.markdown(f"<div style='font-size: 11px; color: #64748b;'>BATCH F1-SCORE</div><div style='font-size: 18px; font-weight: 700; color: #0f172a;'>{b_eval['f1_score'] * 100:.2f}%</div>", unsafe_allow_html=True)
            
            # Attack types breakdown
            if b_eval.get("ground_truth_counts"):
                st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
                chips_html = " ".join([
                    f"<span class='badge' style='background: #f1f5f9; color: #334155; margin-right: 6px;'><b>{lbl}:</b> {cnt:,}</span>"
                    for lbl, cnt in b_eval["ground_truth_counts"].items()
                ])
                st.markdown(f"<div style='font-size: 12px; color: #475569;'><b>Dataset Ground Truth Breakdown:</b> {chips_html}</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # -------------------------------------------------------------
        # 4. Filters Bar for CSV Flow Records
        # -------------------------------------------------------------
        st.markdown("""
        <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 16px; margin-bottom: 16px;">
        """, unsafe_allow_html=True)

        cf1, cf2, cf3 = st.columns([2.5, 1.5, 1.5])
        with cf1:
            csv_search = st.text_input("Search Records", placeholder="Search by Record #, Label, or values...", label_visibility="collapsed")
        with cf2:
            pred_filter = st.selectbox("ML Prediction", ["All Predictions", "Suspicious Only", "Normal Only"], label_visibility="collapsed")
        with cf3:
            conf_filter = st.selectbox("Confidence Level", ["All Confidence", "High Confidence (>= 90%)", "Moderate Confidence (< 90%)"], label_visibility="collapsed")
        st.markdown("</div>", unsafe_allow_html=True)

        # Apply Filters
        filtered_csv = df_csv.copy()

        if pred_filter == "Suspicious Only":
            filtered_csv = filtered_csv[filtered_csv["ml_prediction"] == "Suspicious"]
        elif pred_filter == "Normal Only":
            filtered_csv = filtered_csv[filtered_csv["ml_prediction"] == "Normal"]

        if conf_filter == "High Confidence (>= 90%)":
            filtered_csv = filtered_csv[filtered_csv["confidence"] >= 0.90]
        elif conf_filter == "Moderate Confidence (< 90%)":
            filtered_csv = filtered_csv[filtered_csv["confidence"] < 0.90]

        if csv_search:
            s_val = csv_search.strip()
            mask = filtered_csv.astype(str).apply(lambda row: row.str.contains(s_val, case=False).any(), axis=1)
            filtered_csv = filtered_csv[mask]

        total_csv_filtered = len(filtered_csv)

        # Table & Pagination
        st.markdown(f"""
        <div class="content-card">
            <div class="card-title-row">
                <div>
                    <h4 class="card-title">Network Flow Classification Records</h4>
                    <div class="card-subtitle">Displaying {total_csv_filtered:,} flow records matching current criteria</div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        if total_csv_filtered > 0:
            csv_page_size = DEFAULT_CSV_PAGE_SIZE
            csv_total_pages = max(1, (total_csv_filtered + csv_page_size - 1) // csv_page_size)
            curr_csv_page = min(st.session_state["csv_page_num"], csv_total_pages)

            pg_c1, pg_c2, pg_c3, pg_c4 = st.columns([1, 1, 2, 2])
            with pg_c1:
                if st.button("◀ Prev Page", key="csv_prev_btn", disabled=(curr_csv_page <= 1)):
                    st.session_state["csv_page_num"] = max(1, curr_csv_page - 1)
                    st.rerun()
            with pg_c2:
                if st.button("Next Page ▶", key="csv_next_btn", disabled=(curr_csv_page >= csv_total_pages)):
                    st.session_state["csv_page_num"] = min(csv_total_pages, curr_csv_page + 1)
                    st.rerun()
            with pg_c3:
                st.markdown(f"<div style='padding-top: 8px; font-size: 12.5px; color: #64748b;'>Page <b>{curr_csv_page}</b> of <b>{csv_total_pages}</b></div>", unsafe_allow_html=True)

            start_idx = (curr_csv_page - 1) * csv_page_size
            end_idx = min(start_idx + csv_page_size, total_csv_filtered)
            page_csv_df = filtered_csv.iloc[start_idx:end_idx]

            # Render readable flow records with Streamlit's native table.
            has_gt = stats.get("has_ground_truth", False)
            flow_records = []
            for row_idx, r in page_csv_df.iterrows():
                conf_val = f"{r['confidence'] * 100:.1f}%"
                flow_record = {
                    "Record #": row_idx + 1,
                    "Flow duration (µs)": (
                        f"{int(r['Flow Duration']):,}"
                        if "Flow Duration" in r and pd.notnull(r["Flow Duration"]) else "—"
                    ),
                    "Forward packets": (
                        f"{int(r['Total Fwd Packets']):,}"
                        if "Total Fwd Packets" in r and pd.notnull(r["Total Fwd Packets"]) else "—"
                    ),
                    "Backward packets": (
                        f"{int(r['Total Backward Packets']):,}"
                        if "Total Backward Packets" in r and pd.notnull(r["Total Backward Packets"]) else "—"
                    ),
                    "Average packet length": (
                        f"{float(r['Packet Length Mean']):.1f} B"
                        if "Packet Length Mean" in r and pd.notnull(r["Packet Length Mean"]) else "—"
                    ),
                    "Average packet size": (
                        f"{float(r['Average Packet Size']):.1f} B"
                        if "Average Packet Size" in r and pd.notnull(r["Average Packet Size"]) else "—"
                    ),
                    "Model result": r["ml_prediction"],
                    "Confidence": conf_val,
                }
                if has_gt:
                    flow_record["Dataset label"] = str(r[stats["ground_truth_col"]])
                    flow_record["Prediction matches label"] = (
                        "Yes" if r.get("is_correct", True) else "No"
                    )
                flow_records.append(flow_record)
            st.dataframe(
                pd.DataFrame(flow_records),
                hide_index=True,
                width="stretch",
                height=min(620, 38 + 35 * len(flow_records)),
            )

            # Detailed Record Selector
            st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 6px;'>SELECT RECORD NUMBER TO INSPECT NETWORK FLOW METADATA:</div>", unsafe_allow_html=True)

            page_flow_indices = [idx + 1 for idx in page_csv_df.index]
            selected_record_num = st.selectbox(
                "Select Record #",
                page_flow_indices,
                index=0 if page_flow_indices else 0,
                label_visibility="collapsed",
                key="csv_flow_select"
            )

            # Inspect selected record
            sel_row_idx = selected_record_num - 1
            sel_row = df_csv.loc[sel_row_idx]
            is_sel_suspicious = (sel_row["ml_prediction"] == "Suspicious")
            badge_sel_html = (
                f'<span class="badge badge-ml-suspicious">ML Predicted: Suspicious ({sel_row["confidence_str"]})</span>'
                if is_sel_suspicious
                else f'<span class="badge badge-ml-normal">ML Predicted: Normal ({sel_row["confidence_str"]})</span>'
            )

            border_clr = "#ef4444" if is_sel_suspicious else "#0d9488"
            st.markdown(f"""
            <div class="content-card" style="border-left: 4px solid {border_clr}; margin-top: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div>
                        <span style="font-size: 15px; font-weight: 700; color: #0f172a;">
                            Selected Flow Record: #{selected_record_num}
                        </span>
                        <div style="font-size: 12px; color: #64748b; margin-top: 2px;">
                            Detailed flow properties & Random Forest class decision probabilities
                        </div>
                    </div>
                    <div>{badge_sel_html}</div>
                </div>
            """, unsafe_allow_html=True)

            sc1, sc2, sc3, sc4 = st.columns(4)
            with sc1:
                dur_val = f"{int(sel_row['Flow Duration']):,} µs" if "Flow Duration" in sel_row and pd.notnull(sel_row["Flow Duration"]) else "N/A"
                st.markdown(f"""
                <div class="detail-label">Flow Duration</div>
                <div class="detail-value">{dur_val}</div>
                """, unsafe_allow_html=True)

            with sc2:
                fwd_p = sel_row.get("Total Fwd Packets", "-")
                bwd_p = sel_row.get("Total Backward Packets", "-")
                st.markdown(f"""
                <div class="detail-label">Packets (Fwd / Bwd)</div>
                <div class="detail-value">{fwd_p} / {bwd_p}</div>
                """, unsafe_allow_html=True)

            with sc3:
                fwd_len = sel_row.get("Total Length of Fwd Packets", "-")
                bwd_len = sel_row.get("Total Length of Bwd Packets", "-")
                st.markdown(f"""
                <div class="detail-label">Bytes (Fwd / Bwd)</div>
                <div class="detail-value">{fwd_len} B / {bwd_len} B</div>
                """, unsafe_allow_html=True)

            with sc4:
                win_fwd = sel_row.get("Init_Win_bytes_forward", "-")
                win_bwd = sel_row.get("Init_Win_bytes_backward", "-")
                st.markdown(f"""
                <div class="detail-label">Init TCP Window (Fwd/Bwd)</div>
                <div class="detail-value">{win_fwd} / {win_bwd}</div>
                """, unsafe_allow_html=True)

            # Probability Breakdown
            p_norm = sel_row["prob_normal"] * 100
            p_susp = sel_row["prob_suspicious"] * 100
            st.markdown(f"""
            <div class="detail-box">
                <div class="detail-label" style="margin-bottom: 6px;">Random Forest Class Probabilities:</div>
                <div style="display: flex; gap: 20px; font-size: 13px; color: #334155; margin-bottom: 8px;">
                    <div>● Normal Probability: <b style="color: #047857;">{p_norm:.1f}%</b></div>
                    <div>● Suspicious Probability: <b style="color: #b91c1c;">{p_susp:.1f}%</b></div>
                </div>
                <div style="background: #e2e8f0; border-radius: 10px; height: 10px; overflow: hidden; display: flex;">
                    <div style="width: {p_norm}%; background: #0d9488;"></div>
                    <div style="width: {p_susp}%; background: #ef4444;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            if has_gt:
                orig_label = sel_row[stats["ground_truth_col"]]
                st.markdown(f"""
                <div style="font-size: 12px; color: #475569; margin-top: 10px;">
                    <b>Annotated Ground Truth:</b> <code>{orig_label}</code> | 
                    <b>Evaluation Outcome:</b> {'✓ Successfully Identified' if sel_row.get('is_correct') else '✗ Misclassified by Model'}
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("No flow records found matching the selected filters.")

        st.markdown("</div>", unsafe_allow_html=True)


# =============================================================
# PAGE 1: DASHBOARD
# =============================================================
if st.session_state["current_page"] == "Dashboard":
    # Header
    status_label = "Online" if st.session_state["analyzed"] else "No File Loaded"
    filename_label = st.session_state["pcap_filename"] or "No capture loaded"

    st.markdown(f"""
    <div class="page-header-container">
        <div>
            <h1 class="page-title">Network Traffic Overview</h1>
            <div class="page-subtitle">Real-time packet analysis & anomaly detection using rule-based heuristics</div>
        </div>
        <div class="status-pill">
            <span class="status-dot"></span>
            <span>System Status: {status_label}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    render_context_banner()

    # Check if file analyzed
    if not st.session_state["analyzed"]:
        st.markdown("""
        <div class="content-card" style="text-align: center; padding: 40px 20px;">
            <div style="font-size: 40px; margin-bottom: 12px;">📁</div>
            <h3 style="margin-bottom: 8px;">No Packet Capture Analyzed Yet</h3>
            <p style="color: #64748b; font-size: 14px; max-width: 500px; margin: 0 auto 20px auto;">
                Please upload a <code>.pcap</code> or <code>.pcapng</code> file in Packet Explorer, or click the button below to load the synthetic test capture with pre-configured anomalies.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Load Sample PCAP (sample_traffic.pcap)", type="primary"):
            if os.path.exists(SAMPLE_PCAP_PATH):
                run_analysis(SAMPLE_PCAP_PATH, "sample_traffic.pcap")
                st.rerun()
            else:
                st.warning("Sample PCAP not found. Generate one in Packet Explorer.")
    else:
        # File info bar
        stats = st.session_state["traffic_stats"]
        filesize_str = packet_analyzer.format_bytes(st.session_state["pcap_filesize"])
        total_packets = stats["total_packets"]
        alerts = database.get_alerts(st.session_state["pcap_filename"])
        total_anomalies = len(alerts)
        high_critical_alerts = sum(1 for a in alerts if a["severity"] in [SEVERITY_CRITICAL, SEVERITY_HIGH])

        col_f1, col_f2 = st.columns([4, 1])
        with col_f1:
            st.markdown(f"""
            <div class="file-info-bar">
                <div class="file-info-left">
                    <span style="font-size: 16px;">📁</span>
                    <span>Analyzed File: <b class="file-name-tag">{st.session_state['pcap_filename']}</b></span>
                    <span style="color: #cbd5e1;">|</span>
                    <span>Size: <b>{filesize_str}</b></span>
                    <span style="color: #cbd5e1;">|</span>
                    <span>Total Packets: <b>{total_packets:,}</b></span>
                </div>
            </div>
            """, unsafe_allow_html=True)
        with col_f2:
            if st.button("📤 Upload New PCAP", use_container_width=True):
                st.session_state["current_page"] = "Packet Explorer"
                st.rerun()

        # 4 Top Metric Cards
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Total Packets Analyzed</span>
                    <span class="metric-icon">📑</span>
                </div>
                <div class="metric-value">{total_packets:,}</div>
                <div class="metric-desc">Cumulative capture of packet records</div>
            </div>
            """, unsafe_allow_html=True)

        with m2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Total Traffic Volume</span>
                    <span class="metric-icon">📈</span>
                </div>
                <div class="metric-value">{stats['total_volume_str']}</div>
                <div class="metric-desc">{stats['total_volume_bytes']:,} bytes cumulative data load</div>
            </div>
            """, unsafe_allow_html=True)

        with m3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Total Anomalies</span>
                    <span class="metric-icon">⚠️</span>
                </div>
                <div class="metric-value">{total_anomalies}</div>
                <div class="metric-desc">Actively flagged across 3 rule categories</div>
            </div>
            """, unsafe_allow_html=True)

        with m4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">High Alerts</span>
                    <span class="metric-icon" style="color: #ef4444;">🚨</span>
                </div>
                <div class="metric-value red">{high_critical_alerts}</div>
                <div class="metric-desc">Critical & High severity flags needing attention</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # Middle Row: Protocol Distribution & Traffic Over Time
        col_c1, col_c2 = st.columns([1, 1.4])

        with col_c1:
            st.markdown("""
            <div class="content-card">
                <div class="card-title-row">
                    <div>
                        <h4 class="card-title">Protocol Distribution</h4>
                        <div class="card-subtitle">Packet breakdown by transport protocol</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            # Donut chart
            proto_counts = stats["protocol_counts"]
            labels = list(proto_counts.keys())
            values = list(proto_counts.values())
            colors = ["#0d9488", "#3b82f6", "#38bdf8", "#94a3b8"]

            fig_donut = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.68,
                marker=dict(colors=colors),
                textinfo="percent",
                hoverinfo="label+value+percent",
                showlegend=True
            )])
            fig_donut.update_layout(
                margin=dict(t=10, b=10, l=10, r=10),
                height=260,
                annotations=[dict(
                    text=f"<b>{total_packets:,}</b><br><span style='font-size:10px; color:#64748b;'>TOTAL PACKETS</span>",
                    x=0.5, y=0.5,
                    font_size=18,
                    showarrow=False
                )],
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5,
                    font=dict(size=11)
                )
            )
            st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False})
            st.markdown("</div>", unsafe_allow_html=True)

        with col_c2:
            st.markdown("""
            <div class="content-card">
                <div class="card-title-row">
                    <div>
                        <h4 class="card-title">Traffic Over Time</h4>
                        <div class="card-subtitle">Packet frequency grouped across capture timeline</div>
                    </div>
                    <span style="font-size: 11px; background: #f1f5f9; padding: 4px 8px; border-radius: 6px; color: #475569; font-weight: 500;">
                        1s intervals
                    </span>
                </div>
            """, unsafe_allow_html=True)

            ts_df = stats["time_series"]
            if not ts_df.empty:
                fig_area = go.Figure()
                fig_area.add_trace(go.Scatter(
                    x=ts_df["time_label"],
                    y=ts_df["packet_count"],
                    fill='tozeroy',
                    mode='lines',
                    line=dict(color='#0d9488', width=2.5, shape='spline'),
                    fillcolor='rgba(13, 148, 136, 0.15)',
                    hovertemplate='<b>Time</b>: %{x}<br><b>Packets</b>: %{y:,}<extra></extra>'
                ))
                fig_area.update_layout(
                    margin=dict(t=10, b=20, l=10, r=10),
                    height=260,
                    xaxis=dict(
                        showgrid=False,
                        tickfont=dict(size=10, color='#64748b'),
                        nticks=8
                    ),
                    yaxis=dict(
                        showgrid=True,
                        gridcolor='#f1f5f9',
                        tickfont=dict(size=10, color='#64748b')
                    ),
                    plot_bgcolor='white',
                    paper_bgcolor='white'
                )
                st.plotly_chart(fig_area, use_container_width=True, config={"displayModeBar": False})
            st.markdown("</div>", unsafe_allow_html=True)

        # Bottom Row: Top Source IP Addresses & Recent Detected Anomalies
        col_b1, col_b2 = st.columns([1, 1.4])

        with col_b1:
            st.markdown("""
            <div class="content-card">
                <div class="card-title-row">
                    <div>
                        <h4 class="card-title">Top Source IP Addresses</h4>
                        <div class="card-subtitle">Packets sent per unique host IP address</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            top_sources = stats["top_sources"]
            if not top_sources.empty:
                for _, row in top_sources.iterrows():
                    ip = row["src_ip"]
                    cnt = int(row["packet_count"])
                    pct = row["percentage"]
                    st.markdown(f"""
                    <div style="margin-bottom: 14px;">
                        <div style="display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 4px;">
                            <span style="font-family: monospace; font-weight: 600; color: #1e293b;">{ip}</span>
                            <span style="font-weight: 600; color: #0d9488;">{cnt:,} ({pct:.1f}%)</span>
                        </div>
                        <div style="background-color: #f1f5f9; height: 7px; border-radius: 4px; overflow: hidden;">
                            <div style="background-color: #0d9488; width: {min(100, pct*2.2):.1f}%; height: 100%; border-radius: 4px;"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No IP records available.")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_b2:
            st.subheader("Recent anomalies")
            st.caption(
                "The latest traffic patterns that crossed a detection-rule threshold. "
                "A flag is an indicator to review, not proof of an attack."
            )

            recent_alerts = sorted(
                alerts, key=lambda alert: alert.get("timestamp", 0), reverse=True
            )[:5]
            if recent_alerts:
                for a in recent_alerts:
                    source_ip = a.get("source_ip", "Unknown host")
                    anomaly_type = a.get("anomaly_type", "Unspecified anomaly")
                    packet_count = a.get("packet_count", 0)
                    time_window = a.get("time_window", "a short time window")
                    dest_ip = a.get("dest_ip")
                    dest_port = a.get("dest_port")

                    if anomaly_type == "Possible Port Scanning":
                        port_count = a.get("distinct_ports", 0)
                        target = f" on {dest_ip}" if dest_ip else ""
                        explanation = (
                            f"{source_ip} attempted connections to {port_count} "
                            f"different ports{target} within {time_window}."
                        )
                    elif anomaly_type == "Repeated Connection Attempts":
                        destination = dest_ip or "an unknown destination"
                        if dest_port:
                            destination += f":{dest_port}"
                        explanation = (
                            f"{source_ip} made {packet_count} connection attempts to "
                            f"{destination} within {time_window}."
                        )
                    else:
                        explanation = (
                            f"{source_ip} sent {packet_count} packets within "
                            f"{time_window}."
                        )

                    with st.container(border=True):
                        severity_col, details_col = st.columns([1, 4])
                        with severity_col:
                            st.markdown(f"**{a.get('severity', 'Unknown')}**")
                            st.caption(a.get("time_formatted", "Time unavailable"))
                        with details_col:
                            st.markdown(f"**{anomaly_type}**")
                            st.write(explanation)
            else:
                st.info("No anomalies detected in the current capture.")

            col_btn, _ = st.columns([1, 2])
            with col_btn:
                if st.button("View All Alerts →", key="view_all_alerts_btn"):
                    st.session_state["current_page"] = "Anomaly Detection & Alerts"
                    st.rerun()


# =============================================================
# PAGE 2: ANOMALY DETECTION & ALERTS
# =============================================================
elif st.session_state["current_page"] == "Anomaly Detection & Alerts":
    st.markdown("""
    <div class="page-header-container">
        <div>
            <h1 class="page-title">Anomaly Detection & Alerts</h1>
            <div class="page-subtitle">Rule-based heuristic detection & persistent incident records and status</div>
        </div>
        <div class="status-pill">
            <span class="status-dot"></span>
            <span>Rules Active: 3 Rules</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    render_context_banner()

    if not st.session_state["analyzed"]:
        st.warning("⚠️ No packet capture is currently loaded. Please upload a PCAP file in Packet Explorer or load the sample file.")
        if st.button("🚀 Load Sample PCAP", type="primary"):
            run_analysis(SAMPLE_PCAP_PATH, "sample_traffic.pcap")
            st.rerun()
    else:
        # Get statistics from SQLite for the current capture
        db_stats = database.get_alert_statistics(st.session_state["pcap_filename"])
        
        # 3 Top Metric Cards
        a1, a2, a3 = st.columns(3)
        with a1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Total Anomalies</span>
                    <span class="metric-icon">⚠️</span>
                </div>
                <div class="metric-value">{db_stats['total_anomalies']}</div>
                <div class="metric-desc">Actively flagged rule violations</div>
            </div>
            """, unsafe_allow_html=True)

        with a2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">High Severity Alerts</span>
                    <span class="metric-icon" style="color: #ea580c;">🔥</span>
                </div>
                <div class="metric-value">{db_stats['high_critical_count']}</div>
                <div class="metric-desc">Critical & High severity incidents</div>
            </div>
            """, unsafe_allow_html=True)

        with a3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header">
                    <span class="metric-title">Most Frequent Anomaly Type</span>
                    <span class="metric-icon">📊</span>
                </div>
                <div class="metric-value" style="font-size: 20px; line-height: 1.4;">{db_stats['top_anomaly_type']}</div>
                <div class="metric-desc">{db_stats['top_anomaly_count']} occurrences flagged in capture</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        # Detection Rules Overview (3 rule cards)
        r1, r2, r3 = st.columns(3)
        with r1:
            st.markdown(f"""
            <div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px;">
                <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; color: #0d9488;">
                    <span>⚡</span> Rule A: High Packet Rate
                </div>
                <div style="font-size: 11.5px; color: #64748b; margin-top: 4px;">
                    Threshold: &gt; {HIGH_PACKET_RATE_THRESHOLD} pkts / {HIGH_PACKET_RATE_WINDOW_SECONDS:.0f}s window
                </div>
            </div>
            """, unsafe_allow_html=True)

        with r2:
            st.markdown(f"""
            <div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px;">
                <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; color: #0284c7;">
                    <span>🎯</span> Rule B: Possible Port Scanning
                </div>
                <div style="font-size: 11.5px; color: #64748b; margin-top: 4px;">
                    Threshold: &gt; {PORT_SCAN_PORT_THRESHOLD} distinct ports / {PORT_SCAN_WINDOW_SECONDS:.0f}s (TCP SYN)
                </div>
            </div>
            """, unsafe_allow_html=True)

        with r3:
            st.markdown(f"""
            <div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px;">
                <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; color: #d97706;">
                    <span>🔄</span> Rule C: Repeated Connections
                </div>
                <div style="font-size: 11.5px; color: #64748b; margin-top: 4px;">
                    Threshold: &gt; {REPEATED_CONN_THRESHOLD} attempts / same dst:port / {REPEATED_CONN_WINDOW_SECONDS:.0f}s
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

        # Filters Bar
        st.markdown("""
        <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 16px; margin-bottom: 16px;">
        """, unsafe_allow_html=True)
        f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([2.5, 1.2, 1.5, 1.2, 0.8])

        with f_col1:
            search_query = st.text_input("Search alerts", placeholder="Search by IP, Alert ID, or keyword...", label_visibility="collapsed")
        with f_col2:
            severity_filter = st.selectbox("Severity", ["All Severities", "Critical", "High", "Medium", "Low"], label_visibility="collapsed")
        with f_col3:
            type_filter = st.selectbox("Anomaly Type", ["All Types", "High Packet Rate", "Possible Port Scanning", "Repeated Connection Attempts"], label_visibility="collapsed")
        with f_col4:
            status_filter = st.selectbox("Status", ["All Statuses", "Active", "Acknowledged", "Resolved"], label_visibility="collapsed")
        with f_col5:
            if st.button("Reset", use_container_width=True):
                search_query = ""
                severity_filter = "All Severities"
                type_filter = "All Types"
                status_filter = "All Statuses"
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

        # Query filtered alerts from SQLite
        alerts_list = database.get_alerts(
            capture_filename=st.session_state["pcap_filename"],
            severity=severity_filter,
            anomaly_type=type_filter,
            status=status_filter,
            search=search_query
        )

        # Table Display
        st.markdown(f"""
        <div class="content-card">
            <div class="card-title-row">
                <div>
                    <h4 class="card-title">Alert Records</h4>
                    <div class="card-subtitle">Showing {len(alerts_list)} detected incident flags</div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        if alerts_list:
            # Form select options for radio/selectbox selection
            alert_options = [f"{a['alert_id']} — {a['anomaly_type']} (Source: {a['source_ip']}) [{a['severity']}]" for a in alerts_list]
            
            # Quick Alert Selector for Detail View
            st.markdown("<div style='font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 6px;'>SELECT AN ALERT TO INSPECT FORENSIC DETAILS:</div>", unsafe_allow_html=True)
            selected_option = st.selectbox(
                "Select alert to inspect",
                alert_options,
                index=0,
                key="alert_selector_box",
                label_visibility="collapsed"
            )
            selected_alert_id = selected_option.split(" — ")[0]
            st.session_state["selected_alert_id"] = selected_alert_id

            alert_records = []
            for a in alerts_list:
                destination = a.get("dest_ip") or "Unknown"
                if a.get("dest_port"):
                    destination += f":{a['dest_port']}"
                anomaly_type = a["anomaly_type"]
                time_window = a.get("time_window", "a short time")
                if anomaly_type == "Possible Port Scanning":
                    activity = (
                        f"Contacted {a.get('distinct_ports', 0)} different ports "
                        f"in {time_window}"
                    )
                elif anomaly_type == "Repeated Connection Attempts":
                    activity = (
                        f"{a.get('packet_count', 0)} connection attempts "
                        f"in {time_window}"
                    )
                else:
                    activity = (
                        f"{a.get('packet_count', 0)} packets sent in {time_window}"
                    )
                alert_records.append({
                    "Alert": a["alert_id"],
                    "Observed activity": activity,
                    "Source device": a["source_ip"],
                    "Destination": destination,
                    "Detected at": a["time_formatted"],
                    "Severity": a["severity"],
                    "Review status": a["status"],
                })
            st.dataframe(
                pd.DataFrame(alert_records),
                hide_index=True,
                width="stretch",
                height=min(620, 38 + 35 * len(alert_records)),
            )
            st.markdown("</div>", unsafe_allow_html=True)

            # Selected Alert Detail Panel
            selected_alert = database.get_alert_by_id(st.session_state["selected_alert_id"])
            if selected_alert:
                sev_cls = f"badge-{selected_alert['severity'].lower()}"
                stat_map = {
                    "Active": "badge-active",
                    "Acknowledged": "badge-ack",
                    "Resolved": "badge-resolved",
                }
                stat_cls = stat_map.get(selected_alert['status'], "badge-normal")

                st.markdown(f"""
                <div class="content-card" style="border-left: 4px solid #0d9488;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <div>
                            <span style="font-size: 16px; font-weight: 700; color: #0f172a;">
                                Selected Alert: [{selected_alert['alert_id']}] {selected_alert['anomaly_type']}
                            </span>
                            <div style="font-size: 12px; color: #64748b; margin-top: 2px;">
                                Detailed breakdown of detection heuristics and associated packet indicators
                            </div>
                        </div>
                        <div style="display: flex; gap: 8px;">
                            <span class="badge {sev_cls}">{selected_alert['severity']}</span>
                            <span class="badge {stat_cls}">{selected_alert['status']}</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

                d1, d2, d3, d4 = st.columns(4)
                with d1:
                    st.markdown(f"""
                    <div class="detail-label">Source Host IP</div>
                    <div class="detail-value"><code>{selected_alert['source_ip']}</code></div>
                    """, unsafe_allow_html=True)
                with d2:
                    dst_display = selected_alert['dest_ip'] or 'N/A'
                    if selected_alert['dest_port']:
                        dst_display += f":{selected_alert['dest_port']}"
                    st.markdown(f"""
                    <div class="detail-label">Target Destination</div>
                    <div class="detail-value"><code>{dst_display}</code></div>
                    """, unsafe_allow_html=True)
                with d3:
                    st.markdown(f"""
                    <div class="detail-label">Triggered Rule</div>
                    <div class="detail-value">{selected_alert['triggered_rule']}</div>
                    """, unsafe_allow_html=True)
                with d4:
                    st.markdown(f"""
                    <div class="detail-label">Detection Window / Time</div>
                    <div class="detail-value">{selected_alert['time_formatted']} ({selected_alert['time_window']})</div>
                    """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="detail-box">
                    <div class="detail-label" style="color: #0f766e; margin-bottom: 4px;">Forensic Trigger Explanation:</div>
                    <div style="font-size: 13px; color: #1e293b; line-height: 1.5;">
                        <b>Potentially suspicious activity detected:</b> {selected_alert['reason']}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

                # Status Action Buttons (Persisted in SQLite)
                b_col1, b_col2, b_col3, _ = st.columns([1.2, 1.2, 1.4, 3])
                with b_col1:
                    if st.button("✓ Acknowledge", key="btn_ack"):
                        database.update_alert_status(selected_alert['alert_id'], STATUS_ACKNOWLEDGED)
                        st.success(f"Alert {selected_alert['alert_id']} marked as Acknowledged.")
                        st.rerun()
                with b_col2:
                    if st.button("✓ Resolve", key="btn_resolve"):
                        database.update_alert_status(selected_alert['alert_id'], STATUS_RESOLVED)
                        st.success(f"Alert {selected_alert['alert_id']} marked as Resolved.")
                        st.rerun()
                with b_col3:
                    if st.button("↺ Reset to Active", key="btn_reset_status"):
                        database.update_alert_status(selected_alert['alert_id'], STATUS_ACTIVE)
                        st.info(f"Alert {selected_alert['alert_id']} reset to Active.")
                        st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("No alerts match the selected search or filter criteria.")
            st.markdown("</div>", unsafe_allow_html=True)


# =============================================================
# PAGE 3: PACKET EXPLORER
# =============================================================
elif st.session_state["current_page"] == "Packet Explorer":
    status_label = "Scapy Parser: Active" if "PCAP" in st.session_state["explorer_mode"] else "Random Forest ML: Active"
    st.markdown(f"""
    <div class="page-header-container">
        <div>
            <h1 class="page-title">Packet Explorer</h1>
            <div class="page-subtitle">Inspect packet records, view metadata, and understand traffic composition</div>
        </div>
        <div class="status-pill">
            <span class="status-dot"></span>
            <span>{status_label}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    render_context_banner()

    # Input Mode Selector Bar
    st.markdown("""
    <div style="background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 18px 10px 18px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
        <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b; margin-bottom: 8px;">
            Analysis Input Mode Selection
        </div>
    """, unsafe_allow_html=True)

    mode_options = [
        "📦 PCAP Packet Analysis (Rule-Based Heuristics)",
        "🤖 CSV Dataset Analysis (Random Forest ML)"
    ]
    current_idx = 0 if "PCAP" in st.session_state["explorer_mode"] else 1
    selected_mode = st.radio(
        "Analysis Mode",
        mode_options,
        index=current_idx,
        horizontal=True,
        label_visibility="collapsed",
        key="packet_explorer_mode_choice"
    )
    st.markdown("</div>", unsafe_allow_html=True)

    if selected_mode != st.session_state["explorer_mode"]:
        st.session_state["explorer_mode"] = selected_mode
        st.rerun()

    # Render appropriate view based on selected mode
    if "PCAP" in st.session_state["explorer_mode"]:
        render_pcap_explorer()
    else:
        render_csv_explorer()
