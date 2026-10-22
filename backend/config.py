"""
NetGuard Configuration Module
Configurable thresholds, limits, and styling constants for Network Traffic Analysis.
"""

import os

# Base paths
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = PROJECT_DIR
DATA_DIR = os.path.join(PROJECT_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "netguard.db")
SAMPLE_PCAP_PATH = os.path.join(DATA_DIR, "sample_traffic.pcap")
ML_MODEL_PATH = os.path.join(DATA_DIR, "rf_model.joblib")
DATASET_CSV_PATH = os.path.join(DATA_DIR, "cicids2017_sample.csv")
SAMPLE_CSV_PATH = os.path.join(DATA_DIR, "sample_traffic_test.csv")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# -------------------------------------------------------------
# Anomaly Detection Thresholds (Configurable Heuristics)
# -------------------------------------------------------------

# Rule A: High Packet Rate
# Flags a source IP that sends more than threshold packets within window
HIGH_PACKET_RATE_THRESHOLD = 100       # packets
HIGH_PACKET_RATE_WINDOW_SECONDS = 5.0  # seconds

# Rule B: Possible Port Scanning
# Flags a source IP sending TCP SYN packets to > threshold distinct destination ports within window
PORT_SCAN_PORT_THRESHOLD = 15         # distinct destination ports
PORT_SCAN_WINDOW_SECONDS = 10.0       # seconds

# Rule C: Repeated Connection Attempts
# Flags repeated TCP SYN connection attempts to the same destination IP:port within window
REPEATED_CONN_THRESHOLD = 10          # attempts to same IP:port
REPEATED_CONN_WINDOW_SECONDS = 5.0    # seconds

# -------------------------------------------------------------
# File Processing & Safety Limits
# -------------------------------------------------------------
MAX_UPLOAD_SIZE_MB = 50               # Maximum uploaded PCAP file size
MAX_PACKETS_TO_PROCESS = 35000        # Safeguard against out-of-memory on large PCAPs
DEFAULT_PAGE_SIZE = 50                # Table pagination size for packet explorer
DEFAULT_CSV_PAGE_SIZE = 50            # Table pagination size for CSV ML explorer

# -------------------------------------------------------------
# Severity Levels and Status Definitions
# -------------------------------------------------------------
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

STATUS_ACTIVE = "Active"
STATUS_ACKNOWLEDGED = "Acknowledged"
STATUS_RESOLVED = "Resolved"
