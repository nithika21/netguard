"""
NetGuard Anomaly Detection Engine
Implements three rule-based heuristic anomaly detection rules:
1. High packet rate
2. Possible port scanning
3. Repeated connection attempts
"""

from datetime import datetime
import numpy as np
import pandas as pd

from backend.config import (
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
    STATUS_ACTIVE
)


def detect_high_packet_rate(df, threshold=HIGH_PACKET_RATE_THRESHOLD, window_seconds=HIGH_PACKET_RATE_WINDOW_SECONDS):
    """
    Rule A: High packet rate
    Identifies source IP addresses that send more than `threshold` packets
    within a sliding time window of `window_seconds`.
    """
    alerts = []
    flagged_indices = set()

    ip_df = df[df["src_ip"] != "N/A"]
    if ip_df.empty:
        return alerts, flagged_indices

    # Group by source IP
    for src_ip, group in ip_df.groupby("src_ip"):
        if len(group) <= threshold:
            continue

        timestamps = group["timestamp"].values
        indices = group.index.values

        i = 0
        n = len(timestamps)
        processed_until = 0

        while i < n:
            t_start = timestamps[i]
            t_end_limit = t_start + window_seconds
            
            # Find all packets within window [t_start, t_end_limit]
            j = np.searchsorted(timestamps, t_end_limit, side="right")
            count = j - i

            if count > threshold and j > processed_until:
                window_indices = indices[i:j]
                flagged_indices.update(window_indices)

                burst_duration = max(0.001, timestamps[j - 1] - t_start)
                rate = count / burst_duration

                if count >= threshold * 2.5:
                    severity = SEVERITY_CRITICAL
                elif count >= threshold * 1.5:
                    severity = SEVERITY_HIGH
                else:
                    severity = SEVERITY_MEDIUM

                dt = datetime.fromtimestamp(t_start)
                time_formatted = dt.strftime("%H:%M:%S")

                reason = (
                    f"Host sent {count} packets within {burst_duration:.2f}s "
                    f"(rate: {rate:.1f} pkts/s), exceeding heuristic threshold of "
                    f"{threshold} packets per {window_seconds:.0f}s window. "
                    f"Potentially suspicious burst or automated traffic."
                )

                alerts.append({
                    "anomaly_type": "High Packet Rate",
                    "source_ip": src_ip,
                    "dest_ip": "Multiple / Broadcast" if group.loc[window_indices, "dst_ip"].nunique() > 1 else group.loc[window_indices, "dst_ip"].iloc[0],
                    "dest_port": None,
                    "timestamp": float(t_start),
                    "time_formatted": time_formatted,
                    "time_window": f"{burst_duration:.2f}s window",
                    "severity": severity,
                    "triggered_rule": "Rule A: High Packet Rate",
                    "reason": reason,
                    "packet_count": int(count),
                    "distinct_ports": 0,
                    "status": STATUS_ACTIVE,
                    "flagged_indices": list(window_indices)
                })

                processed_until = j
                i = j  # Move past this burst to avoid duplicate alerts for same event
            else:
                i += 1

    return alerts, flagged_indices


def detect_possible_port_scanning(df, port_threshold=PORT_SCAN_PORT_THRESHOLD, window_seconds=PORT_SCAN_WINDOW_SECONDS):
    """
    Rule B: Possible port scanning
    Identifies potential port-scanning behavior when a source IP sends TCP
    connection-initiation packets (SYN packets without ACK) to > `port_threshold`
    distinct destination ports within `window_seconds`.
    """
    alerts = []
    flagged_indices = set()

    # Filter for TCP SYN connection-initiation packets (is_syn=True, is_ack=False)
    syn_df = df[(df["protocol"] == "TCP") & (df["is_syn"] == True) & (df["is_ack"] == False) & (df["src_ip"] != "N/A")]
    if syn_df.empty:
        return alerts, flagged_indices

    for src_ip, group in syn_df.groupby("src_ip"):
        if group["dst_port"].nunique() <= port_threshold:
            continue

        timestamps = group["timestamp"].values
        ports = group["dst_port"].values
        dst_ips = group["dst_ip"].values
        indices = group.index.values

        i = 0
        n = len(timestamps)
        processed_until = 0

        while i < n:
            t_start = timestamps[i]
            t_end_limit = t_start + window_seconds
            j = np.searchsorted(timestamps, t_end_limit, side="right")

            window_ports = set(ports[i:j])
            distinct_count = len(window_ports)

            if distinct_count > port_threshold and j > processed_until:
                window_indices = indices[i:j]
                flagged_indices.update(window_indices)

                scan_duration = max(0.001, timestamps[j - 1] - t_start)
                unique_dst_ips = list(set(dst_ips[i:j]))
                dst_summary = unique_dst_ips[0] if len(unique_dst_ips) == 1 else f"{len(unique_dst_ips)} target hosts"

                if distinct_count >= 30:
                    severity = SEVERITY_CRITICAL
                elif distinct_count >= 20:
                    severity = SEVERITY_HIGH
                else:
                    severity = SEVERITY_MEDIUM

                dt = datetime.fromtimestamp(t_start)
                time_formatted = dt.strftime("%H:%M:%S")

                reason = (
                    f"Host initiated TCP SYN connection requests to {distinct_count} distinct "
                    f"destination ports targeting {dst_summary} within {scan_duration:.2f}s. "
                    f"Exceeds heuristic threshold of {port_threshold} distinct ports per "
                    f"{window_seconds:.0f}s window. Potentially suspicious port reconnaissance."
                )

                alerts.append({
                    "anomaly_type": "Possible Port Scanning",
                    "source_ip": src_ip,
                    "dest_ip": unique_dst_ips[0] if len(unique_dst_ips) == 1 else "Multiple Targets",
                    "dest_port": None,
                    "timestamp": float(t_start),
                    "time_formatted": time_formatted,
                    "time_window": f"{scan_duration:.2f}s window",
                    "severity": severity,
                    "triggered_rule": "Rule B: Possible Port Scanning",
                    "reason": reason,
                    "packet_count": int(j - i),
                    "distinct_ports": int(distinct_count),
                    "status": STATUS_ACTIVE,
                    "flagged_indices": list(window_indices)
                })

                processed_until = j
                i = j
            else:
                i += 1

    return alerts, flagged_indices


def detect_repeated_connections(df, threshold=REPEATED_CONN_THRESHOLD, window_seconds=REPEATED_CONN_WINDOW_SECONDS):
    """
    Rule C: Repeated connection attempts
    Identifies repeated TCP connection-initiation attempts (SYN without ACK)
    from the same source IP to the same destination IP and destination port
    within `window_seconds`. Avoids counting packets in established connections.
    """
    alerts = []
    flagged_indices = set()

    # Only inspect connection initiation packets (SYN without ACK)
    syn_df = df[
        (df["protocol"] == "TCP") & 
        (df["is_syn"] == True) & 
        (df["is_ack"] == False) & 
        (df["src_ip"] != "N/A") & 
        (df["dst_ip"] != "N/A") & 
        (df["dst_port"].notnull())
    ]
    if syn_df.empty:
        return alerts, flagged_indices

    # Group by (source IP, destination IP, destination port)
    for (src_ip, dst_ip, dst_port), group in syn_df.groupby(["src_ip", "dst_ip", "dst_port"]):
        if len(group) <= threshold:
            continue

        timestamps = group["timestamp"].values
        indices = group.index.values

        i = 0
        n = len(timestamps)
        processed_until = 0

        while i < n:
            t_start = timestamps[i]
            t_end_limit = t_start + window_seconds
            j = np.searchsorted(timestamps, t_end_limit, side="right")
            count = j - i

            if count > threshold and j > processed_until:
                window_indices = indices[i:j]
                flagged_indices.update(window_indices)

                duration = max(0.001, timestamps[j - 1] - t_start)
                if count >= 25:
                    severity = SEVERITY_HIGH
                else:
                    severity = SEVERITY_MEDIUM

                dt = datetime.fromtimestamp(t_start)
                time_formatted = dt.strftime("%H:%M:%S")

                reason = (
                    f"Host initiated {count} repeated TCP SYN connection attempts to "
                    f"{dst_ip}:{int(dst_port)} within {duration:.2f}s without an established session. "
                    f"Exceeds threshold of {threshold} connection attempts per {window_seconds:.0f}s window. "
                    f"Potentially suspicious connection flood or failed retry cycle."
                )

                alerts.append({
                    "anomaly_type": "Repeated Connection Attempts",
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "dest_port": int(dst_port),
                    "timestamp": float(t_start),
                    "time_formatted": time_formatted,
                    "time_window": f"{duration:.2f}s window",
                    "severity": severity,
                    "triggered_rule": "Rule C: Repeated Connection Attempts",
                    "reason": reason,
                    "packet_count": int(count),
                    "distinct_ports": 1,
                    "status": STATUS_ACTIVE,
                    "flagged_indices": list(window_indices)
                })

                processed_until = j
                i = j
            else:
                i += 1

    return alerts, flagged_indices


def run_anomaly_detection(df):
    """
    Executes all three detection rules on the packet DataFrame.
    Assigns sequential alert IDs (ALT-001, ALT-002, etc.), marks packet rows
    with their anomaly status, and returns a tuple (df, alerts_list).
    """
    if df is None or df.empty:
        return df, []

    df_copy = df.copy()

    # Run rules
    alerts_a, indices_a = detect_high_packet_rate(df_copy)
    alerts_b, indices_b = detect_possible_port_scanning(df_copy)
    alerts_c, indices_c = detect_repeated_connections(df_copy)

    all_alerts = alerts_a + alerts_b + alerts_c

    # Sort alerts chronologically
    all_alerts.sort(key=lambda x: x["timestamp"])

    # Assign IDs and map to packet dataframe
    for idx, alert in enumerate(all_alerts, start=1):
        alert_id = f"ALT-{idx:03d}"
        alert["alert_id"] = alert_id

        # Mark corresponding packets in df
        flagged_idx_list = alert.get("flagged_indices", [])
        if flagged_idx_list:
            for p_idx in flagged_idx_list:
                df_copy.at[p_idx, "anomaly_status"] = "Flagged"
                df_copy.at[p_idx, "anomaly_type"] = alert["anomaly_type"]
                df_copy.at[p_idx, "alert_id"] = alert_id

    return df_copy, all_alerts
