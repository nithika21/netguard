"""
NetGuard Database Module
SQLite database for persistent alert history and incident records.
"""

import sqlite3
import os
from datetime import datetime
from backend.config import DB_PATH, STATUS_ACTIVE, STATUS_ACKNOWLEDGED, STATUS_RESOLVED


def get_connection():
    """Returns a SQLite connection with row factory configured."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes SQLite database and creates required tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS captures (
        filename TEXT PRIMARY KEY,
        file_size_bytes INTEGER,
        total_packets INTEGER,
        total_anomalies INTEGER,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        capture_filename TEXT NOT NULL,
        anomaly_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        dest_ip TEXT,
        dest_port INTEGER,
        timestamp REAL,
        time_formatted TEXT,
        time_window TEXT,
        severity TEXT NOT NULL,
        triggered_rule TEXT NOT NULL,
        reason TEXT NOT NULL,
        packet_count INTEGER DEFAULT 0,
        distinct_ports INTEGER DEFAULT 0,
        status TEXT DEFAULT 'Active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (capture_filename) REFERENCES captures (filename)
    )
    """)

    conn.commit()
    conn.close()


def record_capture(filename, file_size_bytes, total_packets, total_anomalies):
    """Records or updates capture file summary in captures table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO captures (filename, file_size_bytes, total_packets, total_anomalies, processed_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(filename) DO UPDATE SET
        file_size_bytes = excluded.file_size_bytes,
        total_packets = excluded.total_packets,
        total_anomalies = excluded.total_anomalies,
        processed_at = CURRENT_TIMESTAMP
    """, (filename, file_size_bytes, total_packets, total_anomalies))
    conn.commit()
    conn.close()


def save_alerts(alerts_list, capture_filename):
    """
    Saves newly detected alerts for a capture.
    If an alert with the same fingerprint already exists for this capture,
    its user-modified status (e.g. Acknowledged or Resolved) is preserved
    and no duplicate record is created.
    """
    if not alerts_list:
        return

    conn = get_connection()
    cursor = conn.cursor()

    for alert in alerts_list:
        # Check if an alert for this capture, rule, and host already exists
        cursor.execute("""
        SELECT alert_id, status FROM alerts
        WHERE capture_filename = ?
          AND anomaly_type = ?
          AND source_ip = ?
          AND (dest_ip IS ? OR dest_ip = ?)
          AND (dest_port IS ? OR dest_port = ?)
        LIMIT 1
        """, (
            capture_filename,
            alert.get("anomaly_type"),
            alert.get("source_ip"),
            alert.get("dest_ip"), alert.get("dest_ip"),
            alert.get("dest_port"), alert.get("dest_port")
        ))
        existing = cursor.fetchone()

        if existing:
            # Alert already recorded. Preserve status and assign persistent alert_id
            alert["alert_id"] = existing["alert_id"]
            alert["status"] = existing["status"]
        else:
            # Insert brand new alert
            cursor.execute("""
            INSERT INTO alerts (
                alert_id, capture_filename, anomaly_type, source_ip, dest_ip, dest_port,
                timestamp, time_formatted, time_window, severity, triggered_rule,
                reason, packet_count, distinct_ports, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                alert.get("alert_id"),
                capture_filename,
                alert.get("anomaly_type"),
                alert.get("source_ip"),
                alert.get("dest_ip"),
                alert.get("dest_port"),
                alert.get("timestamp"),
                alert.get("time_formatted"),
                alert.get("time_window"),
                alert.get("severity"),
                alert.get("triggered_rule"),
                alert.get("reason"),
                alert.get("packet_count", 0),
                alert.get("distinct_ports", 0),
                alert.get("status", STATUS_ACTIVE)
            ))

    conn.commit()
    conn.close()


def get_alerts(capture_filename=None, severity=None, anomaly_type=None, status=None, search=None):
    """Retrieves alerts with optional filtering and search."""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if capture_filename:
        query += " AND capture_filename = ?"
        params.append(capture_filename)

    if severity and severity != "All Severities" and severity != "All":
        query += " AND severity = ?"
        params.append(severity)

    if anomaly_type and anomaly_type != "All Types" and anomaly_type != "All":
        query += " AND anomaly_type = ?"
        params.append(anomaly_type)

    if status and status != "All Statuses" and status != "All":
        query += " AND status = ?"
        params.append(status)

    if search:
        search_term = f"%{search.strip()}%"
        query += """ AND (
            alert_id LIKE ? OR
            source_ip LIKE ? OR
            dest_ip LIKE ? OR
            anomaly_type LIKE ? OR
            reason LIKE ?
        )"""
        params.extend([search_term, search_term, search_term, search_term, search_term])

    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_alert_by_id(alert_id):
    """Retrieves a single alert by its ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_alert_status(alert_id, new_status):
    """Updates status of a specific alert (e.g. Active -> Acknowledged / Resolved)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE alerts
    SET status = ?, updated_at = CURRENT_TIMESTAMP
    WHERE alert_id = ?
    """, (new_status, alert_id))
    conn.commit()
    conn.close()


def get_alert_statistics(capture_filename=None):
    """Calculates summary statistics for alerts in a capture or globally."""
    conn = get_connection()
    cursor = conn.cursor()

    base_filter = "WHERE capture_filename = ?" if capture_filename else "WHERE 1=1"
    params = [capture_filename] if capture_filename else []

    cursor.execute(f"SELECT COUNT(*) FROM alerts {base_filter}", params)
    total_anomalies = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM alerts {base_filter} AND severity IN ('Critical', 'High')", params)
    high_critical_count = cursor.fetchone()[0]

    cursor.execute(f"""
    SELECT anomaly_type, COUNT(*) as cnt
    FROM alerts {base_filter}
    GROUP BY anomaly_type
    ORDER BY cnt DESC
    LIMIT 1
    """, params)
    top_type_row = cursor.fetchone()
    top_type = top_type_row[0] if top_type_row else "None"
    top_type_count = top_type_row[1] if top_type_row else 0

    cursor.execute(f"SELECT COUNT(*) FROM alerts {base_filter} AND status = 'Active'", params)
    active_count = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM alerts {base_filter} AND status = 'Acknowledged'", params)
    ack_count = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM alerts {base_filter} AND status = 'Resolved'", params)
    resolved_count = cursor.fetchone()[0]

    conn.close()
    return {
        "total_anomalies": total_anomalies,
        "high_critical_count": high_critical_count,
        "top_anomaly_type": top_type,
        "top_anomaly_count": top_type_count,
        "active_count": active_count,
        "ack_count": ack_count,
        "resolved_count": resolved_count
    }


def clear_all_for_capture(capture_filename):
    """Clears alerts for a capture if user chooses to reset."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts WHERE capture_filename = ?", (capture_filename,))
    cursor.execute("DELETE FROM captures WHERE filename = ?", (capture_filename,))
    conn.commit()
    conn.close()
