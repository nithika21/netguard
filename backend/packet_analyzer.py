"""
NetGuard Packet Analyzer Module
Scapy-based PCAP parsing, packet metadata extraction, and traffic statistical calculations.
"""

import os
import io
import time
import logging
from datetime import datetime
import pandas as pd

# Suppress Scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP

from backend.config import MAX_PACKETS_TO_PROCESS, MAX_UPLOAD_SIZE_MB


def format_bytes(size_bytes):
    """Formats byte counts into human-readable strings (B, KB, MB, GB)."""
    if size_bytes is None or size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def extract_tcp_flags_str(tcp_layer):
    """Returns human-readable representation of TCP control flags."""
    flags = tcp_layer.flags
    flag_list = []
    if flags.S:
        flag_list.append("SYN")
    if flags.A:
        flag_list.append("ACK")
    if flags.F:
        flag_list.append("FIN")
    if flags.R:
        flag_list.append("RST")
    if flags.P:
        flag_list.append("PSH")
    if flags.U:
        flag_list.append("URG")
    return ", ".join(flag_list) if flag_list else "None"


def parse_pcap_file(file_source, filename="capture.pcap", max_packets=MAX_PACKETS_TO_PROCESS):
    """
    Parses a PCAP/PCAPNG file or file-like buffer into a DataFrame of packet records.
    
    Returns:
        tuple: (df_packets, error_message)
    """
    try:
        packets = []
        
        # Check size if file_source is bytes or UploadedFile
        if hasattr(file_source, "size"):
            file_size_mb = file_source.size / (1024 * 1024)
            if file_size_mb > MAX_UPLOAD_SIZE_MB:
                return None, f"File size ({file_size_mb:.1f} MB) exceeds maximum allowed limit of {MAX_UPLOAD_SIZE_MB} MB."
            file_bytes = file_source.getvalue()
            pcap_stream = io.BytesIO(file_bytes)
            scapy_packets = rdpcap(pcap_stream)
        elif isinstance(file_source, (bytes, bytearray)):
            pcap_stream = io.BytesIO(file_source)
            scapy_packets = rdpcap(pcap_stream)
        elif isinstance(file_source, str) and os.path.exists(file_source):
            size_mb = os.path.getsize(file_source) / (1024 * 1024)
            if size_mb > MAX_UPLOAD_SIZE_MB:
                return None, f"File size ({size_mb:.1f} MB) exceeds maximum limit of {MAX_UPLOAD_SIZE_MB} MB."
            scapy_packets = rdpcap(file_source)
        else:
            return None, "Invalid file source provided."

        total_scapy = len(scapy_packets)
        if total_scapy == 0:
            return None, "The provided PCAP capture contains zero packets."

        # Process packets up to max_packets
        for idx, pkt in enumerate(scapy_packets[:max_packets]):
            pkt_len = len(pkt)
            pkt_time = float(pkt.time) if hasattr(pkt, "time") else time.time()
            dt = datetime.fromtimestamp(pkt_time)
            time_formatted = dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"

            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "Other"
            src_port = None
            dst_port = None
            tcp_flags = ""
            is_syn = False
            is_ack = False

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            elif ARP in pkt:
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                protocol = "ARP"

            if TCP in pkt:
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                tcp_flags = extract_tcp_flags_str(pkt[TCP])
                is_syn = bool(pkt[TCP].flags.S)
                is_ack = bool(pkt[TCP].flags.A)
            elif UDP in pkt:
                protocol = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                tcp_flags = "-"
            elif ICMP in pkt:
                protocol = "ICMP"
                src_port = None
                dst_port = None
                tcp_flags = f"Type {pkt[ICMP].type}"
            elif protocol == "Other":
                # Look at highest layer name
                layer = pkt.lastlayer().name
                protocol = layer if layer else "Other"

            packets.append({
                "packet_id": idx + 1,
                "timestamp": pkt_time,
                "time_formatted": time_formatted,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": pkt_len,
                "tcp_flags": tcp_flags,
                "is_syn": is_syn,
                "is_ack": is_ack,
                "anomaly_status": "Normal",
                "anomaly_type": None,
                "alert_id": None
            })

        df = pd.DataFrame(packets)
        return df, None

    except Exception as e:
        return None, f"Failed to parse PCAP file: {str(e)}"


def calculate_traffic_statistics(df):
    """
    Computes summary metrics, protocol breakdown, time-series distribution,
    and top source hosts from a packet DataFrame.
    """
    if df is None or df.empty:
        return {
            "total_packets": 0,
            "total_volume_bytes": 0,
            "total_volume_str": "0 B",
            "duration_seconds": 0.0,
            "protocol_counts": {},
            "protocol_percentages": {},
            "time_series": pd.DataFrame(),
            "top_sources": pd.DataFrame(),
            "top_destinations": pd.DataFrame(),
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "detected_protocols_count": 0
        }

    total_packets = len(df)
    total_volume_bytes = int(df["length"].sum())
    total_volume_str = format_bytes(total_volume_bytes)

    min_time = df["timestamp"].min()
    max_time = df["timestamp"].max()
    duration_seconds = max(0.001, max_time - min_time)

    # Protocol breakdown
    proto_series = df["protocol"].value_counts()
    protocol_counts = proto_series.to_dict()
    protocol_percentages = {
        proto: round((count / total_packets) * 100, 1)
        for proto, count in protocol_counts.items()
    }

    # Grouping protocols into standard 4 buckets (TCP, UDP, ICMP, Other) for the donut chart
    standard_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    for p, count in protocol_counts.items():
        if p in ["TCP", "UDP", "ICMP"]:
            standard_counts[p] += count
        else:
            standard_counts["Other"] += count

    standard_percentages = {
        p: round((count / total_packets) * 100, 1)
        for p, count in standard_counts.items()
    }

    # Time series (traffic over time)
    # Bin dynamically: 1s bins if duration <= 60s, else 2s or 5s
    bin_size = 1.0 if duration_seconds <= 60 else (2.0 if duration_seconds <= 300 else 5.0)
    df_temp = df.copy()
    # Normalize timestamp to start from 0 for relative timeline or use HH:MM:SS
    df_temp["bin"] = ((df_temp["timestamp"] - min_time) // bin_size) * bin_size
    time_series = df_temp.groupby("bin").agg(
        packet_count=("packet_id", "count"),
        byte_count=("length", "sum")
    ).reset_index()
    time_series["time_label"] = time_series["bin"].apply(
        lambda b: f"{int(b//60):02d}:{int(b%60):02d}s"
    )

    # Top source IP addresses (excluding non-IP N/A)
    ip_df = df[df["src_ip"] != "N/A"]
    if not ip_df.empty:
        top_src_series = ip_df["src_ip"].value_counts().head(5)
        top_sources = pd.DataFrame({
            "src_ip": top_src_series.index,
            "packet_count": top_src_series.values,
            "percentage": [(c / total_packets) * 100 for c in top_src_series.values]
        })
    else:
        top_sources = pd.DataFrame(columns=["src_ip", "packet_count", "percentage"])

    # Top destinations
    dst_ip_df = df[df["dst_ip"] != "N/A"]
    if not dst_ip_df.empty:
        top_dst_series = dst_ip_df["dst_ip"].value_counts().head(5)
        top_destinations = pd.DataFrame({
            "dst_ip": top_dst_series.index,
            "packet_count": top_dst_series.values
        })
    else:
        top_destinations = pd.DataFrame(columns=["dst_ip", "packet_count"])

    unique_src_ips = int(ip_df["src_ip"].nunique()) if not ip_df.empty else 0
    unique_dst_ips = int(dst_ip_df["dst_ip"].nunique()) if not dst_ip_df.empty else 0
    detected_protocols_count = int(df["protocol"].nunique())

    return {
        "total_packets": total_packets,
        "total_volume_bytes": total_volume_bytes,
        "total_volume_str": total_volume_str,
        "duration_seconds": duration_seconds,
        "protocol_counts": standard_counts,
        "protocol_percentages": standard_percentages,
        "raw_protocol_counts": protocol_counts,
        "time_series": time_series,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "unique_src_ips": unique_src_ips,
        "unique_dst_ips": unique_dst_ips,
        "detected_protocols_count": detected_protocols_count,
        "bin_size": bin_size
    }
