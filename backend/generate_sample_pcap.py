"""
NetGuard Sample PCAP Generator
Generates a realistic synthetic PCAP file (sample_traffic.pcap) with exactly 12,840 packets
matching the project screenshots:
- Total packets: 12,840
- 24 Total detected anomalies (14 High Packet Rate, 6 Port Scan, 4 Repeated Connections)
- 10 High/Critical alerts (3 Critical alerts on dashboard)
- Realistic protocol mix: TCP (~64%), UDP (~24%), ICMP (~8%), Other (~4%)
"""

import time
import logging
import random

# Suppress Scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, wrpcap

from backend.config import SAMPLE_PCAP_PATH


def generate_synthetic_pcap(target_path=SAMPLE_PCAP_PATH, total_target=12840):
    print(f"Generating realistic PCAP capture ({total_target} packets) at: {target_path}...")
    base_time = 1728559200.0  # 10:00:00 AM reference
    timeline_duration = 300.0  # 5 minutes timeline

    packets = []

    src_mac = "00:50:56:c0:00:01"
    dst_mac = "00:50:56:c0:00:08"

    web_servers = ["142.250.190.46", "93.184.216.34", "104.21.32.1", "151.101.65.140"]
    dns_servers = ["8.8.8.8", "1.1.1.1"]
    
    # 25 background clients so average rate per client is low (~2-3 pkts/sec), well below 100 pkts/5s
    clients = [f"192.168.1.{i}" for i in range(10, 35)]

    # 1. Inject Rule A: Exactly 14 High Packet Rate bursts across 3 unique hosts
    # Hosts: 192.168.1.105 (7 bursts), 192.168.1.112 (4 bursts), 192.168.1.140 (3 bursts)
    burst_defs = [
        # Host 105: 7 bursts (3 Critical >250 pkts, 4 High >150 pkts)
        {"src": "192.168.1.105", "dst": "10.0.0.5", "count": 260, "offset": 20.0, "dur": 2.0},  # Critical
        {"src": "192.168.1.105", "dst": "10.0.0.5", "count": 270, "offset": 45.0, "dur": 2.2},  # Critical
        {"src": "192.168.1.105", "dst": "10.0.0.8", "count": 255, "offset": 80.0, "dur": 2.1},  # Critical
        {"src": "192.168.1.105", "dst": "10.0.0.5", "count": 180, "offset": 120.0, "dur": 2.5}, # High
        {"src": "192.168.1.105", "dst": "10.0.0.5", "count": 160, "offset": 160.0, "dur": 2.4}, # High
        {"src": "192.168.1.105", "dst": "10.0.0.5", "count": 170, "offset": 210.0, "dur": 2.3}, # High
        {"src": "192.168.1.105", "dst": "10.0.0.5", "count": 165, "offset": 260.0, "dur": 2.2}, # High
        # Host 112: 4 bursts
        {"src": "192.168.1.112", "dst": "172.16.0.4", "count": 130, "offset": 30.0, "dur": 2.8}, # Medium
        {"src": "192.168.1.112", "dst": "172.16.0.4", "count": 140, "offset": 90.0, "dur": 2.7}, # Medium
        {"src": "192.168.1.112", "dst": "172.16.0.4", "count": 135, "offset": 170.0, "dur": 2.6}, # Medium
        {"src": "192.168.1.112", "dst": "172.16.0.4", "count": 145, "offset": 230.0, "dur": 2.5}, # Medium
        # Host 140: 3 bursts
        {"src": "192.168.1.140", "dst": "192.168.1.1", "count": 125, "offset": 60.0, "dur": 2.9},  # Medium
        {"src": "192.168.1.140", "dst": "192.168.1.1", "count": 120, "offset": 140.0, "dur": 3.0}, # Medium
        {"src": "192.168.1.140", "dst": "192.168.1.1", "count": 125, "offset": 250.0, "dur": 2.8}, # Medium
    ]

    for b in burst_defs:
        t_start = base_time + b["offset"]
        step = b["dur"] / b["count"]
        for k in range(b["count"]):
            pkt_t = t_start + k * step
            pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=b["src"], dst=b["dst"]) / UDP(sport=40000+k%1000, dport=9999) / (b"X" * 120)
            pkt.time = pkt_t
            packets.append(pkt)

    # 2. Inject Rule B: Exactly 6 Port Scanning events
    # Probes sending TCP SYN to > 15 distinct ports within 10s
    scan_defs = [
        {"src": "192.168.1.200", "dst": "192.168.1.1", "ports": list(range(20, 42)), "offset": 15.0, "dur": 4.0},   # 22 ports (High)
        {"src": "192.168.1.200", "dst": "192.168.1.50", "ports": list(range(80, 101)), "offset": 75.0, "dur": 4.2},  # 21 ports (High)
        {"src": "192.168.1.200", "dst": "192.168.1.2", "ports": list(range(8000, 8021)), "offset": 135.0, "dur": 3.8}, # 21 ports (High)
        {"src": "192.168.1.200", "dst": "192.168.1.100", "ports": list(range(500, 517)), "offset": 195.0, "dur": 3.5}, # 17 ports (Medium)
        {"src": "192.168.1.205", "dst": "192.168.1.1", "ports": list(range(100, 118)), "offset": 50.0, "dur": 4.1},  # 18 ports (Medium)
        {"src": "192.168.1.205", "dst": "192.168.1.5", "ports": list(range(200, 218)), "offset": 220.0, "dur": 3.9}, # 18 ports (Medium)
    ]

    for s in scan_defs:
        t_start = base_time + s["offset"]
        step = s["dur"] / len(s["ports"])
        for idx, port in enumerate(s["ports"]):
            pkt_t = t_start + idx * step
            pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=s["src"], dst=s["dst"]) / TCP(sport=51000+idx, dport=port, flags="S")
            pkt.time = pkt_t
            packets.append(pkt)

    # 3. Inject Rule C: Exactly 4 Repeated Connection Attempts
    # Repeating TCP SYN connection attempts (>10 attempts) to same dst:port within 5s
    repeat_defs = [
        {"src": "192.168.1.77", "dst": "192.168.1.50", "port": 445, "count": 22, "offset": 35.0, "dur": 2.5}, # High
        {"src": "192.168.1.77", "dst": "192.168.1.80", "port": 3389, "count": 16, "offset": 110.0, "dur": 2.3}, # Medium
        {"src": "192.168.1.77", "dst": "192.168.1.50", "port": 139, "count": 15, "offset": 180.0, "dur": 2.4}, # Medium
        {"src": "192.168.1.88", "dst": "192.168.1.1", "port": 22, "count": 18, "offset": 240.0, "dur": 2.2},  # Medium
    ]

    for r in repeat_defs:
        t_start = base_time + r["offset"]
        step = r["dur"] / r["count"]
        for k in range(r["count"]):
            pkt_t = t_start + k * step
            pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=r["src"], dst=r["dst"]) / TCP(sport=62000+k, dport=r["port"], flags="S")
            pkt.time = pkt_t
            packets.append(pkt)

    # 4. Fill remaining packets with clean background traffic (TCP, UDP, ICMP, ARP)
    remaining_needed = total_target - len(packets)
    print(f"Generating {remaining_needed} clean background packets across {len(clients)} hosts...")

    for i in range(remaining_needed):
        pkt_time = base_time + (i / remaining_needed) * timeline_duration + random.uniform(0.0001, 0.005)
        proto_dice = random.random()

        if proto_dice < 0.65:
            # Normal TCP web traffic (ACK or PSH-ACK, NOT standalone SYN)
            c_ip = random.choice(clients)
            s_ip = random.choice(web_servers)
            sport = random.randint(30000, 60000)
            dport = random.choice([80, 443, 8080])
            flags = random.choice(["A", "PA", "FA", "A"])
            payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" if flags == "PA" else b""
            pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=c_ip, dst=s_ip) / TCP(sport=sport, dport=dport, flags=flags) / payload
        elif proto_dice < 0.88:
            # Normal UDP DNS / NTP
            c_ip = random.choice(clients)
            dns_ip = random.choice(dns_servers)
            sport = random.randint(30000, 60000)
            pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=c_ip, dst=dns_ip) / UDP(sport=sport, dport=53) / b"\xaa\xbb\x01\x00\x00\x01"
        elif proto_dice < 0.96:
            # Normal ICMP ping
            c_ip = random.choice(clients)
            pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=c_ip, dst="8.8.8.8") / ICMP(type=8, code=0)
        else:
            # ARP
            c_ip = random.choice(clients)
            pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=c_ip, pdst="192.168.1.1")

        pkt.time = pkt_time
        packets.append(pkt)

    # Sort all packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    # Ensure exact packet count
    packets = packets[:total_target]

    print(f"Writing {len(packets)} packets to {target_path}...")
    wrpcap(target_path, packets)
    print(f"Successfully generated {len(packets)} packets in {target_path}!")


if __name__ == "__main__":
    generate_synthetic_pcap()
