"""
AI-NIDS Synthetic Lab Traffic Generator & PCAP Builder
Chinhoyi University of Technology - Group 5

Generates localized, non-destructive network traffic samples using Scapy:
1. Port Scan: Horizontal SYN probe across 20 distinct ports
2. DoS: High-rate single-source TCP SYN flood
3. DDoS: Multi-source distributed coordinated flood
4. Brute Force: Repeated short connection probes to port 22 (SSH) and 21 (FTP)
5. Baseline Benign: Normal HTTP/HTTPS web traffic flows

Can write directly to sample .pcap files or transmit safely on private loopback (127.0.0.1).
LEGAL: Restricted strictly to localhost and isolated educational laboratories.
"""

import os
import sys
import time
import argparse
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, Raw, wrpcap, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def generate_port_scan_packets(target_ip="192.168.1.1", source_ip="192.168.1.25", ports=range(20, 45)):
    packets = []
    base_time = time.time()
    for idx, port in enumerate(ports):
        pkt = IP(src=source_ip, dst=target_ip) / TCP(sport=50000 + idx, dport=port, flags="S")
        pkt.time = base_time + (idx * 0.05)
        packets.append(pkt)
    return packets


def generate_dos_packets(target_ip="192.168.1.10", source_ip="192.168.1.30", count=250):
    packets = []
    base_time = time.time()
    for i in range(count):
        pkt = IP(src=source_ip, dst=target_ip) / TCP(sport=40000 + (i % 5000), dport=80, flags="S")
        pkt.time = base_time + (i * 0.005)  # 200 pkts/second rate
        packets.append(pkt)
    return packets


def generate_ddos_packets(target_ip="192.168.1.1", num_sources=8, count_per_source=40):
    packets = []
    base_time = time.time()
    for s_idx in range(num_sources):
        src_ip = f"192.168.1.{150 + s_idx}"
        for i in range(count_per_source):
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=30000 + i, dport=80, flags="S")
            pkt.time = base_time + (i * 0.01) + (s_idx * 0.002)
            packets.append(pkt)
    return packets


def generate_brute_force_packets(target_ip="192.168.1.20", source_ip="192.168.1.40", auth_port=22, attempts=15):
    packets = []
    base_time = time.time()
    for i in range(attempts):
        sport = 55000 + i
        t0 = base_time + (i * 0.8)
        # SYN
        p1 = IP(src=source_ip, dst=target_ip) / TCP(sport=sport, dport=auth_port, flags="S")
        p1.time = t0
        # SYN-ACK
        p2 = IP(src=target_ip, dst=source_ip) / TCP(sport=auth_port, dport=sport, flags="SA")
        p2.time = t0 + 0.02
        # ACK
        p3 = IP(src=source_ip, dst=target_ip) / TCP(sport=sport, dport=auth_port, flags="A")
        p3.time = t0 + 0.03
        # Quick RST Teardown
        p4 = IP(src=source_ip, dst=target_ip) / TCP(sport=sport, dport=auth_port, flags="R")
        p4.time = t0 + 0.15

        packets.extend([p1, p2, p3, p4])
    return packets


def generate_benign_packets(client_ip="192.168.1.105", server_ip="192.168.1.1", count=40):
    packets = []
    base_time = time.time()
    sport = 49152
    dport = 443
    # 3-way handshake
    p1 = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="S")
    p1.time = base_time
    p2 = IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="SA")
    p2.time = base_time + 0.02
    p3 = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="A")
    p3.time = base_time + 0.03
    packets.extend([p1, p2, p3])

    # Data packets
    for i in range(count):
        data_p = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=b"X" * 250)
        data_p.time = base_time + 0.05 + (i * 0.05)
        ack_p = IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="A")
        ack_p.time = data_p.time + 0.01
        packets.extend([data_p, ack_p])

    return packets


def build_synthetic_lab_pcap():
    if not HAS_SCAPY:
        print("[!] Scapy is required to generate synthetic test pcaps.")
        return

    print("[*] Generating synthetic test pcap with 5 canonical attack profiles...")
    all_packets = []

    # 1. Normal benign baseline
    all_packets.extend(generate_benign_packets())

    # 2. Port Scan
    all_packets.extend(generate_port_scan_packets())

    # 3. DoS Flood
    all_packets.extend(generate_dos_packets())

    # 4. DDoS Distributed Flood
    all_packets.extend(generate_ddos_packets())

    # 5. SSH Brute Force attempts
    all_packets.extend(generate_brute_force_packets())

    # Sort packets chronologically
    all_packets.sort(key=lambda p: float(p.time))

    out_file = os.path.join(OUTPUT_DIR, "cut_lab_test_traffic.pcap")
    wrpcap(out_file, all_packets)

    print(f"[+] Successfully generated synthetic test capture file ({len(all_packets)} packets):")
    print(f"    -> {out_file}")
    print("[+] You can upload this file directly on the Live Monitor page to test Wireshark ingestion!")


if __name__ == "__main__":
    build_synthetic_lab_pcap()
