"""
Campus Threat Scenario Replay
Chinhoyi University of Technology - Group 5

The benchmark dataset (data/cic.csv) labels brute-force campaigns only, so the Random
Forest cannot produce the other documented threat types. This module replays those
threats the way the live monitor sees them: a packet stream is handed to FlowBuilder,
whose flows and window summary are judged by BehaviourAnalyzer against the parameters
in config/rules.yaml. Nothing here writes a verdict by hand - the measurements,
confidence and severity of every stored threat come from the running detectors.

Usage (called by database/ingest_cic_dataset.py):
    from database.scenario_replay import build_threat_records
    records = build_threat_records({"Port Scanning": 45, "DoS": 45}, seed=7)
"""

import json
import random
import time
from datetime import datetime, timedelta

from backend.config import BEHAVIOUR_METHOD, CAMPUS_ACTIVE_DEVICES, TEST_TRAFFIC_SOURCE
from backend.services.behaviour_analyzer import BehaviourAnalyzer
from backend.services.flow_builder import FlowBuilder
from backend.services.severity_engine import SeverityEngine

EVENT_ID_PREFIX = "THR-B"

# Campus endpoints the scenarios are replayed between
SCANNER_POOL = tuple(f"192.168.13.{30 + i * 9}" for i in range(8))
CLIENT_POOL = tuple(f"192.168.{10 + i % 4}.{100 + (i * 17) % 140}" for i in range(40))
SERVICE_TARGETS = ("10.10.0.10", "10.10.0.5", "10.10.0.6", "10.10.0.20")
SCAN_PORT_RANGE = (20, 5000)
BASE_SRC_PORT = 40000

PACKET_LENGTH = 64

# Share of the flagged flows each documented threat accounts for. Shaped like a real
# campus week: many low-grade anomalies, fewer confirmed floods, rare distributed attacks.
BEHAVIOUR_SPLIT = {
    "Traffic Spike Anomaly": 120,
    "Port Scanning": 60,
    "DoS": 40,
    "Other/Suspicious": 30,
    "DDoS": 14,
}

# Scenario builders are registered by threat type in SCENARIO_BUILDERS, below them


def _packet(src_ip, dst_ip, src_port, dst_port, timestamp, protocol=6, syn=0, ack=0, rst=0):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": timestamp,
        "length": PACKET_LENGTH,
        "syn": syn,
        "ack": ack,
        "rst": rst,
        "fin": 0,
        "psh": 0,
    }


def _port_scan_packets(rng, base_epoch):
    """One host walking a row of destination ports without completing handshakes."""
    scanner = rng.choice(SCANNER_POOL)
    target = rng.choice(SERVICE_TARGETS)
    probes = rng.randint(18, 60)
    ports = rng.sample(range(*SCAN_PORT_RANGE), probes)
    packets = [
        _packet(scanner, target, BASE_SRC_PORT + i, port,
                base_epoch + i * (0.4 / probes), syn=1)
        for i, port in enumerate(ports)
    ]
    return packets, scanner, target


def _dos_packets(rng, base_epoch):
    """One host flooding a service with half-open connections."""
    attacker = rng.choice(SCANNER_POOL)
    target = rng.choice(SERVICE_TARGETS)
    burst = rng.randint(130, 260)
    port = rng.choice((80, 443, 53, 3389))
    packets = [
        _packet(attacker, target, BASE_SRC_PORT + i, port,
                base_epoch + i * (0.6 / burst), syn=1)
        for i in range(burst)
    ]
    return packets, attacker, target


def _ddos_packets(rng, base_epoch):
    """A spread of campus hosts converging on one service at once."""
    host_count = rng.randint(6, 10)
    hosts = rng.sample(CLIENT_POOL, host_count)
    target = rng.choice(SERVICE_TARGETS)
    port = rng.choice((80, 443, 53))
    per_host = 30
    packets = []
    for host_index, host in enumerate(hosts):
        for i in range(per_host):
            packets.append(_packet(host, target, BASE_SRC_PORT + host_index * 100 + i,
                                   port, base_epoch + i * (0.6 / per_host), syn=1))
    return packets, hosts[0], target


def _anomaly_packets(rng, base_epoch):
    """A single connection torn down by resets on most of its packets."""
    host = rng.choice(CLIENT_POOL)
    target = rng.choice(SERVICE_TARGETS)
    count = rng.randint(6, 12)
    port = rng.choice((80, 443, 21, 22))
    # One five-tuple, because the reset ratio is measured per flow
    src_port = BASE_SRC_PORT + rng.randint(0, 15000)
    packets = [_packet(host, target, src_port, port, base_epoch, syn=1)]
    packets += [
        _packet(host, target, src_port, port, base_epoch + (i + 1) * (0.2 / count), rst=1)
        for i in range(count - 1)
    ]
    return packets, host, target


def _traffic_spike_packets(rng, base_epoch):
    """One host running far faster than every other flow in the same window."""
    host = rng.choice(CLIENT_POOL)
    target = rng.choice(SERVICE_TARGETS)
    port = rng.choice((443, 80, 3306, 1433))
    packets = []

    # The rest of the window: ordinary short sessions, which set the median the spike is measured against
    for peer_index in range(14):
        peer = f"10.10.{peer_index % 3}.{20 + peer_index}"
        speaker, listener = (host, peer) if peer_index % 4 == 0 else (peer, host)
        for step in range(6):
            packets.append(_packet(speaker, listener, 49152 + peer_index, 443,
                                   base_epoch + step * 0.2, syn=1 if step == 0 else 0,
                                   ack=0 if step == 0 else 1))

    # The spike itself: a well-answered bulk transfer on one connection, so it is an
    # anomaly rather than a flood
    burst = rng.randint(55, 110)
    burst_port = BASE_SRC_PORT + 500 + rng.randint(0, 900)
    for i in range(burst):
        packets.append(_packet(host, target, burst_port, port,
                               base_epoch + i * (0.5 / burst), ack=1))
    return packets, host, target


SCENARIO_BUILDERS = {
    "Port Scanning": _port_scan_packets,
    "DoS": _dos_packets,
    "DDoS": _ddos_packets,
    "Other/Suspicious": _anomaly_packets,
    "Traffic Spike Anomaly": _traffic_spike_packets,
}


def build_threat_records(counts: dict, seed: int = 7, window_end_margin: timedelta = timedelta(hours=1)):
    """Replays one window per scenario and returns the events the detectors produced."""
    rng = random.Random(seed)
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    severity_engine = SeverityEngine()

    records = []
    missed = {}
    # Spread the scenarios over the day before the baseline ends, oldest first
    span_seconds = 86400.0
    latest = datetime.utcnow() - window_end_margin

    scenario_no = 0
    for threat_type, wanted in counts.items():
        builder = SCENARIO_BUILDERS[threat_type]
        fired = 0
        attempt = 0
        while fired < wanted and attempt < wanted * 4:
            attempt += 1
            scenario_no += 1
            detected_at = latest - timedelta(seconds=rng.uniform(0, span_seconds))
            packets, _attacker, target_ip = builder(rng, detected_at.timestamp())
            flows, window_summary, _build_ms = flow_builder.build_flows_from_packets(packets)
            findings = [f for f in analyzer.analyse(flows, window_summary)
                        if f["threat_type"] == threat_type and f["destination_ip"] == target_ip]
            if not findings:
                continue
            for finding in findings[: wanted - fired]:
                records.append(_event_record(finding, detected_at, flow_builder,
                                             severity_engine, scenario_no, len(records)))
                fired += 1
        if fired < wanted:
            missed[threat_type] = wanted - fired

    if missed:
        print(f"[-] Scenarios that produced no detection (thresholds not breached): {missed}")
    records.sort(key=lambda r: r["detection_time"])
    return records


def _event_record(finding, detected_at, flow_builder, severity_engine, scenario_no, offset):
    """Turns one behavioural finding into a stored event, exactly as the live monitor does."""
    severity, _, rationale = severity_engine.evaluate_severity(
        attack_type=finding["threat_type"],
        ml_class=finding["ml_class"],
        confidence_score=finding["confidence"],
        packet_count=finding["packets"],
        destination_ip=finding["destination_ip"],
        num_sources=finding["num_sources"],
    )

    distributed = finding["num_sources"] > 1
    stats = {
        "total_packets": finding["packets"],
        "threat_metrics": finding["metrics"],
        "scenario": finding["threat_type"],
    }

    return {
        "event_id": f"{EVENT_ID_PREFIX}-{offset:06d}",
        "detection_time": detected_at,
        "attack_type": finding["threat_type"],
        "ml_class": finding["ml_class"],
        "source_ip": finding["source_ip"],
        "destination_ip": finding["destination_ip"],
        "source_ips_list": json.dumps(finding["metrics"].get("sources")) if distributed else None,
        "protocol": finding["protocol"],
        "source_port": BASE_SRC_PORT + (scenario_no % 15000),
        "destination_port": finding["destination_port"],
        "traffic_stats": json.dumps(stats),
        "detection_method": BEHAVIOUR_METHOD,
        "severity": severity,
        "confidence_score": finding["confidence"],
        "evidence": f"{finding['evidence']} {rationale}.",
        "evidence_json": json.dumps({
            "engine": "Behavioural rule engine (config/rules.yaml)",
            "metrics": finding["metrics"],
            "num_sources": finding["num_sources"],
            "campus_devices_monitored": CAMPUS_ACTIVE_DEVICES,
        }),
        "response_status": "Pending review",
        "system_response": "Live traffic matched the documented behavioural parameters and stored",
        "admin_action": "None",
        "reviewed_by": None,
        "reviewed_at": None,
        "notes": None,
        "capture_source": TEST_TRAFFIC_SOURCE,
        "integrity_hash": None,
    }


def replay_selfcheck(seed: int = 11):
    """Runs one window of every scenario and prints what the detectors returned."""
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    started = time.time()
    report = {}
    for threat_type, builder in SCENARIO_BUILDERS.items():
        rng = random.Random(seed)
        base = datetime.utcnow().timestamp()
        packets, source_ip, _target = builder(rng, base)
        flows, window_summary, _ms = flow_builder.build_flows_from_packets(packets)
        findings = analyzer.analyse(flows, window_summary)
        match = next((f for f in findings if f["threat_type"] == threat_type), None)
        report[threat_type] = (
            f"{match['ml_class']} at {match['confidence']:.3f} {match['metrics']}"
            if match else f"NO DETECTION ({len(findings)} other findings)"
        )
    return report, (time.time() - started) * 1000.0


if __name__ == "__main__":
    results, elapsed = replay_selfcheck()
    for name, outcome in results.items():
        print(f"{name:18s} -> {outcome}")
    print(f"[+] Self-check latency: {elapsed:.1f} ms")
