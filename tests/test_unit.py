"""
AI-NIDS Unit Testing Suite (UT01 - UT11)
Chinhoyi University of Technology - Group 5
Validates individual modules: feature pipeline, priority queue, hashing,
severity tier assignment, tshark parser abstraction, and the behavioural threat detector.
"""

import os
import sys
import pytest
import random
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.services.behaviour_analyzer import BehaviourAnalyzer, is_group_destination
from backend.services.feature_pipeline import FeaturePipeline, LIVE_FEATURE_NAMES
from backend.services.flow_builder import FlowBuilder
from backend.services.priority_queue import AlertPriorityQueue, compute_event_integrity_hash
from backend.services.severity_engine import SeverityEngine
from backend.services.tshark_parser import TSharkParser
from database.scenario_replay import SCENARIO_BUILDERS, _packet


# UT01: Feature Pipeline Conversion
def test_ut01_feature_pipeline_vectorization():
    pipeline = FeaturePipeline()
    sample_dict = {f: 1.0 for f in LIVE_FEATURE_NAMES}
    sample_dict["Dst Port"] = 443.0
    sample_dict["Protocol"] = 6.0

    vec = pipeline.prepare_vector(sample_dict)
    assert len(vec) == len(LIVE_FEATURE_NAMES)
    assert vec[0] == 443.0
    assert vec[1] == 6.0


# UT02: Priority Queue Heapq Ordering
def test_ut02_priority_queue_ordering():
    pq = AlertPriorityQueue()
    ev_low = {"event_id": "THR-001", "severity": "Low", "confidence_score": 0.5, "detection_time": "2026-10-20T00:00:00"}
    ev_med = {"event_id": "THR-002", "severity": "Medium", "confidence_score": 0.8, "detection_time": "2026-10-20T00:01:00"}
    ev_high = {"event_id": "THR-003", "severity": "High", "confidence_score": 0.95, "detection_time": "2026-10-20T00:02:00"}
    ev_crit = {"event_id": "THR-004", "severity": "Critical", "confidence_score": 0.99, "detection_time": "2026-10-20T00:03:00"}

    pq.push(ev_low)
    pq.push(ev_high)
    pq.push(ev_crit)
    pq.push(ev_med)

    assert pq.size() == 4
    top1 = pq.pop()
    assert top1["event_id"] == "THR-004"  # Critical popped first
    top2 = pq.pop()
    assert top2["event_id"] == "THR-003"  # High popped second


# UT03: Cryptographic Integrity Hashing (SHA-256)
def test_ut03_sha256_integrity_hash():
    ev = {
        "event_id": "THR-000100",
        "detection_time": "2026-10-20T10:00:00",
        "attack_type": "DoS",
        "source_ip": "192.168.1.30",
        "destination_ip": "192.168.1.1",
        "detection_method": "Wireshark",
        "severity": "High"
    }
    h1 = compute_event_integrity_hash(ev)
    h2 = compute_event_integrity_hash(ev)
    assert h1 == h2
    assert len(h1) == 64

    # Tamper detection
    tampered = dict(ev)
    tampered["source_ip"] = "192.168.1.99"
    h_tampered = compute_event_integrity_hash(tampered)
    assert h1 != h_tampered


# UT04: Severity Engine Tier Assignment & Response Latency
def test_ut04_severity_engine_tiers():
    engine = SeverityEngine()

    severity, latency, rationale = engine.evaluate_severity(
        attack_type="DoS",
        ml_class="Potential Attack",
        packet_count=60000,
        destination_ip="192.168.1.1"
    )
    assert severity == "Critical"
    assert latency < 2.0
    assert rationale

    benign, _, _ = engine.evaluate_severity("Normal", "Normal")
    assert benign == "Low"

    suspicious, _, _ = engine.evaluate_severity("Other/Suspicious", "Suspicious")
    assert suspicious == "Medium"

    unknown, _, _ = engine.evaluate_severity("Unknown Pattern", "Suspicious")
    assert unknown == "Medium"


# UT05: TShark Parser Interface Enumeration
def test_ut05_tshark_parser_environment():
    parser = TSharkParser()
    assert parser.tshark_path is not None
    is_avail, msg = parser.check_environment()
    # On systems with Wireshark installed, should be True
    if parser.is_available:
        ifaces = parser.list_interfaces()
        assert isinstance(ifaces, list)


# UT06: Behavioural Detector Covers the Documented Threat Types
def test_ut06_behavioural_detector_threat_types():
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    rng = random.Random(3)
    base = datetime(2026, 10, 25, 8, 0, 0).timestamp()

    for threat_type, builder in SCENARIO_BUILDERS.items():
        packets, _source, _target = builder(rng, base)
        flows, window_summary, _ms = flow_builder.build_flows_from_packets(packets)
        findings = [f for f in analyzer.analyse(flows, window_summary)
                    if f["threat_type"] == threat_type]
        assert findings, f"{threat_type} produced no detection"
        finding = findings[0]
        assert finding["confidence"] > 0.7
        assert finding["evidence"]
        assert finding["ml_class"] in ("Suspicious", "Potential Attack")

    # Distributed flood must report the coordinating hosts, not a single attacker
    packets, _s, _t = SCENARIO_BUILDERS["DDoS"](rng, base)
    flows, window_summary, _ms = flow_builder.build_flows_from_packets(packets)
    ddos = next(f for f in analyzer.analyse(flows, window_summary) if f["threat_type"] == "DDoS")
    assert ddos["num_sources"] >= analyzer.ddos_rules["min_distinct_sources"]
    assert len(ddos["metrics"]["sources"]) == ddos["num_sources"]


# UT07: Ordinary Browsing Raises No Behavioural Finding
def test_ut07_behavioural_detector_ignores_benign_browsing():
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    base = datetime(2026, 10, 25, 8, 0, 0).timestamp()

    packets = []
    for host_index in range(6):
        host = f"192.168.12.{100 + host_index}"
        for step, (syn, ack) in enumerate([(1, 0), (0, 1), (1, 1), (0, 1)]):
            packets.append(_packet(host, "10.10.0.10", 49152 + host_index, 443,
                                   base + step * 0.4, syn=syn, ack=ack))
    flows, window_summary, _ms = flow_builder.build_flows_from_packets(packets)
    assert analyzer.analyse(flows, window_summary) == []


# UT08: Normal Multicast and Broadcast Fan-Out Is Not a Flood
def test_ut08_group_destinations_are_ignored():
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    base = datetime(2026, 10, 25, 8, 0, 0).timestamp()

    for group in ("224.0.0.251", "10.252.255.255", "255.255.255.255"):
        packets = []
        for host_index in range(12):
            host = f"10.252.{host_index % 4}.{100 + host_index}"
            for step in range(30):
                packets.append(_packet(host, group, 5353, 5353,
                                       base + step * 0.02, protocol=17))
        flows, window_summary, _ms = flow_builder.build_flows_from_packets(packets)
        findings = analyzer.analyse(flows, window_summary)
        assert [f for f in findings if f["threat_type"] in ("DDoS", "DoS")] == [], group

    assert is_group_destination("224.0.0.251")
    assert is_group_destination("10.252.255.255")
    assert not is_group_destination("10.10.0.10")
    assert not is_group_destination("not-an-address")


# UT09: Traffic Spikes Are Measured Against Their Own Window
def test_ut09_traffic_spike_is_relative_and_severity_follows_strength():
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    engine = SeverityEngine()
    base = datetime(2026, 10, 25, 8, 0, 0).timestamp()

    def window(burst_packets):
        packets = []
        for peer_index in range(14):
            peer = f"10.10.0.{20 + peer_index}"
            for step in range(6):
                packets.append(_packet(peer, "10.10.0.10", 49152 + peer_index, 443,
                                       base + step * 0.2, ack=1))
        for i in range(burst_packets):
            packets.append(_packet("10.10.0.99", "10.10.0.10", 5000, 443,
                                   base + i * (0.5 / burst_packets), ack=1))
        flows, summary, _ms = flow_builder.build_flows_from_packets(packets)
        return analyzer.analyse(flows, summary)

    quiet = window(60)
    spikes = [f for f in quiet if f["threat_type"] == "Traffic Spike Anomaly"]
    assert len(spikes) == 1, f"expected one spike finding, got {quiet}"
    assert spikes[0]["ml_class"] == "Suspicious"
    assert spikes[0]["metrics"]["multiple_of_window_median"] >= 10

    loud = [f for f in window(400) if f["threat_type"] == "Traffic Spike Anomaly"][0]
    assert loud["confidence"] > spikes[0]["confidence"]

    mild_severity, _, _ = engine.evaluate_severity(
        attack_type="Traffic Spike Anomaly", ml_class="Suspicious",
        confidence_score=spikes[0]["confidence"])
    strong_severity, _, _ = engine.evaluate_severity(
        attack_type="Traffic Spike Anomaly", ml_class="Suspicious",
        confidence_score=loud["confidence"])
    assert mild_severity == "Low"
    assert strong_severity == "Medium"

    # A window of like-for-like flows has no outlier to report
    steady = []
    for peer_index in range(14):
        for step in range(6):
            steady.append(_packet(f"10.10.0.{20 + peer_index}", "10.10.0.10",
                                  49152 + peer_index, 443, base + step * 0.2, ack=1))
    flows, summary, _ms = flow_builder.build_flows_from_packets(steady)
    assert [f for f in analyzer.analyse(flows, summary)
            if f["threat_type"] == "Traffic Spike Anomaly"] == []


# UT10: Many Servers Replying to One Host Is Fan-In, Not a Distributed Flood
def test_ut10_server_fan_in_is_not_ddos():
    flow_builder = FlowBuilder()
    analyzer = BehaviourAnalyzer()
    base = datetime(2026, 10, 25, 8, 0, 0).timestamp()

    client = "10.252.5.201"
    packets = []
    for server_index in range(12):
        server = f"10.10.{server_index % 3}.{20 + server_index}"
        for step in range(40):
            packets.append(_packet(server, client, 443, 49152 + server_index,
                                   base + step * 0.0125, ack=1))

    flows, window_summary, _ms = flow_builder.build_flows_from_packets(packets)
    target = window_summary["dst_to_sources"][client]
    assert len(target["sources"]) >= analyzer.ddos_rules["min_distinct_sources"]
    assert target["aggregate_pps"] >= analyzer.ddos_rules["aggregate_packets_per_sec"]
    assert analyzer.analyse(flows, window_summary) == []


# UT11: Every Graded Threat Carries One of the Four Documented Tiers
def test_ut11_severity_engine_returns_only_documented_tiers():
    engine = SeverityEngine()
    categories = [
        "DDoS", "DoS", "Port Scanning", "Brute Force", "Other/Suspicious",
        "Traffic Spike Anomaly", "Normal", "Unrecognised Pattern", "",
    ]
    for attack_type in categories:
        for ml_class in ("Suspicious", "Potential Attack", "Normal"):
            for confidence in (0.5, 0.75, 0.95):
                severity, _, _ = engine.evaluate_severity(
                    attack_type=attack_type, ml_class=ml_class, confidence_score=confidence)
                assert severity in ("Critical", "High", "Medium", "Low"), (
                    attack_type, ml_class, confidence, severity)
