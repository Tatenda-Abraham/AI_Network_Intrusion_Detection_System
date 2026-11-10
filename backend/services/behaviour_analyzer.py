"""
AI-NIDS Behavioural Threat Analysis
Chinhoyi University of Technology - Group 5

Second detection stage of the system specification. The Random Forest recognises the
attack classes that are labelled in the campus benchmark dataset (brute-force
campaigns); the behavioural parameters below catch the reconnaissance and volumetric
threats that dataset does not label - port scanning, denial of service, distributed
denial of service and baseline anomalies.

Every threshold is read from the ip-flow blocks of config/rules.yaml, and the
aggregation is supplied by FlowBuilder's per-window summary, so the live monitor and
the stored campus baseline are judged by exactly the same parameters.
"""

import os
import statistics
from collections import defaultdict
from typing import Any, Dict, List

import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_PATH = os.path.join(BASE_DIR, "config", "rules.yaml")

# A single flow with a handful of packets proves too little to call a flood
MIN_PACKETS_FOR_RATE_FINDING = 5

# 224.0.0.0/4 is the IPv4 multicast block; .255 hosts are Ethernet subnet broadcasts.
# Many hosts sending to one of these addresses is normal group fan-out (mDNS, ARP, DHCP),
# not a flood aimed at a server, so the volumetric parameters ignore them.
MULTICAST_FIRST_OCTET_RANGE = range(224, 240)


def is_group_destination(address: str) -> bool:
    """True when an address is a multicast group or a broadcast host part."""
    parts = (address or "").split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    octets = [int(p) for p in parts]
    if octets[0] in MULTICAST_FIRST_OCTET_RANGE:
        return True
    return octets == [255, 255, 255, 255] or octets[3] == 255


class BehaviourAnalyzer:
    """Evaluates the documented IP-flow behavioural parameters over one capture window."""

    def __init__(self, rules_path: str = RULES_PATH):
        rules = {}
        if os.path.exists(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                rules = yaml.safe_load(f) or {}
        self.port_scan_rules = rules.get("port_scan", {}) or {}
        self.dos_rules = rules.get("dos", {}) or {}
        self.ddos_rules = rules.get("ddos", {}) or {}
        self.anomaly_rules = rules.get("suspicious_anomaly", {}) or {}
        self.spike_rules = rules.get("traffic_spike", {}) or {}

    def analyse(self, flows: List[Dict[str, Any]], window_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Returns one finding per source or target that breaches a documented parameter."""
        findings = []
        findings += self._port_scans(window_summary)
        findings += self._denial_of_service(flows, window_summary)
        findings += self._distributed_denial_of_service(window_summary)
        findings += self._anomalies(flows)
        findings += self._traffic_spikes(flows)
        return findings

    def _port_scans(self, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        rule = self.port_scan_rules
        if not rule.get("enabled", True):
            return []

        need_ports = int(rule.get("distinct_ports_threshold", 15))
        need_ratio = float(rule.get("syn_without_ack_min_ratio", 2.0))
        findings = []

        for source, data in (summary.get("source_to_distinct_dst_ports") or {}).items():
            ports = data.get("distinct_ports") or []
            syn, ack = int(data.get("syn_count", 0)), int(data.get("ack_count", 0))
            unanswered = syn / max(ack, 1)
            if len(ports) < need_ports or unanswered < need_ratio:
                continue

            findings.append(self._finding(
                threat_type="Port Scanning",
                ml_class="Potential Attack",
                source_ip=source,
                destination_ip=data.get("target_ip", ""),
                destination_port=max(ports),
                protocol="TCP",
                packets=syn + ack,
                num_sources=1,
                confidence=self._confidence(len(ports) / need_ports),
                metrics={
                    "distinct_ports": len(ports),
                    "port_range": [min(ports), max(ports)],
                    "syn_without_ack_ratio": round(unanswered, 2),
                },
                evidence=(
                    f"{source} addressed {len(ports)} distinct destination ports "
                    f"({min(ports)}-{max(ports)}) while sending {unanswered:.1f} unanswered SYN packets "
                    f"per ACK, breaching the documented scan parameters "
                    f"(at least {need_ports} ports, SYN/ACK ratio at least {need_ratio})."
                ),
            ))
        return findings

    def _denial_of_service(self, flows: List[Dict[str, Any]], summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        rule = self.dos_rules
        if not rule.get("enabled", True):
            return []

        need_pps = float(rule.get("packets_per_sec_threshold", 120))
        need_syn_pps = float(rule.get("syn_per_sec_threshold", 40))
        need_ratio = float(rule.get("syn_without_ack_ratio_threshold", 3.0))
        require_imbalance = rule.get("require_ml_or_syn_imbalance", True)
        duration = max(float(summary.get("window_duration_seconds") or 0.0), 1.0)

        pairs = defaultdict(lambda: {"packets": 0, "syn": 0, "ack": 0, "ports": set(), "protocol": "OTHER"})
        for flow in flows:
            agg = pairs[(flow["src_ip"], flow["dst_ip"])]
            stats = flow["traffic_stats"]
            agg["packets"] += int(stats["total_packets"])
            agg["syn"] += int(stats["syn_flags"])
            agg["ack"] += int(stats["ack_flags"])
            agg["ports"].add(flow["dst_port"])
            agg["protocol"] = flow["protocol_name"]

        findings = []
        for (source, target), agg in pairs.items():
            if agg["packets"] < MIN_PACKETS_FOR_RATE_FINDING:
                continue
            if rule.get("skip_group_destinations", True) and is_group_destination(target):
                continue
            rate = agg["packets"] / duration
            syn_rate = agg["syn"] / duration
            unanswered = agg["syn"] / max(agg["ack"], 1)
            if not (rate >= need_pps or syn_rate >= need_syn_pps):
                continue
            # A large but well-answered download is not a flood; the documented rule
            # demands unanswered SYNs before this parameter fires.
            if require_imbalance and unanswered < need_ratio:
                continue

            exceedance = max(rate / need_pps, syn_rate / max(need_syn_pps, 1.0))
            findings.append(self._finding(
                threat_type="DoS",
                ml_class="Potential Attack",
                source_ip=source,
                destination_ip=target,
                destination_port=max(agg["ports"], default=0),
                protocol=agg["protocol"],
                packets=agg["packets"],
                num_sources=1,
                confidence=self._confidence(exceedance),
                metrics={
                    "packets_per_sec": round(rate, 1),
                    "syn_per_sec": round(syn_rate, 1),
                    "syn_without_ack_ratio": round(unanswered, 2),
                    "window_seconds": round(duration, 2),
                },
                evidence=(
                    f"{source} sent {agg['packets']:,} packets to {target} across {duration:.1f} s "
                    f"({rate:,.0f} pps, {syn_rate:,.0f} SYN pps, {unanswered:.1f} unanswered SYN per ACK), "
                    f"exceeding the documented flood parameters "
                    f"(at least {need_pps:,.0f} pps or {need_syn_pps:,.0f} SYN pps)."
                ),
            ))
        return findings

    def _distributed_denial_of_service(self, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        rule = self.ddos_rules
        if not rule.get("enabled", True):
            return []

        need_sources = int(rule.get("min_distinct_sources", 5))
        need_pps = float(rule.get("aggregate_packets_per_sec", 250))
        correlate = rule.get("correlated_port_or_proto", True)
        duration = max(float(summary.get("window_duration_seconds") or 0.0), 1.0)
        findings = []

        for target, data in (summary.get("dst_to_sources") or {}).items():
            sources = data.get("sources") or []
            if rule.get("skip_group_destinations", True) and is_group_destination(target):
                continue
            if len(sources) < need_sources:
                continue

            if not correlate:
                rate = float(data.get("aggregate_pps") or 0.0)
                if rate < need_pps:
                    continue
                port, port_sources, port_seconds = 0, sources, duration
            else:
                # The documented parameter is a coordinated flood: the same service on
                # the target must be addressed by enough hosts, fast enough. Fan-in from
                # independent servers replying on their own ports is ordinary traffic.
                strongest = None
                for port_key, port_data in (data.get("by_port") or {}).items():
                    port_srcs = port_data.get("sources") or []
                    if len(port_srcs) < need_sources:
                        continue
                    port_seconds = max(float(port_data.get("duration_seconds") or 0.0), 0.1)
                    port_rate = int(port_data.get("packets", 0)) / port_seconds
                    if port_rate < need_pps:
                        continue
                    if strongest is None or port_rate > strongest[0]:
                        strongest = (port_rate, int(port_key), port_srcs, port_seconds)
                if strongest is None:
                    continue
                rate, port, port_sources, port_seconds = strongest

            findings.append(self._finding(
                threat_type="DDoS",
                ml_class="Potential Attack",
                source_ip=port_sources[0],
                destination_ip=target,
                destination_port=port,
                protocol="MIXED" if port == 0 else "TCP",
                packets=int(rate),
                num_sources=len(port_sources),
                confidence=self._confidence(rate / need_pps),
                metrics={
                    "distinct_sources": len(port_sources),
                    "aggregate_packets_per_sec": round(rate, 1),
                    "common_destination_port": port or None,
                    "observation_seconds": round(port_seconds, 2),
                    "sources": port_sources[:12],
                },
                evidence=(
                    f"{len(port_sources)} campus hosts directed {rate:,.0f} packets per second at "
                    + (f"{target}:{port}" if port else f"{target} across its services")
                    + f" over {port_seconds:.1f} s, breaching the documented distributed flood parameters "
                    f"(at least {need_sources} sources above {need_pps:,.0f} pps). "
                    f"Alerts are decision support for analyst review, not a confirmed breach."
                ),
            ))
        return findings

    def _anomalies(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rule = self.anomaly_rules
        if not rule.get("enabled", True):
            return []

        need_rst_ratio = float(rule.get("rst_flag_ratio_threshold", 0.6))
        findings = []

        for flow in flows:
            stats = flow["traffic_stats"]
            packets = int(stats["total_packets"])
            if packets < MIN_PACKETS_FOR_RATE_FINDING:
                continue
            rst_ratio = int(stats["rst_flags"]) / packets
            if rst_ratio < need_rst_ratio:
                continue

            findings.append(self._finding(
                threat_type="Other/Suspicious",
                ml_class="Suspicious",
                source_ip=flow["src_ip"],
                destination_ip=flow["dst_ip"],
                destination_port=flow["dst_port"],
                protocol=flow["protocol_name"],
                packets=packets,
                num_sources=1,
                confidence=self._confidence(rst_ratio / need_rst_ratio),
                metrics={
                    "rst_flag_ratio": round(rst_ratio, 2),
                    "flow_duration_seconds": stats["duration_seconds"],
                },
                evidence=(
                    f"Flow {flow['src_ip']}:{flow['src_port']} to {flow['dst_ip']}:{flow['dst_port']} "
                    f"reset {rst_ratio * 100:.0f}% of its {packets} packets, against the documented "
                    f"anomaly parameter of {need_rst_ratio * 100:.0f}%."
                ),
            ))
        return findings

    def _traffic_spikes(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """A flow whose rate stands far above the rest of its own window."""
        rule = self.spike_rules
        if not rule.get("enabled", True):
            return []

        multiplier = float(rule.get("rate_multiplier", 10.0))
        min_packets = int(rule.get("min_packets", 40))
        need_flows = int(rule.get("min_flows_in_window", 12))
        skip_groups = rule.get("skip_group_destinations", True)
        if len(flows) < need_flows:
            return []

        rates = [float(f["traffic_stats"]["packets_per_sec"]) for f in flows]
        median_rate = statistics.median(rates)
        if median_rate <= 0:
            return []
        bar = median_rate * multiplier

        candidates = [
            f for f in flows
            if int(f["traffic_stats"]["total_packets"]) >= min_packets
            and float(f["traffic_stats"]["packets_per_sec"]) >= bar
            and not (skip_groups and is_group_destination(f["dst_ip"]))
        ]
        # Only the strongest deviations are reported, so a busy window cannot flood the register
        candidates.sort(key=lambda f: -float(f["traffic_stats"]["packets_per_sec"]))

        findings = []
        for flow in candidates[: int(rule.get("max_findings_per_window", 3))]:
            stats = flow["traffic_stats"]
            rate = float(stats["packets_per_sec"])
            findings.append(self._finding(
                threat_type="Traffic Spike Anomaly",
                ml_class="Suspicious",
                source_ip=flow["src_ip"],
                destination_ip=flow["dst_ip"],
                destination_port=flow["dst_port"],
                protocol=flow["protocol_name"],
                packets=int(stats["total_packets"]),
                num_sources=1,
                confidence=self._confidence(rate / bar),
                metrics={
                    "packets_per_sec": round(rate, 1),
                    "window_median_packets_per_sec": round(median_rate, 2),
                    "multiple_of_window_median": round(rate / median_rate, 1),
                    "flow_duration_seconds": stats["duration_seconds"],
                },
                evidence=(
                    f"Flow {flow['src_ip']} to {flow['dst_ip']}:{flow['dst_port']} ran at "
                    f"{rate:,.0f} packets per second against a window median of {median_rate:,.1f} "
                    f"({rate / median_rate:,.0f}x), past the documented spike multiple of {multiplier:,.0f}x."
                ),
            ))
        return findings

    @staticmethod
    def _confidence(exceedance: float) -> float:
        """Rule strength: how far a measurement sits past its documented threshold."""
        return round(min(0.97, 0.75 + 0.05 * max(float(exceedance), 1.0)), 3)

    @staticmethod
    def _finding(
        threat_type: str,
        ml_class: str,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
        packets: int,
        num_sources: int,
        confidence: float,
        metrics: Dict[str, Any],
        evidence: str,
    ) -> Dict[str, Any]:
        return {
            "threat_type": threat_type,
            "ml_class": ml_class,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "packets": packets,
            "num_sources": num_sources,
            "confidence": confidence,
            "metrics": metrics,
            "evidence": evidence,
        }
