"""
AI-NIDS Severity Assessment Engine
Chinhoyi University of Technology - Group 5
Evaluates event severity dynamically based on attack category, confidence score,
packet volume, target criticality, and multi-source coordination.
Measures and records evaluation time (target < 2.0 s).
"""

import os
import yaml
import time
from typing import Dict, Any, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SEVERITY_CONFIG_PATH = os.path.join(BASE_DIR, "config", "severity_rules.yaml")

# The four tiers the system specification defines, and the action each one carries:
# Critical/High block and push, Medium waits for the analyst, Low is register-only.
DOCUMENTED_TIERS = ("Critical", "High", "Medium", "Low")


class SeverityEngine:
    def __init__(self, config_path: str = SEVERITY_CONFIG_PATH):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f) or {}
        return {
            "base_severities": {
                "DDoS": "Critical",
                "DoS": "High",
                "Port Scanning": "High",
                "Brute Force": "High",
                "Other/Suspicious": "Investigate",
                "Traffic Spike Anomaly": "Low",
                "Normal": "Low"
            },
            "ml_class_overrides": {
                "Suspicious": "Medium",
                "Potential Attack": "High",
                "Normal": "Low"
            },
            "escalation_modifiers": {
                "high_confidence_threshold": 0.90,
                "critical_target_subnets": ["192.168.1.1", "192.168.1.254", "10.0.0.1"],
                "high_packet_volume_threshold": 50000,
                "multi_source_threshold": 10
            }
        }

    def evaluate_severity(
        self,
        attack_type: str,
        ml_class: str,
        confidence_score: float = 0.0,
        packet_count: int = 0,
        destination_ip: str = "",
        num_sources: int = 1
    ) -> Tuple[str, float, str]:
        """
        Calculates severity level, records latency in seconds, and provides reasoning.
        Returns: (severity_label, latency_seconds, rationale)
        """
        t0 = time.time()
        base_map = self.config.get("base_severities", {})
        escalations = self.config.get("escalation_modifiers", {})
        destination_ip = destination_ip or ""

        # 1. Base Severity from Attack Category
        severity = base_map.get(attack_type, "Investigate")
        rationale_parts = [f"Base tier for {attack_type}: {severity}"]

        # 2. ML Class Alignment
        if ml_class == "Suspicious" and severity == "Investigate":
            # A category with no documented tier of its own is lifted to analyst review;
            # a category that does have one (e.g. a measured traffic spike) keeps it.
            severity = "Medium"
            rationale_parts.append("Elevated to Medium due to Suspicious ML class classification")
        elif ml_class == "Normal":
            severity = "Low"
            rationale_parts = ["Classified as Normal benign traffic"]

        # 3. Dynamic Escalation Modifiers
        conf_thresh = escalations.get("high_confidence_threshold", 0.90)
        if ml_class == "Suspicious" and severity == "Low" and confidence_score >= conf_thresh:
            severity = "Medium"
            rationale_parts.append(
                f"Signal measured {confidence_score * 100:.0f}% past its parameter "
                f"(at or above {conf_thresh * 100:.0f}%), escalated to analyst review"
            )

        crit_subnets = escalations.get("critical_target_subnets", [])
        if any(destination_ip.startswith(prefix) for prefix in crit_subnets) and severity in ["Medium", "High"]:
            if severity == "High" and attack_type in ["DoS", "DDoS"]:
                severity = "Critical"
                rationale_parts.append(f"Target {destination_ip} is an identified critical infrastructure host; escalated to Critical")
            elif severity == "Medium":
                severity = "High"
                rationale_parts.append(f"Target {destination_ip} is in critical infrastructure subnet")

        vol_thresh = escalations.get("high_packet_volume_threshold", 50000)
        if packet_count > vol_thresh and severity == "High":
            severity = "Critical"
            rationale_parts.append(f"Packet volume ({packet_count:,} packets) exceeds high-volume threshold ({vol_thresh:,})")

        multi_thresh = escalations.get("multi_source_threshold", 10)
        if num_sources >= multi_thresh and severity in ["Medium", "High"]:
            severity = "Critical"
            rationale_parts.append(f"Distributed attack from {num_sources} concurrent sources")

        # The document defines four tiers only, so an unrecognised category is graded by
        # its classification rather than left with a label the register cannot act on.
        if severity not in DOCUMENTED_TIERS:
            severity = self.config.get("ml_class_overrides", {}).get(ml_class, "Medium")
            rationale_parts.append(f"Graded as {severity} from its {ml_class} classification")

        eval_latency = time.time() - t0
        rationale = " | ".join(rationale_parts)

        return severity, eval_latency, rationale
