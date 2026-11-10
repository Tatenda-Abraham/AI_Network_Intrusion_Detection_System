"""
AI-NIDS Live Flow Classification
Chinhoyi University of Technology - Group 5
Wires the monitor-mode prototype to the detection core:
1. FlowBuilder aggregates captured packets into bidirectional flows (34 features)
2. FeaturePipeline validates and prepares the feature vectors
3. MLService classifies each flow with the same Random Forest used for stored traffic
4. BehaviourAnalyzer judges the documented behavioural parameters over the window
   (port scanning, DoS, DDoS, baseline anomalies) that the dataset does not label
5. SeverityEngine sets the response tier
6. Results are written to the shared `events` table, with an alert per elevated threat
"""

import json
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd

from backend.config import AI_MODEL_METHOD, BEHAVIOUR_METHOD, LIVE_TRAFFIC_SOURCE
from backend.models import Alert, Event
from backend.services.behaviour_analyzer import BehaviourAnalyzer
from backend.services.feature_pipeline import LIVE_FEATURE_NAMES, FeaturePipeline
from backend.services.flow_builder import FlowBuilder
from backend.services.ml_service import MLService
from backend.services.priority_queue import compute_event_integrity_hash
from backend.services.severity_engine import SeverityEngine

# Single-packet observations (broadcasts, mDNS) carry no flow behaviour to classify
MIN_PACKETS_PER_FLOW = 2
# Busiest flows are stored each window; every non-benign flow is always stored
MAX_BENIGN_EVENTS_PER_WINDOW = 25



class FlowClassifier:
    def __init__(self):
        self.flow_builder = FlowBuilder()
        self.pipeline = FeaturePipeline()
        self.ml_service = MLService()
        self.severity_engine = SeverityEngine()
        self.behaviour = BehaviourAnalyzer()

    def classify_window(
        self,
        db,
        packets: List[Dict[str, Any]],
        window_start: datetime,
        window_end: datetime,
        capture_session_id: Optional[int] = None,
        window_id: Optional[int] = None,
        adapter_label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Aggregates, classifies and persists one capture window of live traffic."""
        summary = {
            "flows_detected": 0,
            "flows_classified": 0,
            "events_created": 0,
            "alerts_created": 0,
            "attacks_found": 0,
            "behaviour_findings": 0,
            "preprocessing_ms": 0.0,
            "inference_ms": 0.0,
        }

        flows, window_summary, build_ms = self.flow_builder.build_flows_from_packets(packets)
        summary["flows_detected"] = len(flows)
        summary["preprocessing_ms"] = round(build_ms, 2)

        candidates = [
            f for f in flows
            if f["traffic_stats"]["total_packets"] >= MIN_PACKETS_PER_FLOW
        ]
        if not candidates:
            return summary

        frame = pd.DataFrame([[float(f[name]) for name in LIVE_FEATURE_NAMES] for f in candidates],
                             columns=LIVE_FEATURE_NAMES)
        cleaned, prep_ms = self.pipeline.clean_dataframe(frame)
        predictions, infer_ms = self.ml_service.predict_batch(cleaned)
        summary["preprocessing_ms"] = round(summary["preprocessing_ms"] + prep_ms, 2)
        summary["inference_ms"] = round(infer_ms, 2)

        ranked = sorted(
            zip(candidates, predictions),
            key=lambda pair: -pair[0]["traffic_stats"]["total_packets"],
        )

        benign_stored = 0
        for flow, pred in ranked:
            is_threat = pred["ml_class"] != "Normal"
            if not is_threat and benign_stored >= MAX_BENIGN_EVENTS_PER_WINDOW:
                continue

            stats = flow["traffic_stats"]
            severity, _eval_ms, rationale = self.severity_engine.evaluate_severity(
                attack_type=pred["attack_type"],
                ml_class=pred["ml_class"],
                confidence_score=pred["confidence_score"],
                packet_count=stats["total_packets"],
                destination_ip=flow["dst_ip"],
            )

            endpoint = f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']}"
            evidence = (
                f"{self.ml_service.active_algorithm} classified live flow {endpoint} "
                f"({flow['protocol_name']}, {stats['total_packets']} packets, "
                f"{stats['bytes_per_sec']:,.0f} B/s) as {pred['ml_class']} at "
                f"{pred['confidence_score'] * 100:.1f}% confidence. {rationale}"
            )

            payload = {
                "event_id": f"THR-{secrets.token_hex(4).upper()}",
                "detection_time": window_end,
                "attack_type": pred["attack_type"],
                "ml_class": pred["ml_class"],
                "source_ip": flow["src_ip"],
                "destination_ip": flow["dst_ip"],
                "protocol": flow["protocol_name"],
                "source_port": flow["src_port"],
                "destination_port": flow["dst_port"],
                "traffic_stats": json.dumps(stats),
                "detection_method": AI_MODEL_METHOD,
                "severity": severity,
                "confidence_score": pred["confidence_score"],
                "evidence": evidence,
                "evidence_json": json.dumps({
                    "engine": self.ml_service.active_algorithm,
                    "adapter": adapter_label,
                    "flow_features": {name: flow[name] for name in LIVE_FEATURE_NAMES},
                }),
                "response_status": "Pending review" if is_threat else "Resolved",
                "system_response": "Live traffic classified by the Random Forest model and stored",
                "capture_source": LIVE_TRAFFIC_SOURCE,
                "capture_session_id": capture_session_id,
                "window_id": window_id,
            }
            payload["integrity_hash"] = compute_event_integrity_hash(payload)

            event = Event(**payload)
            db.add(event)
            db.flush()
            summary["events_created"] += 1
            summary["flows_classified"] += 1

            if is_threat:
                summary["attacks_found"] += 1
                if severity in ("Critical", "High", "Medium"):
                    db.add(Alert(
                        event_id=event.id,
                        severity=severity,
                        status="Active",
                        message=(
                            f"{severity} alert: {pred['attack_type']} detected from "
                            f"{flow['src_ip']} against {flow['dst_ip']}:{flow['dst_port']}"
                        ),
                    ))
                    summary["alerts_created"] += 1

            if not is_threat:
                benign_stored += 1

        # Stage 2: the documented behavioural parameters, judged over the whole window
        for finding in self.behaviour.analyse(candidates, window_summary):
            severity, eval_ms, rationale = self.severity_engine.evaluate_severity(
                attack_type=finding["threat_type"],
                ml_class=finding["ml_class"],
                confidence_score=finding["confidence"],
                packet_count=finding["packets"],
                destination_ip=finding["destination_ip"],
                num_sources=finding["num_sources"],
            )
            summary["severity_evaluation_ms"] = round(
                summary.get("severity_evaluation_ms", 0.0) + eval_ms * 1000, 3
            )

            payload = {
                "event_id": f"THR-{secrets.token_hex(4).upper()}",
                "detection_time": window_end,
                "attack_type": finding["threat_type"],
                "ml_class": finding["ml_class"],
                "source_ip": finding["source_ip"],
                "destination_ip": finding["destination_ip"],
                "protocol": finding["protocol"],
                "source_port": 0,
                "destination_port": finding["destination_port"],
                "traffic_stats": json.dumps(finding["metrics"]),
                "detection_method": BEHAVIOUR_METHOD,
                "severity": severity,
                "confidence_score": finding["confidence"],
                "evidence": f"{finding['evidence']} {rationale}",
                "evidence_json": json.dumps({
                    "engine": "Behavioural parameters (config/rules.yaml)",
                    "adapter": adapter_label,
                    "metrics": finding["metrics"],
                }),
                "response_status": "Pending review",
                "system_response": "Live traffic matched the documented behavioural parameters and stored",
                "capture_source": LIVE_TRAFFIC_SOURCE,
                "capture_session_id": capture_session_id,
                "window_id": window_id,
            }
            payload["integrity_hash"] = compute_event_integrity_hash(payload)

            event = Event(**payload)
            db.add(event)
            db.flush()
            summary["events_created"] += 1
            summary["attacks_found"] += 1
            summary["behaviour_findings"] = summary.get("behaviour_findings", 0) + 1

            if severity in ("Critical", "High", "Medium"):
                db.add(Alert(
                    event_id=event.id,
                    severity=severity,
                    status="Active",
                    message=(
                        f"{severity} alert: {finding['threat_type']} detected from "
                        f"{finding['source_ip']} against {finding['destination_ip']}"
                    ),
                ))
                summary["alerts_created"] += 1

        return summary
