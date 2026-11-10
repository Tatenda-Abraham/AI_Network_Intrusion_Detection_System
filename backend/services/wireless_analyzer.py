"""
AI-NIDS Wireless Analysis Service
Chinhoyi University of Technology - Group 5
Performs:
1. 802.11 frame analysis & window aggregation (10s windows)
2. Wireless attack detection:
   - Deauthentication / Disassociation flood
   - Beacon flood
   - Probe request flood
   - Authentication flood
   - Rogue AP & Evil Twin heuristics (SSID on unapproved BSSID / unexpected channel)
   - Baseline statistical deviation calculation
3. OUI vendor resolution for device conversations
4. Persistence into live_capture_windows, wifi_frames, device_conversations, live_findings, events, alerts
"""

import os
import json
import secrets
import math
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.config import LIVE_TRAFFIC_SOURCE
from backend.models import (
    LiveCaptureWindow, LiveFinding, WifiFrame,
    DeviceConversation, Event, Alert, WifiAccessPoint,
    BaselineStat
)
from backend.services.priority_queue import compute_event_integrity_hash
from backend.services.severity_engine import SeverityEngine

# Standard OUI prefix map for hardware vendor resolution
COMMON_OUIS = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:1c:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi",
    "3c:71:bf": "Espressif (ESP32/ESP8266)",
    "24:6f:28": "Espressif",
    "30:ae:a4": "Espressif",
    "a4:cf:12": "Espressif",
    "00:1a:2b": "Cisco Systems",
    "00:24:14": "Cisco Systems",
    "cc:d5:39": "Cisco Systems",
    "00:17:88": "Philips Lighting",
    "18:b4:30": "Nest Labs",
    "70:ee:50": "Netgear",
    "c0:ff:d4": "TP-Link",
    "50:c7:bf": "TP-Link",
    "e8:48:b8": "TP-Link",
    "00:14:bf": "Linksys",
    "00:18:0a": "Cisco-Linksys",
    "ac:bc:32": "Apple",
    "f0:18:98": "Apple",
    "3c:06:30": "Apple",
    "a4:83:e7": "Apple",
    "70:3a:cb": "Apple",
    "a8:5b:78": "Apple",
    "34:42:62": "Apple",
    "00:23:12": "Apple",
    "48:d7:05": "Apple",
    "f8:ff:c2": "Apple",
    "00:1a:11": "Google",
    "3c:5a:37": "Google",
    "d8:6c:63": "Google",
    "00:09:5b": "Netgear",
    "20:4e:7f": "Netgear",
    "00:26:86": "Quantenna",
    "40:16:9f": "TP-Link",
    "14:cc:20": "TP-Link",
    "00:21:6a": "Intel",
    "00:1b:21": "Intel",
    "34:13:e8": "Intel",
    "a4:bb:6d": "Intel",
    "00:24:d7": "Intel",
    "80:86:f2": "Intel",
    "00:28:f8": "Samsung Electronics",
    "34:be:00": "Samsung Electronics",
    "50:01:d9": "Samsung Electronics",
    "ec:1f:72": "Samsung Electronics",
    "78:40:e4": "Samsung Electronics",
    "00:16:6c": "Samsung Electronics",
    "00:e0:4c": "Realtek Semiconductor",
    "54:04:a6": "Realtek",
    "74:da:38": "Edimax Technology",
    "00:04:0e": "AVM GmbH",
    "00:26:4a": "ASUSTek Computer",
    "f0:79:59": "ASUSTek Computer"
}


def lookup_oui(mac: Optional[str]) -> str:
    """Resolves MAC address prefix to vendor using local OUI table."""
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac[:8].lower()
    return COMMON_OUIS.get(prefix, "Standard Network Interface")


class WirelessAnalyzer:
    def __init__(self, db_session: Session, rules: Optional[Dict[str, Any]] = None):
        self.db = db_session
        self.rules = rules or {}
        self.w_rules = self.rules.get("wireless", {})
        register = self.w_rules.get("approved_access_points", []) or []
        self.approved_bssids = {
            str(entry.get("bssid", "")).lower() for entry in register if entry.get("bssid")
        }
        self.approved_ssids = {
            str(entry.get("ssid", "")).lower() for entry in register if entry.get("ssid")
        }
        anomaly = self.w_rules.get("baseline_anomaly", {}) or {}
        self.anomaly_z_threshold = float(anomaly.get("z_score_threshold", 2.5))
        self.severity_engine = SeverityEngine()

    def _is_authorised_ap(self, bssid: str, ssid: Optional[str]) -> bool:
        return bssid.lower() in self.approved_bssids or (ssid or "").lower() in self.approved_ssids

    def analyze_window(self, capture_session_id: int, packets: List[Dict[str, Any]], 
                       window_start: datetime, window_end: datetime) -> LiveCaptureWindow:
        """Processes 802.11 frames in a window into summaries, conversations, and findings."""
        frames_count = len(packets)
        mgt_frames = 0
        ctrl_frames = 0
        data_frames = 0
        deauth_frames = 0
        beacon_frames = 0
        probe_frames = 0
        auth_frames = 0
        transmitters = set()
        total_rssi = 0
        rssi_count = 0

        # Conversation aggregations: (mac_a, mac_b) -> stats
        convs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # AP tracking: bssid -> dict
        seen_aps: Dict[str, Dict[str, Any]] = {}

        for p in packets:
            tx = p.get("transmitter_mac")
            rx = p.get("receiver_mac")
            bssid = p.get("bssid")
            ftype = p.get("fc_type")
            subtype = p.get("fc_subtype")
            rssi = p.get("rssi")
            ssid = p.get("ssid")
            ch = p.get("channel")

            if tx:
                transmitters.add(tx.lower())
            if rssi is not None:
                total_rssi += rssi
                rssi_count += 1

            if bssid and bssid != "ff:ff:ff:ff:ff:ff":
                b_low = bssid.lower()
                if b_low not in seen_aps:
                    seen_aps[b_low] = {
                        "bssid": b_low,
                        "ssid": ssid,
                        "channel": ch,
                        "rssi": rssi,
                        "beacon_count": 0
                    }
                if ssid and not seen_aps[b_low]["ssid"]:
                    seen_aps[b_low]["ssid"] = ssid
                if ch and not seen_aps[b_low]["channel"]:
                    seen_aps[b_low]["channel"] = ch

            # 802.11 frame categorization
            if ftype == 0:  # Management
                mgt_frames += 1
                if subtype in (10, 12):  # Disassociation (10), Deauth (12)
                    deauth_frames += 1
                elif subtype == 8:  # Beacon
                    beacon_frames += 1
                    if bssid and bssid.lower() in seen_aps:
                        seen_aps[bssid.lower()]["beacon_count"] += 1
                elif subtype in (4, 5):  # Probe Request (4), Probe Response (5)
                    probe_frames += 1
                elif subtype in (0, 11):  # Association/Auth
                    auth_frames += 1
            elif ftype == 1:  # Control
                ctrl_frames += 1
            elif ftype == 2:  # Data
                data_frames += 1

            # Conversation tracking
            if tx and rx and tx != "ff:ff:ff:ff:ff:ff":
                tx_l = tx.lower()
                rx_l = rx.lower()
                pair = tuple(sorted([tx_l, rx_l]))
                if pair not in convs:
                    convs[pair] = {
                        "mac_a": tx_l,
                        "mac_b": rx_l,
                        "bssid": bssid.lower() if bssid else None,
                        "channel": ch,
                        "packets": 0,
                        "bytes": 0,
                        "rssi_sum": 0,
                        "rssi_count": 0
                    }
                c = convs[pair]
                c["packets"] += 1
                c["bytes"] += p.get("length", 0)
                if rssi is not None:
                    c["rssi_sum"] += rssi
                    c["rssi_count"] += 1

        duration = max((window_end - window_start).total_seconds(), 1.0)
        pps = frames_count / duration
        avg_rssi = (total_rssi / rssi_count) if rssi_count > 0 else None

        # Query baseline stats for current day and hour
        dow = window_start.weekday()
        hod = window_start.hour
        baseline_record = self.db.query(BaselineStat).filter_by(day_of_week=dow, hour_of_day=hod).first()

        baseline_pps = baseline_record.avg_pps if baseline_record and baseline_record.avg_pps else 0.0
        baseline_std = baseline_record.std_pps if baseline_record and baseline_record.std_pps else 1.0

        # Deviation score calculation (Z-score heuristic)
        anomaly_score = 0.0
        if baseline_pps > 0:
            anomaly_score = max(0.0, (pps - baseline_pps) / max(baseline_std, 1.0))
        elif pps > 100.0:
            anomaly_score = min(1.0, pps / 200.0)

        # Create and persist window record
        window = LiveCaptureWindow(
            capture_session_id=capture_session_id,
            window_start=window_start,
            window_end=window_end,
            frames_count=frames_count,
            management_frames=mgt_frames,
            control_frames=ctrl_frames,
            data_frames=data_frames,
            deauth_frames=deauth_frames,
            beacon_frames=beacon_frames,
            probe_frames=probe_frames,
            unique_transmitters=len(transmitters),
            packets_per_second=round(pps, 2),
            avg_rssi_dbm=round(avg_rssi, 1) if avg_rssi is not None else None,
            baseline_pps=round(baseline_pps, 2),
            anomaly_score=round(min(anomaly_score, 10.0), 3),
            findings_count=0,
            processing_ms=0.0
        )
        self.db.add(window)
        self.db.flush()

        # Update baseline stats rolling average
        self._update_baseline(dow, hod, pps, deauth_frames / duration)

        # Update or record WiFi Access Points
        for bssid_val, ap_info in seen_aps.items():
            authorised = self._is_authorised_ap(bssid_val, ap_info.get("ssid"))
            existing_ap = self.db.query(WifiAccessPoint).filter_by(bssid=bssid_val).first()
            if not existing_ap:
                new_ap = WifiAccessPoint(
                    bssid=bssid_val,
                    ssid=ap_info.get("ssid"),
                    channel=ap_info.get("channel"),
                    approved=authorised,
                    first_seen=window_start,
                    last_seen=window_end
                )
                self.db.add(new_ap)
            else:
                existing_ap.last_seen = window_end
                if authorised and not existing_ap.approved:
                    existing_ap.approved = True
                if ap_info.get("ssid") and not existing_ap.ssid:
                    existing_ap.ssid = ap_info.get("ssid")
                if ap_info.get("channel"):
                    existing_ap.channel = ap_info.get("channel")

        # Persist Device Conversations with OUI vendor lookup
        for pair, stats in convs.items():
            avg_c_rssi = (stats["rssi_sum"] / stats["rssi_count"]) if stats["rssi_count"] > 0 else None
            conv = DeviceConversation(
                capture_session_id=capture_session_id,
                window_id=window.id,
                mac_a=stats["mac_a"],
                mac_b=stats["mac_b"],
                bssid=stats["bssid"],
                channel=stats["channel"],
                packets=stats["packets"],
                bytes=stats["bytes"],
                packets_per_second=round(stats["packets"] / duration, 2),
                avg_rssi_dbm=round(avg_c_rssi, 1) if avg_c_rssi is not None else None,
                first_seen=window_start,
                last_seen=window_end,
                vendor_a=lookup_oui(stats["mac_a"]),
                vendor_b=lookup_oui(stats["mac_b"])
            )
            self.db.add(conv)

        # Sample and persist up to 50 raw frames into wifi_frames table
        sample_step = max(1, len(packets) // 50) if packets else 1
        for idx, p in enumerate(packets):
            if idx % sample_step == 0:
                ftype = p.get("fc_type")
                subtype = p.get("fc_subtype")
                is_flagged = (subtype in (10, 12) and deauth_frames > 20)
                frame_rec = WifiFrame(
                    capture_session_id=capture_session_id,
                    window_id=window.id,
                    frame_time=window_start + timedelta(seconds=p.get("delta_time", 0.0)),
                    delta_time=p.get("delta_time"),
                    transmitter_mac=p.get("transmitter_mac"),
                    receiver_mac=p.get("receiver_mac"),
                    bssid=p.get("bssid"),
                    frame_type=str(ftype) if ftype is not None else "Management",
                    frame_subtype=str(subtype) if subtype is not None else "Unknown",
                    rssi_dbm=p.get("rssi"),
                    channel=p.get("channel"),
                    frame_length=p.get("length"),
                    ssid=p.get("ssid"),
                    reason_code=p.get("reason_code"),
                    flagged=is_flagged
                )
                self.db.add(frame_rec)

        # Detect Wireless Attacks
        findings = self._detect_wireless_attacks(
            window=window,
            packets=packets,
            seen_aps=seen_aps,
            deauth_count=deauth_frames,
            beacon_count=beacon_frames,
            probe_count=probe_frames,
            auth_count=auth_frames,
            anomaly_score=anomaly_score,
            pps=pps,
            baseline_pps=baseline_pps
        )
        window.findings_count = len(findings)

        return window

    def _update_baseline(self, dow: int, hod: int, pps: float, deauth_rate: float):
        """Updates rolling baseline stats for the current day of week and hour."""
        stat = self.db.query(BaselineStat).filter_by(day_of_week=dow, hour_of_day=hod).first()
        if not stat:
            stat = BaselineStat(
                day_of_week=dow,
                hour_of_day=hod,
                avg_pps=pps,
                std_pps=pps * 0.2,
                avg_deauth_rate=deauth_rate,
                samples=1,
                updated_at=datetime.utcnow()
            )
            self.db.add(stat)
        else:
            n = stat.samples
            new_n = n + 1
            new_avg = ((stat.avg_pps or 0.0) * n + pps) / new_n
            stat.avg_pps = new_avg
            stat.avg_deauth_rate = (((stat.avg_deauth_rate or 0.0) * n) + deauth_rate) / new_n
            stat.samples = new_n
            stat.updated_at = datetime.utcnow()

    def _detect_wireless_attacks(
        self, window: LiveCaptureWindow, packets: List[Dict[str, Any]], 
        seen_aps: Dict[str, Dict[str, Any]], deauth_count: int, beacon_count: int, 
        probe_count: int, auth_count: int, anomaly_score: float, pps: float, baseline_pps: float
    ) -> List[LiveFinding]:
        findings = []

        # 1. Deauthentication / Disassociation Flood
        deauth_thresh = self.w_rules.get("deauth_flood", {}).get("frame_threshold", 30)
        if deauth_count >= deauth_thresh:
            src_counts: Dict[str, int] = {}
            target_counts: Dict[str, int] = {}
            for p in packets:
                if p.get("fc_type") == 0 and p.get("fc_subtype") in (10, 12):
                    tx = p.get("transmitter_mac")
                    rx = p.get("receiver_mac")
                    if tx:
                        src_counts[tx.lower()] = src_counts.get(tx.lower(), 0) + 1
                    if rx:
                        target_counts[rx.lower()] = target_counts.get(rx.lower(), 0) + 1

            top_src = max(src_counts, key=src_counts.get) if src_counts else "Unknown"
            top_tgt = max(target_counts, key=target_counts.get) if target_counts else "Broadcast"
            src_name = f"{top_src} ({lookup_oui(top_src)})"
            evidence = (
                f"Abnormal burst of {deauth_count} deauthentication/disassociation frames observed within 10s "
                f"(threshold: {deauth_thresh}). Top transmitter {src_name} directed {src_counts.get(top_src, 0)} eviction frames at {top_tgt}."
            )
            findings.append(self._create_finding_and_alert(
                window=window,
                threat_type="Deauthentication Flood",
                severity="High",
                source_mac=top_src,
                target_mac=top_tgt,
                confidence=0.96,
                evidence=evidence,
                action="Deploy RF directional sensor or isolate client MAC; verify physical proximity on campus."
            ))

        # 2. Beacon Flood
        beacon_thresh = self.w_rules.get("beacon_flood", {}).get("frame_threshold", 80)
        if beacon_count >= beacon_thresh:
            evidence = f"High-frequency beacon frame density ({beacon_count} beacons/10s, threshold: {beacon_thresh}) indicating potential Wi-Fi fake SSID spamming."
            findings.append(self._create_finding_and_alert(
                window=window,
                threat_type="Beacon Flood",
                severity="Medium",
                confidence=0.91,
                evidence=evidence,
                action="Inspect nearby transmitters for ESP8266/ESP32 Wi-Fi deauthers or automated beacon generators."
            ))

        # 3. Probe Request Flood
        probe_thresh = self.w_rules.get("probe_flood", {}).get("frame_threshold", 50)
        if probe_count >= probe_thresh:
            evidence = f"Volumetric probe request surge ({probe_count} probes in 10s window) targeting SSID mapping and network enumeration."
            findings.append(self._create_finding_and_alert(
                window=window,
                threat_type="Probe Request Flood",
                severity="Medium",
                confidence=0.88,
                evidence=evidence,
                action="Monitor channel occupancy and track client MAC probing patterns."
            ))

        # 4. Authentication Flood
        auth_thresh = self.w_rules.get("auth_flood", {}).get("frame_threshold", 25)
        if auth_count >= auth_thresh:
            evidence = f"Rapid authentication attempts ({auth_count} frames in 10s window) exhausting access point association tables."
            findings.append(self._create_finding_and_alert(
                window=window,
                threat_type="Authentication Flood",
                severity="High",
                confidence=0.94,
                evidence=evidence,
                action="Enable AP association throttling and review AP system CPU/memory load."
            ))

        # 5. Rogue AP / Evil Twin Heuristic
        # Campus AP register: rows approved in the database plus config/rules.yaml entries
        approved_aps = {ap.bssid.lower(): ap for ap in self.db.query(WifiAccessPoint).filter_by(approved=True).all()}
        known_ssids = {ap.ssid.lower(): ap for ap in approved_aps.values() if ap.ssid}

        for bssid, info in seen_aps.items():
            ssid = info.get("ssid")
            ch = info.get("channel")
            if ssid and ssid.lower() in known_ssids:
                legit_ap = known_ssids[ssid.lower()]
                if bssid != legit_ap.bssid.lower():
                    # Evil Twin heuristic: known approved SSID broadcast from an unapproved BSSID
                    evidence = (
                        f"Heuristic estimate: Campus SSID '{ssid}' detected broadcasting from unapproved BSSID {bssid} "
                        f"on Channel {ch} (Legitimate campus BSSID is {legit_ap.bssid} on Ch {legit_ap.channel}). "
                        f"Note: Evil Twin is a heuristic estimate, not a confirmed attack."
                    )
                    findings.append(self._create_finding_and_alert(
                        window=window,
                        threat_type="Evil Twin",
                        severity="High",
                        bssid=bssid,
                        source_mac=bssid,
                        channel=ch,
                        confidence=0.89,
                        evidence=evidence,
                        action="Perform physical campus RF triangulation to locate rogue transmitter and confirm authorization."
                    ))
            elif approved_aps and bssid not in approved_aps and info.get("beacon_count", 0) > 5:
                # Unapproved standalone AP, judged only once a campus register exists
                evidence = f"Access point {bssid} (SSID: '{ssid or 'Hidden'}') detected active on Channel {ch}, outside the approved campus register."
                findings.append(self._create_finding_and_alert(
                    window=window,
                    threat_type="Unapproved Access Point",
                    severity="Medium",
                    bssid=bssid,
                    source_mac=bssid,
                    channel=ch,
                    confidence=0.82,
                    evidence=evidence,
                    action="Analyst to review device ownership; authorised campus hardware is registered under wireless.approved_access_points in config/rules.yaml."
                ))

        # 6. Baseline Statistical Traffic Spike
        # A spike alone proves little, so the documented severity engine judges it from
        # the measured deviation, exactly as the IP-flow parameters judge a wire spike.
        if anomaly_score >= self.anomaly_z_threshold and not findings:
            exceedance = anomaly_score / max(self.anomaly_z_threshold, 0.1)
            confidence = round(min(0.97, 0.75 + 0.05 * max(exceedance, 1.0)), 3)
            severity, _, _ = self.severity_engine.evaluate_severity(
                attack_type="Traffic Spike Anomaly",
                ml_class="Suspicious",
                confidence_score=confidence
            )
            evidence = (
                f"Traffic velocity ({pps:.1f} pkts/s) exceeds historical baseline ({baseline_pps:.1f} pkts/s) "
                f"with anomaly deviation score {anomaly_score:.2f} against the documented "
                f"z-score parameter of {self.anomaly_z_threshold:.1f}. "
                f"Note: A traffic spike alone does not prove an attack; flagged for operational triage."
            )
            findings.append(self._create_finding_and_alert(
                window=window,
                threat_type="Traffic Spike Anomaly",
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                action="Correlate with campus schedule (lectures, exams) to determine if volumetric spike is benign."
            ))

        return findings

    def _create_finding_and_alert(
        self, window: LiveCaptureWindow, threat_type: str, severity: str,
        source_mac: Optional[str] = None, target_mac: Optional[str] = None,
        bssid: Optional[str] = None, channel: Optional[int] = None,
        confidence: float = 0.85, evidence: str = "", action: str = ""
    ) -> LiveFinding:
        finding_id = f"WF-{secrets.token_hex(4).upper()}"
        now = datetime.utcnow()

        finding = LiveFinding(
            finding_id=finding_id,
            window_id=window.id,
            capture_session_id=window.capture_session_id,
            found_at=now,
            finding_type=threat_type,
            severity=severity,
            source_mac=source_mac,
            target_mac=target_mac,
            bssid=bssid,
            channel=channel,
            packets_in_window=window.frames_count,
            packets_per_second=window.packets_per_second,
            confidence_score=confidence,
            detection_method="Wireless Heuristics",
            evidence=evidence,
            recommended_action=action,
            status="Pending review"
        )
        self.db.add(finding)
        self.db.flush()

        # Mirror the finding to the shared events table for the threat register and reports
        event_payload = {
            "event_id": f"THR-{secrets.token_hex(4).upper()}",
            "detection_time": now,
            "attack_type": threat_type,
            "ml_class": "Suspicious",
            "source_ip": source_mac or "Wireless Airspace",
            "destination_ip": target_mac or bssid or "Broadcast",
            "protocol": "802.11",
            "source_port": 0,
            "destination_port": 0,
            "traffic_stats": json.dumps({
                "total_packets": window.frames_count,
                "packets_per_sec": window.packets_per_second,
                "management_frames": window.management_frames,
                "deauth_frames": window.deauth_frames,
            }),
            "source_mac": source_mac,
            "destination_mac": target_mac,
            "bssid": bssid,
            "channel": channel,
            "detection_method": "Wireless Heuristics",
            "severity": severity,
            "confidence_score": confidence,
            "evidence": evidence,
            "response_status": "Pending review",
            "system_response": "802.11 frame analysis flagged the airspace pattern for analyst review",
            "capture_source": LIVE_TRAFFIC_SOURCE,
            "capture_session_id": window.capture_session_id,
            "window_id": window.id,
        }
        event_payload["integrity_hash"] = compute_event_integrity_hash(event_payload)
        ev = Event(**event_payload)
        self.db.add(ev)
        self.db.flush()
        finding.event_id = ev.id

        # Generate alert if High or Critical
        if severity in ("Critical", "High", "Medium"):
            alert = Alert(
                event_id=ev.id,
                severity=severity,
                status="Active",
                message=f"{severity} alert: {threat_type} detected on wireless interface"
            )
            self.db.add(alert)

        return finding
