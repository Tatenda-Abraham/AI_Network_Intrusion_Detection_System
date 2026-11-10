"""
AI-NIDS Live Capture & Traffic Analysis Service
Chinhoyi University of Technology - Group 5
Orchestrates the monitoring pipeline for the Wireshark/TShark front end:
1. Capture on the active network adapter in sliding analysis windows (live_window_seconds)
2. 802.11 / IP frame analysis and wireless attack detection (WirelessAnalyzer)
3. Flow aggregation and Random Forest classification of live traffic (FlowClassifier)
4. Automatic adapter fallback and TShark restart with backoff
"""

import os
import time
import uuid
import threading
import subprocess
import yaml
from collections import deque
from datetime import datetime
from typing import Dict, List, Any, Optional

from backend.config import LIVE_TRAFFIC_SOURCE
from backend.services.analysis_totals import refresh_analysis_totals
from backend.services.tshark_parser import TSharkParser
from backend.services.wireless_analyzer import WirelessAnalyzer
from backend.models import CaptureSession, Setting, LiveCaptureWindow

# Consecutive empty windows on the chosen adapter before looking for another one
EMPTY_WINDOW_SWITCH_THRESHOLD = 3


class CaptureService:
    def __init__(self, db_session_factory, alert_queue=None):
        self.db_session_factory = db_session_factory
        self.alert_queue = alert_queue
        self.tshark_parser = TSharkParser()

        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_requested = threading.Event()
        self.active_session_db_id: Optional[int] = None
        self.active_session_identifier: Optional[str] = None
        self.capture_start_timestamp: Optional[float] = None
        self.flow_classifier = None

        self.status = {
            "state": "STOPPED",
            "is_capturing": False,
            "adapter": None,
            "friendly_name": None,
            "device": None,
            "selection_method": None,
            "channel": "Auto",
            "packets_per_second": 0.0,
            "total_packets": 0,
            "total_flows": 0,
            "total_events": 0,
            "total_alerts": 0,
            "dropped_frames": 0,
            "restart_count": 0,
            "last_error": None,
            "window_seconds": 10,
            "last_window_time": None,
            "last_window_latency_ms": None,
            "last_flows_in_window": 0,
            "last_preprocessing_ms_per_flow": None,
            "last_inference_ms_per_flow": None,
            "started_at": None,
        }

        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, Any]:
        try:
            rules_path = os.path.join(os.getcwd(), "config", "rules.yaml")
            if os.path.exists(rules_path):
                with open(rules_path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[!] Warning reading rules.yaml: {e}")
        return {}

    def get_status(self) -> Dict[str, Any]:
        return self.status

    def close_abandoned_sessions(self) -> int:
        """Records capture sessions owned by a process that no longer exists.

        Only this service writes capture_sessions, so a row still marked Running when the
        application starts is the residue of an earlier run that ended without stopping the
        monitor. Leaving it Running would make the database claim a capture that is not happening.
        """
        db = self.db_session_factory()
        try:
            stale = db.query(CaptureSession).filter(
                CaptureSession.status == "Running").all()
            for sess in stale:
                sess.status = "Interrupted"
                sess.ended_at = sess.ended_at or datetime.utcnow()
                sess.last_error = "Backend process ended before the capture was stopped"
            db.commit()
            return len(stale)
        except Exception as e:
            db.rollback()
            print(f"[!] Could not close abandoned capture sessions: {e}")
            return 0
        finally:
            db.close()

    def _get_window_seconds(self) -> int:
        db = self.db_session_factory()
        try:
            s = db.query(Setting).filter(Setting.key == "live_window_seconds").first()
            if s and s.value:
                return max(2, int(s.value))
        except Exception:
            pass
        finally:
            db.close()
        return 10

    def _get_classifier(self):
        """Loads the model on first use so application start-up stays fast."""
        if self.flow_classifier is None:
            from backend.services.flow_classifier import FlowClassifier
            self.flow_classifier = FlowClassifier()
        return self.flow_classifier

    def start_live_capture(
        self,
        interface_id: Optional[str] = None,
        adapter_friendly_name: Optional[str] = None,
        device_name: Optional[str] = None,
        monitor_mode: bool = False,
        channel: Optional[int] = None,
        started_by: str = "Administrator"
    ) -> Dict[str, Any]:
        """
        Begins continuous capture. With no interface supplied the adapter that owns
        the default route is selected automatically, so monitoring never needs setup.
        """
        if self.is_capturing:
            return {"status": "success", "message": "Live capture is already running",
                    "already_running": True, "adapter": self.status.get("friendly_name")}

        if not self.tshark_parser.is_available:
            return {"status": "error",
                    "message": f"Capture engine unavailable: {self.tshark_parser.status_message}"}

        iface: Dict[str, Any] = {}
        selection_method = "selected"
        if not interface_id or str(interface_id).lower() in ("auto", "default", "0"):
            picked = self.tshark_parser.select_primary_interface()
            if not picked:
                return {"status": "error", "message": "No capture interface could be found"}
            iface = picked
            selection_method = "active adapter"
        else:
            for candidate in self.tshark_parser.list_interfaces():
                if interface_id in (candidate["device"], candidate["friendly_name"], candidate["index"]):
                    iface = candidate
                    break

        interface_id = iface.get("device") or interface_id
        friendly = adapter_friendly_name or iface.get("friendly_name") or f"Interface {interface_id}"
        dev = device_name or iface.get("device") or str(interface_id)

        window_sec = self._get_window_seconds()

        db = self.db_session_factory()
        try:
            session_id = f"CAP-{int(time.time())}"
            new_session = CaptureSession(
                session_identifier=session_id,
                interface_name=dev,
                adapter_friendly_name=friendly,
                capture_type="Live Capture",
                monitor_mode=monitor_mode,
                channel=channel,
                window_seconds=window_sec,
                started_by=started_by,
                status="Running",
                started_at=datetime.utcnow()
            )
            db.add(new_session)
            db.commit()
            self.active_session_db_id = new_session.id
            self.active_session_identifier = session_id
        except Exception as e:
            db.rollback()
            return {"status": "error", "message": f"Failed to record capture session: {str(e)}"}
        finally:
            db.close()

        self.is_capturing = True
        self.stop_requested.clear()
        self.capture_start_timestamp = time.time()

        self.status.update({
            "state": "CAPTURING",
            "is_capturing": True,
            "adapter": interface_id,
            "friendly_name": friendly,
            "device": dev,
            "selection_method": selection_method,
            "channel": channel if channel else "Auto",
            "packets_per_second": 0.0,
            "total_packets": 0,
            "total_flows": 0,
            "total_events": 0,
            "total_alerts": 0,
            "restart_count": 0,
            "last_error": None,
            "window_seconds": window_sec,
            "started_at": datetime.utcnow().isoformat(),
        })

        self.capture_thread = threading.Thread(
            target=self._capture_worker_loop,
            args=(interface_id, friendly, monitor_mode, channel),
            daemon=True,
            name="LiveCaptureWorker"
        )
        self.capture_thread.start()

        return {
            "status": "success",
            "message": f"Live capture started on {friendly}",
            "session_id": session_id,
            "adapter": friendly,
            "interface_id": interface_id,
            "selection_method": selection_method,
        }

    def stop_live_capture(self) -> Dict[str, Any]:
        if not self.is_capturing:
            return {"status": "success", "message": "Live capture is not running", "already_stopped": True}

        self.stop_requested.set()
        self.is_capturing = False

        db = self.db_session_factory()
        try:
            if self.active_session_db_id:
                sess = db.query(CaptureSession).get(self.active_session_db_id)
                if sess:
                    sess.status = "Completed"
                    sess.ended_at = datetime.utcnow()
                    sess.packets_captured = self.status.get("total_packets", 0)
                    sess.total_frames = self.status.get("total_packets", 0)
                    sess.flows_analyzed = self.status.get("total_flows", 0)
                    sess.events_stored = self.status.get("total_events", 0)
                    sess.alerts_raised = self.status.get("total_alerts", 0)
                    db.commit()
            refresh_analysis_totals(db, LIVE_TRAFFIC_SOURCE)
        except Exception as e:
            db.rollback()
            print(f"[!] Error updating ended capture session: {e}")
        finally:
            db.close()

        self.status["state"] = "STOPPED"
        self.status["is_capturing"] = False
        return {"status": "success",
                "message": f"Live capture stopped after {self.status.get('total_packets', 0)} packets"}

    def _capture_worker_loop(self, interface_id: str, friendly: str,
                             monitor_mode: bool, channel: Optional[int]):
        """Continuous background capture with automatic adapter fallback and restart backoff."""
        restart_backoffs = [2, 5, 10, 15, 20]
        retry_count = 0
        current = (interface_id, friendly)

        while not self.stop_requested.is_set():
            try:
                current = self._run_capture_session(current, monitor_mode, channel)
                retry_count = 0
                if self.stop_requested.is_set():
                    break
            except Exception as e:
                if self.stop_requested.is_set():
                    break
                retry_count += 1
                self.status["state"] = "RESTARTING"
                self.status["restart_count"] = retry_count
                self.status["last_error"] = str(e)
                print(f"[!] TShark worker exception (attempt {retry_count}): {e}")
                self._record_session_error(retry_count, str(e))

                if retry_count > 5:
                    print("[!] Max 5 capture restarts reached. Worker halted.")
                    self.status["state"] = "STOPPED"
                    self.is_capturing = False
                    break

                backoff = restart_backoffs[min(retry_count - 1, len(restart_backoffs) - 1)]
                time.sleep(backoff)

    def _record_session_error(self, retry_count: int, message: str):
        db = self.db_session_factory()
        try:
            if self.active_session_db_id:
                sess = db.query(CaptureSession).get(self.active_session_db_id)
                if sess:
                    sess.restart_count = retry_count
                    sess.last_error = message
                    db.commit()
        except Exception:
            pass
        finally:
            db.close()

    def _run_capture_session(self, current, monitor_mode: bool, channel: Optional[int]):
        """Runs capture windows on one adapter; switches adapter when it carries no traffic."""
        interface_id, friendly = current
        empty_windows = 0

        while not self.stop_requested.is_set():
            window_sec = self._get_window_seconds()
            self.status["window_seconds"] = window_sec
            start_time = datetime.utcnow()
            packets = self._capture_packet_file(interface_id, friendly, window_sec, monitor_mode, channel)
            end_time = datetime.utcnow()

            if packets:
                empty_windows = 0
                self._process_window_file(packets, start_time, end_time, interface_id, friendly)
            else:
                self.status["packets_per_second"] = 0.0
                empty_windows += 1
                if empty_windows >= EMPTY_WINDOW_SWITCH_THRESHOLD:
                    alternative = self._find_alternative_adapter(interface_id)
                    if alternative:
                        print(f"[LIVE] No traffic on {friendly}; switching to {alternative['friendly_name']}")
                        self.status["friendly_name"] = alternative["friendly_name"]
                        self.status["adapter"] = alternative["device"]
                        self.status["device"] = alternative["device"]
                        self.status["selection_method"] = "failover adapter"
                        self.status["total_packets"] = 0
                        empty_windows = 0
                        return (alternative["device"], alternative["friendly_name"])
        return (interface_id, friendly)

    def _find_alternative_adapter(self, exclude_device: str) -> Optional[Dict[str, Any]]:
        """Probes the other physical adapters for live traffic."""
        for candidate in self.tshark_parser.list_interfaces():
            if candidate["device"] == exclude_device or candidate.get("is_virtual"):
                continue
            probe = self.tshark_parser.test_adapter(candidate["device"], duration=2)
            if probe.get("packet_count", 0) > 0:
                return candidate
        return None

    def _capture_packet_file(self, interface_id: str, friendly: str, window_sec: int,
                             monitor_mode: bool, channel: Optional[int]) -> List[Dict[str, Any]]:
        """Captures one window to a temporary file and returns the dissected packets."""
        temp_pcap = os.path.join(os.getcwd(), "uploads", f"live_win_{uuid.uuid4().hex[:8]}.pcapng")
        os.makedirs(os.path.dirname(temp_pcap), exist_ok=True)

        tshark_cmd = [
            self.tshark_parser.tshark_path,
            "-i", str(interface_id),
            "-a", f"duration:{window_sec}",
            "-w", temp_pcap,
        ]
        if monitor_mode:
            tshark_cmd.append("-I")

        try:
            proc = subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True, encoding="utf-8", errors="replace")
            stderr_tail: deque = deque(maxlen=12)
            drainer = threading.Thread(
                target=lambda: [stderr_tail.append(line) for line in proc.stderr],
                daemon=True, name="TSharkStderr"
            )
            drainer.start()

            deadline = time.time() + window_sec + 6
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                if self.stop_requested.is_set():
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        proc.kill()
                    return []
                time.sleep(0.5)

            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            drainer.join(timeout=1)

            if stderr_tail and proc.returncode not in (0, None):
                self.status["last_error"] = " ".join(stderr_tail)[-300:]

            if os.path.exists(temp_pcap) and os.path.getsize(temp_pcap) > 24:
                packets = self.tshark_parser.parse_pcap_file(temp_pcap, is_wireless=True)
                if not packets and self.tshark_parser.last_dissection_error:
                    self.status["last_error"] = self.tshark_parser.last_dissection_error
                elif packets:
                    self.status["last_error"] = None
                return packets
            return []
        finally:
            if os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except Exception:
                    pass

    def _process_window_file(self, packets: List[Dict[str, Any]], start_time: datetime,
                             end_time: datetime, interface_id: str, friendly: str):
        """Dissects, aggregates, classifies and persists one analysis window."""
        t0 = time.time()
        db = self.db_session_factory()
        try:
            analyzer = WirelessAnalyzer(db, self.rules)
            window = analyzer.analyze_window(
                capture_session_id=self.active_session_db_id or 1,
                packets=packets,
                window_start=start_time,
                window_end=end_time
            )
            window.processing_ms = round((time.time() - t0) * 1000.0, 2)
            db.commit()

            # Separate transaction: a classification failure must not lose the captured window
            try:
                classification = self._get_classifier().classify_window(
                    db=db,
                    packets=packets,
                    window_start=start_time,
                    window_end=end_time,
                    capture_session_id=self.active_session_db_id,
                    window_id=window.id,
                    adapter_label=friendly,
                )
                db.commit()
            except Exception as e:
                db.rollback()
                classification = {"flows_detected": 0, "flows_classified": 0,
                                  "events_created": 0, "alerts_created": 0, "attacks_found": 0}
                self.status["last_error"] = f"flow classification: {str(e)[:200]}"
                print(f"[!] Live flow classification error: {e}")

            proc_ms = (time.time() - t0) * 1000.0
            window.processing_ms = round(proc_ms, 2)
            duration = max((end_time - start_time).total_seconds(), 1.0)
            flows_in_window = classification["flows_detected"] or 1
            self.status["total_packets"] += len(packets)
            self.status["total_flows"] += classification["flows_detected"]
            self.status["total_events"] += classification["events_created"]
            self.status["total_alerts"] += classification["alerts_created"]
            self.status["packets_per_second"] = round(len(packets) / duration, 1)
            self.status["last_window_time"] = end_time.isoformat()
            self.status["last_window_latency_ms"] = round(proc_ms, 1)
            self.status["last_flows_in_window"] = classification["flows_detected"]
            self.status["last_preprocessing_ms_per_flow"] = round(
                classification.get("preprocessing_ms", 0.0) / flows_in_window, 3)
            self.status["last_inference_ms_per_flow"] = round(
                classification.get("inference_ms", 0.0) / flows_in_window, 3)
            if classification["attacks_found"]:
                self.status["last_attack_summary"] = (
                    f"{classification['attacks_found']} attack-classified flow(s) at "
                    f"{end_time.strftime('%H:%M:%S')} UTC"
                )

            if self.active_session_db_id:
                sess = db.query(CaptureSession).get(self.active_session_db_id)
                if sess:
                    sess.packets_captured = self.status["total_packets"]
                    sess.total_frames = self.status["total_packets"]
                    sess.total_findings = (sess.total_findings or 0) + window.findings_count
                    sess.flows_analyzed = self.status["total_flows"]
                    sess.events_stored = self.status["total_events"]
                    sess.alerts_raised = self.status["total_alerts"]
                    db.commit()

            # The dashboard reads its live headline figures from analysis_totals, so the
            # stored row follows the capture window by window rather than being invented
            # at request time.
            refresh_analysis_totals(
                db, LIVE_TRAFFIC_SOURCE,
                notes=f"Live capture on {friendly}; counters also held per session in capture_sessions.")

            print(
                f"[LIVE WINDOW] {friendly} | Packets: {len(packets)} | "
                f"Flows: {classification['flows_detected']} "
                f"(classified {classification['flows_classified']}) | "
                f"Events stored: {classification['events_created']} | "
                f"Alerts: {classification['alerts_created']} | "
                f"Wireless findings: {window.findings_count} | "
                f"Rate: {self.status['packets_per_second']} pkts/s | "
                f"Processing: {proc_ms:.1f}ms"
            )
        except Exception as e:
            db.rollback()
            self.status["last_error"] = str(e)[:300]
            print(f"[!] Live window processing error: {e}")
        finally:
            db.close()
