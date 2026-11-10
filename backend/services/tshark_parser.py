"""
AI-NIDS TShark / Wireshark Dissection Service
Chinhoyi University of Technology - Group 5
Wraps Wireshark's TShark CLI utility across Windows and Linux.
Performs:
1. Startup verification of TShark and Npcap/libpcap presence
2. Network interface enumeration and active-adapter selection
3. Adapter testing and traffic auto-detection
4. Packet dissection from pcap/pcapng files with dual 802.11/Ethernet extraction
"""

import os
import re
import csv
import io
import shutil
import socket
import platform
import subprocess
from typing import Dict, List, Tuple, Any, Optional

DEFAULT_WIN_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DEFAULT_LINUX_TSHARK = "/usr/bin/tshark"

# tcp.flags arrives as a hex mask; the boolean sub-fields are unreliable across releases
TCP_FLAG_BITS = {
    "fin": 0x01,
    "syn": 0x02,
    "rst": 0x04,
    "psh": 0x08,
    "ack": 0x10,
}

VIRTUAL_KEYWORDS = [
    "vethernet", "hyper-v", "virtualbox", "vmware", "loopback",
    "local area connection*", "bluetooth", "npcap loopback", "wan miniport",
    "etwdump", "ciscodump", "randpkt", "sshdump", "udpdump", "wsl", "tap",
]


def _flag_mask_to_bits(raw: Optional[str]) -> Dict[str, int]:
    """Decodes tshark's hex tcp.flags into the individual flag counters."""
    value = 0
    text = (raw or "").strip()
    if text:
        try:
            value = int(text, 16)
        except ValueError:
            value = 0
    return {name: 1 if value & bit else 0 for name, bit in TCP_FLAG_BITS.items()}


class TSharkParser:
    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = self._resolve_tshark_path(tshark_path)
        self.is_available, self.status_message = self.check_environment()
        self.last_dissection_error = None

    def _resolve_tshark_path(self, configured_path: Optional[str]) -> str:
        if configured_path and os.path.exists(configured_path):
            return configured_path

        env_path = os.getenv("TSHARK_PATH")
        if env_path and os.path.exists(env_path):
            return env_path

        if platform.system() == "Windows":
            if os.path.exists(DEFAULT_WIN_TSHARK):
                return DEFAULT_WIN_TSHARK
            which_tshark = shutil.which("tshark.exe")
            if which_tshark:
                return which_tshark
            return DEFAULT_WIN_TSHARK
        else:
            if os.path.exists(DEFAULT_LINUX_TSHARK):
                return DEFAULT_LINUX_TSHARK
            which_tshark = shutil.which("tshark")
            if which_tshark:
                return which_tshark
            return "tshark"

    def check_environment(self) -> Tuple[bool, str]:
        """Verifies if TShark executable and packet capture drivers (Npcap/libpcap) exist."""
        if not os.path.exists(self.tshark_path) and not shutil.which(self.tshark_path):
            return False, f"TShark executable not found at '{self.tshark_path}'. Please install Wireshark with Npcap."

        try:
            res = subprocess.run([self.tshark_path, "-v"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                first_line = res.stdout.splitlines()[0] if res.stdout else "TShark detected"
                has_npcap = "Npcap" in res.stdout or "libpcap" in res.stdout
                driver_info = "Npcap driver active" if has_npcap else "Capture driver verified"
                return True, f"{first_line} ({driver_info})"
            return False, f"TShark check failed with return code {res.returncode}: {res.stderr}"
        except Exception as e:
            return False, f"Error launching TShark check: {str(e)}"

    def list_interfaces(self) -> List[Dict[str, Any]]:
        """Parses output of `tshark -D` to return available network interfaces with virtual classification."""
        if not self.is_available:
            return []

        try:
            res = subprocess.run([self.tshark_path, "-D"], capture_output=True, text=True, timeout=8)
            interfaces = []

            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Pattern: 1. \Device\NPF_{...} (Friendly Name) OR 11. etwdump (Event Tracing...)
                match = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$", line)
                if match:
                    idx, device, desc = match.groups()
                    friendly = desc or device
                    is_virt = any(k in friendly.lower() or k in device.lower() for k in VIRTUAL_KEYWORDS)
                    interfaces.append({
                        "index": idx,
                        "device": device,
                        "friendly_name": friendly,
                        "is_virtual": is_virt,
                        "is_active": False
                    })
            return interfaces
        except Exception as e:
            print(f"[!] Error listing interfaces: {e}")
            return []

    def _default_route_local_ip(self) -> Optional[str]:
        """Local IP address the operating system uses for outbound traffic."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            return None
        finally:
            sock.close()

    def _default_route_adapter_name(self) -> Optional[str]:
        """OS name of the adapter carrying the default route."""
        try:
            if platform.system() == "Windows":
                res = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     "Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | "
                     "Select-Object -ExpandProperty InterfaceAlias"],
                    capture_output=True, text=True, timeout=15
                )
            else:
                res = subprocess.run(
                    ["sh", "-c", "ip route get 1.1.1.1 | sed -n 's/.* dev \\([^ ]+\\).*/\\1/p'"],
                    capture_output=True, text=True, timeout=15
                )
            for line in (res.stdout or "").splitlines():
                if line.strip():
                    return line.strip()
        except Exception as e:
            print(f"[!] Default route lookup failed: {e}")
        return None

    def mark_active_interfaces(self, interfaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flags the adapter that owns the default route, so capture can start without user input."""
        active_name = (self._default_route_adapter_name() or "").lower()
        for iface in interfaces:
            iface["is_active"] = bool(
                active_name
                and (
                    iface.get("friendly_name", "").lower() == active_name
                    or iface.get("device", "").lower() == active_name
                    or active_name in iface.get("friendly_name", "").lower()
                )
            )
        return interfaces

    def select_primary_interface(self) -> Optional[Dict[str, Any]]:
        """
        Chooses the interface to monitor without user input: the adapter owning the
        default route, else the first physical adapter that actually carries traffic.
        """
        interfaces = self.mark_active_interfaces(self.list_interfaces())
        if not interfaces:
            return None

        active = [i for i in interfaces if i["is_active"]]
        if active:
            return active[0]

        for iface in [i for i in interfaces if not i["is_virtual"]] + interfaces:
            probe = self.test_adapter(iface["device"], duration=2)
            if probe.get("packet_count", 0) > 0:
                return iface
        return interfaces[0]

    def test_adapter(self, interface: str, duration: int = 3) -> Dict[str, Any]:
        """Runs a short capture test on the selected interface to measure real packet flow."""
        if not self.is_available:
            return {"status": "error", "message": "TShark is not available", "packets": 0}

        try:
            cmd = [
                self.tshark_path,
                "-i", str(interface),
                "-a", f"duration:{duration}",
                "-c", "500"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 4)
            # Count packet lines in stdout
            lines = [l for l in res.stdout.splitlines() if re.match(r"^\s*\d+\s+\d+\.", l)]
            pkt_count = len(lines)
            return {
                "status": "success",
                "interface": interface,
                "duration_seconds": duration,
                "packet_count": pkt_count,
                "is_active": pkt_count > 0,
                "sample_output": lines[:3]
            }
        except subprocess.TimeoutExpired:
            return {"status": "success", "interface": interface, "packet_count": 0, "is_active": False}
        except Exception as e:
            return {"status": "error", "interface": interface, "message": str(e), "packet_count": 0}

    def parse_pcap_file(self, pcap_path: str, max_packets: int = 50000, is_wireless: bool = True) -> List[Dict[str, Any]]:
        """
        Dissects a pcap file.
        Extracts 802.11 wireless fields AND Ethernet/IP fields for unified fallback.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Pcap file not found: {pcap_path}")

        fields = [
            "frame.time_epoch",
            "frame.time_delta",
            "frame.len",
            # 802.11 fields
            "wlan.ta",
            "wlan.ra",
            "wlan.bssid",
            "wlan.fc.type",
            "wlan.fc.type_subtype",
            "radiotap.dbm_antsignal",
            "wlan_radio.channel",
            "wlan.ssid",
            "wlan.fixed.reason_code",
            # Ethernet / IP fields
            "eth.src",
            "eth.dst",
            "ip.src",
            "ip.dst",
            "ip.proto",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "tcp.flags",
        ]

        tshark_cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-T", "fields",
            "-E", "separator=/t",
            "-E", "header=y",
            "-E", "occurrence=f"
        ]

        for f in fields:
            tshark_cmd.extend(["-e", f])

        if max_packets > 0:
            tshark_cmd.extend(["-c", str(max_packets)])

        try:
            res = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=120)
            if not (res.stdout or "").strip():
                self.last_dissection_error = (res.stderr or "").strip()[:300] or (
                    f"tshark returned no fields (exit {res.returncode})"
                )
                print(f"[!] TShark dissection produced no output: {self.last_dissection_error}")
                return []
            self.last_dissection_error = None
            return self._parse_tsv_output(res.stdout)
        except Exception as e:
            self.last_dissection_error = str(e)[:300]
            print(f"[!] TShark parse error: {e}")
            return []

    def _parse_tsv_output(self, tsv_text: str) -> List[Dict[str, Any]]:
        packets = []
        reader = csv.DictReader(io.StringIO(tsv_text), delimiter="\t")

        def num(raw, cast):
            try:
                return cast(raw)
            except (TypeError, ValueError):
                return None

        for row in reader:
            try:
                # Timings & length
                ts = float(num(row.get("frame.time_epoch"), float) or 0.0)
                delta = float(num(row.get("frame.time_delta"), float) or 0.0)
                length = int(num(row.get("frame.len"), float) or 0)

                # Wireless MACs with Ethernet fallback
                tx_mac = row.get("wlan.ta") or row.get("eth.src") or "00:00:00:00:00:00"
                rx_mac = row.get("wlan.ra") or row.get("eth.dst") or "ff:ff:ff:ff:ff:ff"
                bssid = row.get("wlan.bssid") or tx_mac

                # Frame types
                fc_type = int(num(row.get("wlan.fc.type"), float)) if row.get("wlan.fc.type") else 2  # default data
                fc_subtype = int(num(row.get("wlan.fc.type_subtype"), float)) if row.get("wlan.fc.type_subtype") else 0

                # RSSI & Channel
                rssi = int(num(row.get("radiotap.dbm_antsignal"), float) or -65)
                channel = int(num(row.get("wlan.channel"), float) or 6)
                ssid = row.get("wlan.ssid") or None
                reason_code = num(row.get("wlan.fixed.reason_code"), int)

                # IP / Ports
                src_ip = row.get("ip.src") or None
                dst_ip = row.get("ip.dst") or None
                src_port = int(num(row.get("tcp.srcport"), float) or num(row.get("udp.srcport"), float) or 0)
                dst_port = int(num(row.get("tcp.dstport"), float) or num(row.get("udp.dstport"), float) or 0)
                flags = _flag_mask_to_bits(row.get("tcp.flags"))

                pkt = {
                    "timestamp": ts,
                    "delta_time": delta,
                    "length": length,
                    "transmitter_mac": tx_mac,
                    "receiver_mac": rx_mac,
                    "bssid": bssid,
                    "fc_type": fc_type,
                    "fc_subtype": fc_subtype,
                    "rssi": rssi,
                    "channel": channel,
                    "ssid": ssid,
                    "reason_code": reason_code,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": int(num(row.get("ip.proto"), float) or 0),
                    "fin": flags["fin"],
                    "syn": flags["syn"],
                    "rst": flags["rst"],
                    "psh": flags["psh"],
                    "ack": flags["ack"],
                }
                packets.append(pkt)
            except Exception:
                continue

        return packets
