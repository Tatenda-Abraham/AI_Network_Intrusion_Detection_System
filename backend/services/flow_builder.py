"""
AI-NIDS Bidirectional Flow Aggregation Builder
Chinhoyi University of Technology - Group 5
Aggregates raw packet streams into bidirectional flows (5-tuple + time window)
and computes the 34 live-computable flow features matching cic.csv.
Monitors and logs preprocessing latency (target < 50 ms).
"""

import time
import numpy as np
from typing import Dict, List, Tuple, Any


class FlowBuilder:
    def __init__(self, flow_timeout_seconds: float = 15.0):
        self.flow_timeout_seconds = flow_timeout_seconds

    def build_flows_from_packets(self, packets: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any], float]:
        """
        Aggregates packet records into bidirectional flows and window summary structures.
        Returns:
            - flows: list of flow feature dictionaries ready for ML & rule evaluation
            - window_summary: multi-flow metadata for port scan and DDoS heuristics
            - latency_ms: elapsed preprocessing time in milliseconds
        """
        t0 = time.time()
        if not packets:
            return [], {}, 0.0

        # Group packets by bidirectional 5-tuple
        flow_groups: Dict[Tuple, List[Dict[str, Any]]] = {}
        for pkt in packets:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            # ARP, LLDP and other non-IP frames have no flow endpoints to classify
            if not src_ip or not dst_ip:
                continue
            src_port = pkt.get("src_port", 0)
            dst_port = pkt.get("dst_port", 0)
            proto = pkt.get("protocol", 6)

            # Bidirectional canonical key
            if (src_ip, src_port) <= (dst_ip, dst_port):
                key = (src_ip, src_port, dst_ip, dst_port, proto)
            else:
                key = (dst_ip, dst_port, src_ip, src_port, proto)

            if key not in flow_groups:
                flow_groups[key] = []
            flow_groups[key].append(pkt)

        flows = []
        source_to_ports: Dict[str, Dict[str, Any]] = {}
        dst_to_sources: Dict[str, Dict[str, Any]] = {}

        min_time = float("inf")
        max_time = float("-inf")

        for key, pkt_list in flow_groups.items():
            # Sort packets chronologically
            pkt_list.sort(key=lambda x: x["timestamp"])
            fwd_ip = pkt_list[0]["src_ip"]
            fwd_port = pkt_list[0]["src_port"]
            bwd_ip = pkt_list[0]["dst_ip"]
            bwd_port = pkt_list[0]["dst_port"]
            protocol = pkt_list[0]["protocol"]

            first_epoch = pkt_list[0]["timestamp"]
            last_epoch = pkt_list[-1]["timestamp"]
            min_time = min(min_time, first_epoch)
            max_time = max(max_time, last_epoch)

            # Duration in microseconds
            duration_us = max(int((last_epoch - first_epoch) * 1e6), 1)
            duration_s = max(duration_us / 1e6, 0.000001)

            fwd_pkts = [p for p in pkt_list if p["src_ip"] == fwd_ip]
            bwd_pkts = [p for p in pkt_list if p["src_ip"] != fwd_ip]

            tot_fwd_pkts = len(fwd_pkts)
            tot_bwd_pkts = len(bwd_pkts)
            tot_pkts = tot_fwd_pkts + tot_bwd_pkts

            fwd_lengths = [p["length"] for p in fwd_pkts] if fwd_pkts else [0]
            bwd_lengths = [p["length"] for p in bwd_pkts] if bwd_pkts else [0]
            all_lengths = [p["length"] for p in pkt_list]

            tot_len_fwd = sum(fwd_lengths)
            tot_len_bwd = sum(bwd_lengths)
            tot_bytes = tot_len_fwd + tot_len_bwd

            flow_byts_s = float(tot_bytes / duration_s)
            flow_pkts_s = float(tot_pkts / duration_s)

            # Inter-Arrival Times (IAT) in microseconds
            all_iats = [
                (pkt_list[i]["timestamp"] - pkt_list[i - 1]["timestamp"]) * 1e6
                for i in range(1, len(pkt_list))
            ] if len(pkt_list) > 1 else [0.0]

            fwd_iats = [
                (fwd_pkts[i]["timestamp"] - fwd_pkts[i - 1]["timestamp"]) * 1e6
                for i in range(1, len(fwd_pkts))
            ] if len(fwd_pkts) > 1 else [0.0]

            bwd_iats = [
                (bwd_pkts[i]["timestamp"] - bwd_pkts[i - 1]["timestamp"]) * 1e6
                for i in range(1, len(bwd_pkts))
            ] if len(bwd_pkts) > 1 else [0.0]

            # Flag counts
            syn_cnt = sum(p.get("syn", 0) for p in pkt_list)
            ack_cnt = sum(p.get("ack", 0) for p in pkt_list)
            rst_cnt = sum(p.get("rst", 0) for p in pkt_list)
            fin_cnt = sum(p.get("fin", 0) for p in pkt_list)
            psh_cnt = sum(p.get("psh", 0) for p in pkt_list)

            down_up_ratio = float(tot_bwd_pkts / max(tot_fwd_pkts, 1))
            pkt_size_avg = float(np.mean(all_lengths))

            flow_dict = {
                # Identification metadata
                "src_ip": fwd_ip,
                "dst_ip": bwd_ip,
                "src_port": fwd_port,
                "dst_port": bwd_port,
                "protocol_name": "TCP" if protocol == 6 else ("UDP" if protocol == 17 else "OTHER"),
                "timestamp": first_epoch,

                # 34 Live-Computable Features
                "Dst Port": float(bwd_port),
                "Protocol": float(protocol),
                "Flow Duration": float(duration_us),
                "Tot Fwd Pkts": float(tot_fwd_pkts),
                "Tot Bwd Pkts": float(tot_bwd_pkts),
                "TotLen Fwd Pkts": float(tot_len_fwd),
                "TotLen Bwd Pkts": float(tot_len_bwd),
                "Fwd Pkt Len Max": float(np.max(fwd_lengths)),
                "Fwd Pkt Len Min": float(np.min(fwd_lengths)),
                "Fwd Pkt Len Mean": float(np.mean(fwd_lengths)),
                "Fwd Pkt Len Std": float(np.std(fwd_lengths)),
                "Bwd Pkt Len Max": float(np.max(bwd_lengths)),
                "Bwd Pkt Len Min": float(np.min(bwd_lengths)),
                "Bwd Pkt Len Mean": float(np.mean(bwd_lengths)),
                "Bwd Pkt Len Std": float(np.std(bwd_lengths)),
                "Flow Byts/s": float(flow_byts_s),
                "Flow Pkts/s": float(flow_pkts_s),
                "Flow IAT Mean": float(np.mean(all_iats)),
                "Flow IAT Std": float(np.std(all_iats)),
                "Flow IAT Max": float(np.max(all_iats)),
                "Flow IAT Min": float(np.min(all_iats)),
                "Fwd IAT Mean": float(np.mean(fwd_iats)),
                "Bwd IAT Mean": float(np.mean(bwd_iats)),
                "Pkt Len Min": float(np.min(all_lengths)),
                "Pkt Len Max": float(np.max(all_lengths)),
                "Pkt Len Mean": float(np.mean(all_lengths)),
                "Pkt Len Std": float(np.std(all_lengths)),
                "FIN Flag Cnt": float(fin_cnt),
                "SYN Flag Cnt": float(syn_cnt),
                "RST Flag Cnt": float(rst_cnt),
                "PSH Flag Cnt": float(psh_cnt),
                "ACK Flag Cnt": float(ack_cnt),
                "Down/Up Ratio": float(down_up_ratio),
                "Pkt Size Avg": float(pkt_size_avg),

                # Aggregate stats for evidence
                "traffic_stats": {
                    "total_packets": tot_pkts,
                    "total_bytes": tot_bytes,
                    "duration_seconds": round(duration_s, 4),
                    "packets_per_sec": round(flow_pkts_s, 2),
                    "bytes_per_sec": round(flow_byts_s, 2),
                    "syn_flags": syn_cnt,
                    "ack_flags": ack_cnt,
                    "rst_flags": rst_cnt
                }
            }
            flows.append(flow_dict)

            # Window Aggregation for Port Scanning
            if fwd_ip not in source_to_ports:
                source_to_ports[fwd_ip] = {
                    "distinct_ports": set(),
                    "target_ip": bwd_ip,
                    "syn_count": 0,
                    "ack_count": 0
                }
            source_to_ports[fwd_ip]["distinct_ports"].add(bwd_port)
            source_to_ports[fwd_ip]["syn_count"] += syn_cnt
            source_to_ports[fwd_ip]["ack_count"] += ack_cnt

            # Window Aggregation for DDoS
            if bwd_ip not in dst_to_sources:
                dst_to_sources[bwd_ip] = {
                    "sources": set(),
                    "total_pkts": 0,
                    "port_sources": {},
                    "port_pkts": {},
                    "port_span": {}
                }
            dst_to_sources[bwd_ip]["sources"].add(fwd_ip)
            dst_to_sources[bwd_ip]["total_pkts"] += tot_pkts
            # A flood is many hosts converging on one service, so keep the per-port view
            dst_to_sources[bwd_ip]["port_sources"].setdefault(bwd_port, set()).add(fwd_ip)
            dst_to_sources[bwd_ip]["port_pkts"][bwd_port] = \
                dst_to_sources[bwd_ip]["port_pkts"].get(bwd_port, 0) + tot_pkts
            span = dst_to_sources[bwd_ip]["port_span"].setdefault(bwd_port, [first_epoch, last_epoch])
            span[0] = min(span[0], first_epoch)
            span[1] = max(span[1], last_epoch)

        window_duration = max(max_time - min_time, 1.0) if max_time >= min_time else 5.0

        # Serialize sets for window summary
        serialized_ports = {
            src: {
                "distinct_ports": sorted(list(data["distinct_ports"])),
                "target_ip": data["target_ip"],
                "syn_count": data["syn_count"],
                "ack_count": data["ack_count"]
            }
            for src, data in source_to_ports.items()
        }

        serialized_dsts = {
            dst: {
                "sources": sorted(list(data["sources"])),
                "total_packets": data["total_pkts"],
                # Measured across the whole window so a target's rate cannot be
                # inflated by one short-lived flow that opened the group.
                "aggregate_pps": data["total_pkts"] / max(window_duration, 0.1),
                # A flood is many hosts converging on one service, so the per-port
                # fan-in is kept: an ordinary host answering on its own ephemeral
                # ports is not one.
                "by_port": {
                    port: {
                        "sources": sorted(port_srcs),
                        "packets": data["port_pkts"][port],
                        "duration_seconds": round(
                            max(data["port_span"][port][1] - data["port_span"][port][0], 0.000001), 4
                        ),
                    }
                    for port, port_srcs in data["port_sources"].items()
                },
            }
            for dst, data in dst_to_sources.items()
        }

        window_summary = {
            "window_duration_seconds": round(window_duration, 2),
            "source_to_distinct_dst_ports": serialized_ports,
            "dst_to_sources": serialized_dsts,
            "flow_count": len(flows),
            "packet_count": len(packets)
        }

        latency_ms = (time.time() - t0) * 1000.0
        return flows, window_summary, latency_ms
