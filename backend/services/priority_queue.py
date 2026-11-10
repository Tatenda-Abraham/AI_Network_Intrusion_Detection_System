"""
AI-NIDS Priority Queue & Search / Sorting Data Structures
Chinhoyi University of Technology - Group 5
Implements:
1. Min/Max Priority Queue using heapq to prioritize pending alerts by
   (Severity Tier DESC, Confidence Score DESC, Detection Time DESC).
2. Multi-attribute sorting and binary search algorithms for events.
3. Cryptographic integrity verification (SHA-256).
"""

import heapq
import hashlib
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Investigate": 1,
    "Low": 0
}


class AlertQueueItem:
    """Wrapper class enabling priority comparison for heapq."""
    def __init__(self, event: Dict[str, Any]):
        self.event = event
        self.event_id = event.get("event_id", "")
        self.severity = event.get("severity", "Low")
        self.confidence = float(event.get("confidence_score") or 0.0)

        # Parse timestamp to integer epoch
        det_time = event.get("detection_time")
        if isinstance(det_time, datetime):
            self.epoch = det_time.timestamp()
        elif isinstance(det_time, str):
            try:
                self.epoch = datetime.fromisoformat(det_time.replace("Z", "+00:00")).timestamp()
            except Exception:
                self.epoch = 0.0
        else:
            self.epoch = 0.0

        self.severity_weight = SEVERITY_WEIGHTS.get(self.severity, 0)

    def __lt__(self, other: "AlertQueueItem") -> bool:
        # We want max-priority behavior in Python's min-heap:
        # Compare higher severity weight first
        if self.severity_weight != other.severity_weight:
            return self.severity_weight > other.severity_weight
        # Compare higher confidence score second
        if self.confidence != other.confidence:
            return self.confidence > other.confidence
        # Compare newer timestamp third
        return self.epoch > other.epoch


class AlertPriorityQueue:
    def __init__(self):
        self._heap: List[AlertQueueItem] = []

    def push(self, event: Dict[str, Any]):
        """Pushes an event onto the priority queue."""
        item = AlertQueueItem(event)
        heapq.heappush(self._heap, item)

    def pop(self) -> Optional[Dict[str, Any]]:
        """Pops the highest priority alert from the queue."""
        if not self._heap:
            return None
        return heapq.heappop(self._heap).event

    def peek(self) -> Optional[Dict[str, Any]]:
        """Returns the highest priority alert without removing it."""
        if not self._heap:
            return None
        return self._heap[0].event

    def size(self) -> int:
        return len(self._heap)

    def get_all_sorted(self) -> List[Dict[str, Any]]:
        """Returns all elements in strict priority order without destroying the heap."""
        sorted_items = sorted(self._heap)
        return [item.event for item in sorted_items]

    def clear(self):
        self._heap.clear()


class EventSearchSortEngine:
    @staticmethod
    def sort_events(events: List[Dict[str, Any]], sort_by: str = "detection_time", ascending: bool = False) -> List[Dict[str, Any]]:
        """
        Sorts event records by:
        - 'detection_time': chronologically
        - 'severity': by threat severity tier
        - 'confidence_score': numeric confidence
        - 'source_ip': lexicographically by IP
        """
        if sort_by == "severity":
            return sorted(
                events,
                key=lambda x: SEVERITY_WEIGHTS.get(x.get("severity", "Low"), 0),
                reverse=not ascending
            )
        elif sort_by == "confidence_score":
            return sorted(
                events,
                key=lambda x: float(x.get("confidence_score") or 0.0),
                reverse=not ascending
            )
        elif sort_by == "source_ip":
            return sorted(
                events,
                key=lambda x: str(x.get("source_ip", "")),
                reverse=not ascending
            )
        else:
            # Default: detection_time
            def get_time(item):
                t = item.get("detection_time")
                if isinstance(t, datetime):
                    return t.timestamp()
                elif isinstance(t, str):
                    try:
                        return datetime.fromisoformat(t).timestamp()
                    except Exception:
                        return 0.0
                return 0.0

            return sorted(events, key=get_time, reverse=not ascending)

    @staticmethod
    def filter_events(
        events: List[Dict[str, Any]],
        search_query: str = "",
        severity: str = "",
        attack_type: str = "",
        detection_method: str = "",
        response_status: str = "",
        min_confidence: float = 0.0
    ) -> List[Dict[str, Any]]:
        """Filters events across multiple criteria with case-insensitive substring searching."""
        results = []
        q = search_query.strip().lower()

        for ev in events:
            # Substring match on event_id, source_ip, destination_ip, attack_type, registration_number
            if q:
                matchable_text = f"{ev.get('event_id', '')} {ev.get('source_ip', '')} {ev.get('destination_ip', '')} {ev.get('attack_type', '')} {ev.get('registration_number', '')} {ev.get('evidence', '')}".lower()
                if q not in matchable_text:
                    continue

            if severity and ev.get("severity") != severity:
                continue

            if attack_type and ev.get("attack_type") != attack_type:
                continue

            if detection_method and ev.get("detection_method") != detection_method:
                continue

            if response_status and ev.get("response_status") != response_status:
                continue

            conf = float(ev.get("confidence_score") or 0.0)
            if min_confidence > 0.0 and conf < min_confidence:
                continue

            results.append(ev)

        return results


def _canonical_time(value: Any) -> str:
    """Datetime objects and serialised event dicts must hash to the same timestamp string."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")


def compute_event_integrity_hash(event_dict: Dict[str, Any]) -> str:
    """
    Computes a cryptographic SHA-256 integrity hash for an event record
    using its canonical fields to ensure tamper evidence.
    """
    canonical_payload = {
        "event_id": str(event_dict.get("event_id", "")),
        "detection_time": _canonical_time(event_dict.get("detection_time")),
        "attack_type": str(event_dict.get("attack_type", "")),
        "source_ip": str(event_dict.get("source_ip", "")),
        "destination_ip": str(event_dict.get("destination_ip", "")),
        "detection_method": str(event_dict.get("detection_method", "")),
        "severity": str(event_dict.get("severity", ""))
    }
    encoded = json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
