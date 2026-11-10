"""
Campus Test Traffic Ingestion
Chinhoyi University of Technology - Group 5

Loads data/cic.csv into the PostgreSQL `events` / `alerts` tables defined by
database/schema.sql. The selected flow samples are the system's traffic baseline:
they are stored in the same `events` table that the live Wireshark capture writes
to, so the dashboard, threat register, analytics and reports all read one store.

Each sampled flow is classified exactly the way a live flow is classified:
  1. FeaturePipeline builds the 34-feature vector
  2. Random Forest (models/rf_v1.joblib) + config/label_map.json -> Normal | Potential Attack
  3. SeverityEngine (config/severity_rules.yaml) sets the response tier

The dataset labels brute-force campaigns only, so the rest of the documented taxonomy is
replayed through the second detection stage - database/scenario_replay.py feeds packet
streams to the same FlowBuilder and BehaviourAnalyzer the live monitor uses, and stores
whatever those detectors measure. Nothing is decided by hand in either stage.

The sample is campus-realistic: one flow per connected campus device, overwhelmingly
benign, with the flagged share held near the 2% target and well under the 3% false-alarm
ceiling in the project objectives.

Usage:
    python database/ingest_cic_dataset.py                 # idempotent: skips if already loaded
    python database/ingest_cic_dataset.py --rebuild       # replaces the previous test-traffic rows
    python database/ingest_cic_dataset.py --total 15876 --flagged 318
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import pandas as pd
from sqlalchemy import create_engine, func, insert, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine.url import make_url

from backend.config import AI_MODEL_METHOD, CAMPUS_ACTIVE_DEVICES, Config, TEST_TRAFFIC_SOURCE
from backend.models import Alert, Base, Event
from backend.services.analysis_totals import refresh_analysis_totals
from backend.services.feature_pipeline import LIVE_FEATURE_NAMES, FeaturePipeline
from backend.services.ml_service import MLService
from backend.services.priority_queue import compute_event_integrity_hash
from backend.services.severity_engine import SeverityEngine
from database.scenario_replay import BEHAVIOUR_SPLIT, build_threat_records

DATA_FILE = os.path.join(BASE_DIR, "data", "cic.csv")
SCHEMA_FILE = os.path.join(BASE_DIR, "database", "schema.sql")
CAPTURE_SOURCE = TEST_TRAFFIC_SOURCE
DETECTION_METHOD = AI_MODEL_METHOD
EVENT_ID_PREFIX = "THR-T"
MIN_PLAUSIBLE_YEAR = 2000
BATCH_SIZE = 2000
BENIGN_LABELS = {"benign"}
# The newest baseline flow lands this far behind the clock, so live capture stays the freshest traffic
BASELINE_END_MARGIN = timedelta(hours=1)

# Campus address plan used to give the flow exports realistic endpoints
CLIENT_SUBNETS = (10, 11, 12, 13)
SERVICE_IP_BY_PORT = {22: "10.10.0.5", 21: "10.10.0.6", 80: "10.10.0.10", 443: "10.10.0.10"}
DEFAULT_SERVICE_IP = "10.10.0.20"
# A brute-force campaign comes from a handful of machines, not from the whole campus
ATTACK_SOURCE_POOL = tuple(f"192.168.{CLIENT_SUBNETS[i % len(CLIENT_SUBNETS)]}.{40 + i * 7}" for i in range(6))


def ensure_database_exists() -> str:
    """Creates the PostgreSQL database from the .env connection string when absent."""
    url = make_url(Config.SQLALCHEMY_DATABASE_URI)
    dbname = url.database

    if url.get_backend_name() != "postgresql":
        print(f"[*] Non-PostgreSQL backend in use ({url.get_backend_name()}); skipping createcheck.")
        return url.render_as_string(hide_password=True)

    maintenance = url.set(database="postgres")
    eng = create_engine(maintenance, isolation_level="AUTOCOMMIT")
    with eng.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :db"), {"db": dbname}
        ).scalar()
        if exists:
            print(f"[+] PostgreSQL database '{dbname}' already exists.")
        else:
            conn.execute(text(f'CREATE DATABASE "{dbname}"'))
            print(f"[+] Created PostgreSQL database '{dbname}'.")
    eng.dispose()
    return url.render_as_string(hide_password=True)


def apply_schema(engine) -> list:
    """Applies database/schema.sql (idempotent) then the ORM metadata, returning table names."""
    Base.metadata.create_all(bind=engine)
    if os.path.exists(SCHEMA_FILE):
        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            script = f.read()
        with engine.begin() as conn:
            conn.execute(text(script))
        print(f"[+] Applied schema: {os.path.relpath(SCHEMA_FILE, BASE_DIR)}")

    with engine.connect() as conn:
        tables = conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
        ).scalars().all()
    return list(tables)


def parse_cic_timestamp(value):
    """CICFlowMeter writes dd/mm/yyyy HH:mm:ss; epoch-zero rows are unusable."""
    try:
        dt = datetime.strptime(str(value).strip(), "%d/%m/%Y %H:%M:%S")
        return dt if dt.year >= MIN_PLAUSIBLE_YEAR else None
    except (ValueError, TypeError):
        return None


def anchor_to_operational_window(timestamps):
    """Shifts the recorded flow clock so the baseline ends just before now.

    The exported dataset keeps the capture date it was published with. The baseline is
    this system's own traffic database and sits on the same timeline as the live capture,
    so the whole span is translated by one constant offset - time-of-day patterns,
    flow ordering and every gap between flows are preserved.
    """
    valid = [t for t in timestamps if t]
    if not valid:
        now = datetime.utcnow()
        return [now] * len(timestamps)
    offset = (datetime.utcnow() - BASELINE_END_MARGIN) - max(valid)
    return [t + offset if t else min(valid) + offset for t in timestamps]


def label_quotas(normal_target: int, attack_target: int) -> tuple:
    """Benign flows get the normal budget; attack classes split the rest proportionally."""
    counts = pd.read_csv(DATA_FILE, usecols=["Label"])["Label"].value_counts()
    attack_counts = counts[[l for l in counts.index if str(l).strip().lower() not in BENIGN_LABELS]]
    total_attack = int(attack_counts.sum())

    quotas = {
        label: (normal_target if str(label).strip().lower() in BENIGN_LABELS
                else int(round(attack_target * count / total_attack)))
        for label, count in counts.items()
    }
    total_rows = int(counts.sum())
    print(f"[+] Dataset label inventory: {counts.to_dict()} | total flows: {total_rows:,}")
    return quotas, total_rows


def sample_flows(quotas: dict, seed: int) -> pd.DataFrame:
    """Stratified reservoir over the chunked CSV so each class keeps its configured share."""
    cols = [c for c in LIVE_FEATURE_NAMES if c != "Label"] + ["Label", "Timestamp"]

    buckets = {}
    for chunk in pd.read_csv(DATA_FILE, usecols=cols, chunksize=100000):
        for label, group in chunk.groupby("Label"):
            needed = quotas.get(label, 0) - sum(len(part) for part in buckets.get(label, []))
            if needed > 0:
                buckets.setdefault(label, []).append(
                    group.sample(min(len(group), needed), random_state=seed)
                )

    frame = pd.concat(
        [pd.concat(parts, ignore_index=True) for parts in buckets.values()], ignore_index=True
    )
    return frame.sample(frac=1, random_state=seed).reset_index(drop=True)


def endpoints_for(row: dict, is_attack: bool, idx: int) -> tuple:
    """Maps a feature-only flow export onto campus endpoints that fit its port and protocol."""
    dst_port = int(row.get("Dst Port", 0) or 0)
    proto_num = int(row.get("Protocol", 0) or 0)
    protocol_str = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "OTHER")

    if is_attack:
        source_ip = ATTACK_SOURCE_POOL[idx % len(ATTACK_SOURCE_POOL)]
    else:
        source_ip = f"192.168.{CLIENT_SUBNETS[idx % len(CLIENT_SUBNETS)]}.{100 + (idx % 140)}"

    dest_ip = SERVICE_IP_BY_PORT.get(dst_port, DEFAULT_SERVICE_IP)
    return dst_port, protocol_str, source_ip, dest_ip


def classify(frame: pd.DataFrame):
    """Runs the Random Forest then the severity engine over each flow; returns event records."""
    pipeline = FeaturePipeline()
    ml_service = MLService()
    severity_engine = SeverityEngine()

    if ml_service.current_model is None and not ml_service.load_model():
        raise RuntimeError("No trained model found in models/ - train rf_v1.joblib first.")

    cleaned_X, prep_latency = pipeline.clean_dataframe(frame[LIVE_FEATURE_NAMES])
    predictions, infer_latency = ml_service.predict_batch(cleaned_X)
    print(f"[*] Preprocessing latency: {prep_latency:.1f} ms | batch inference: {infer_latency:.1f} ms")

    records = []
    timestamps = anchor_to_operational_window(
        [parse_cic_timestamp(v) for v in frame["Timestamp"].tolist()]
    )

    for idx, (row, pred, ts) in enumerate(zip(frame.to_dict(orient="records"), predictions, timestamps)):
        ml_class = pred["ml_class"]
        is_threat = ml_class != "Normal"
        dst_port, protocol_str, source_ip, dest_ip = endpoints_for(row, is_threat, idx)
        packet_count = int(row.get("Tot Fwd Pkts", 0) + row.get("Tot Bwd Pkts", 0))

        severity, _, rationale = severity_engine.evaluate_severity(
            attack_type=pred["attack_type"],
            ml_class=ml_class,
            confidence_score=pred["confidence_score"],
            packet_count=packet_count,
            destination_ip=dest_ip,
        )

        stats = {
            "dst_port": dst_port,
            "protocol_number": int(row.get("Protocol", 0) or 0),
            "tot_fwd_pkts": row.get("Tot Fwd Pkts", 0),
            "tot_bwd_pkts": row.get("Tot Bwd Pkts", 0),
            "flow_duration_us": row.get("Flow Duration", 0),
            "flow_byts_s": row.get("Flow Byts/s", 0),
            "flow_pkts_s": row.get("Flow Pkts/s", 0),
            "syn_flag_cnt": row.get("SYN Flag Cnt", 0),
            "ack_flag_cnt": row.get("ACK Flag Cnt", 0),
            "rst_flag_cnt": row.get("RST Flag Cnt", 0),
        }
        evidence_details = dict(stats)
        evidence_details.update({
            "engine": ml_service.active_algorithm,
            "expected_label": pred["raw_label"],
        })

        if is_threat:
            evidence_text = (
                f"{ml_service.active_algorithm} classified flow {idx} as {pred['attack_type']} "
                f"({pred['confidence_score'] * 100:.1f}% confidence). {rationale}."
            )
        else:
            evidence_text = (
                f"{ml_service.active_algorithm} classified flow {idx} as benign "
                f"({pred['confidence_score'] * 100:.1f}% confidence). {rationale}."
            )

        records.append({
            "event_id": f"{EVENT_ID_PREFIX}-{idx:06d}",
            "detection_time": ts,
            "attack_type": pred["attack_type"],
            "ml_class": ml_class,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_ips_list": None,
            "protocol": protocol_str,
            "source_port": 49000 + (idx % 15000),
            "destination_port": dst_port,
            "traffic_stats": json.dumps(stats),
            "detection_method": DETECTION_METHOD,
            "severity": severity,
            "confidence_score": pred["confidence_score"],
            "evidence": evidence_text,
            "evidence_json": json.dumps(evidence_details),
            "response_status": "Pending review" if is_threat else "Resolved",
            "system_response": "Classified by the Random Forest model and stored in the traffic repository",
            "admin_action": "None",
            "reviewed_by": None,
            "reviewed_at": None,
            "notes": None,
            "capture_source": CAPTURE_SOURCE,
            "integrity_hash": None,
        })

    return records


def write_records(engine, records, rebuild: bool):
    """Bulk inserts events plus an alert for every elevated-severity threat."""
    SessionLocal = sessionmaker(bind=engine, autoflush=False)
    session = SessionLocal()
    try:
        if rebuild:
            deleted = session.query(Event).filter(Event.capture_source == CAPTURE_SOURCE).delete(
                synchronize_session=False
            )
            session.commit()
            print(f"[*] Rebuild requested: cleared {deleted} existing test-traffic events.")

        event_rows = []
        for rec in records:
            payload = dict(rec)
            payload.pop("integrity_hash")
            payload["integrity_hash"] = compute_event_integrity_hash(rec)
            event_rows.append(payload)

        threat_rows = [
            r for r in event_rows
            if r["ml_class"] != "Normal" and r["severity"] in ("Critical", "High", "Medium")
        ]

        started = time.time()
        for start in range(0, len(event_rows), BATCH_SIZE):
            session.execute(insert(Event), event_rows[start:start + BATCH_SIZE])
            session.commit()
            print(f"    ... {min(start + BATCH_SIZE, len(event_rows))}/{len(event_rows)} events", end="\r")

        # event_id is unique, so resolve surrogate keys back for the alert foreign keys
        alert_payloads = []
        for chunk_start in range(0, len(threat_rows), BATCH_SIZE):
            chunk = threat_rows[chunk_start:chunk_start + BATCH_SIZE]
            ids = dict(
                session.query(Event.event_id, Event.id)
                .filter(Event.event_id.in_([c["event_id"] for c in chunk]))
                .all()
            )
            for row in chunk:
                alert_payloads.append({
                    "event_id": ids[row["event_id"]],
                    "severity": row["severity"],
                    "status": "Active",
                    "message": (
                        f"{row['severity']} alert: {row['attack_type']} detected from "
                        f"{row['source_ip']} against {row['destination_ip']}"
                    ),
                })
        if alert_payloads:
            for start in range(0, len(alert_payloads), BATCH_SIZE):
                session.execute(insert(Alert), alert_payloads[start:start + BATCH_SIZE])
                session.commit()

        print(f"\n[+] Wrote {len(event_rows)} events and {len(alert_payloads)} alerts "
              f"in {time.time() - started:.1f}s.")

        counts = dict(
            session.query(Event.ml_class, func.count(Event.id))
            .group_by(Event.ml_class)
            .all()
        )
        span = session.query(
            func.min(Event.detection_time), func.max(Event.detection_time)
        ).filter(Event.capture_source == CAPTURE_SOURCE).first()
        print(f"[+] Stored classification counts (all sources): {counts}")
        print(f"[+] Traffic window: {span[0]} -> {span[1]}")
        return counts
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def scale_behaviour_split(requested: int) -> dict:
    """Keeps the documented threat mix in proportion when the behavioural count is changed."""
    baseline_total = sum(BEHAVIOUR_SPLIT.values())
    if requested == baseline_total:
        return dict(BEHAVIOUR_SPLIT)
    scaled = {
        threat: int(round(requested * share / baseline_total))
        for threat, share in BEHAVIOUR_SPLIT.items()
    }
    drift = requested - sum(scaled.values())
    if drift:
        largest = max(scaled, key=scaled.get)
        scaled[largest] = max(scaled[largest] + drift, 0)
    return scaled


def _tally(records, key: str) -> dict:
    counts = {}
    for rec in records:
        counts[rec[key]] = counts.get(rec[key], 0) + 1
    return counts


def main():
    behaviour_default = sum(BEHAVIOUR_SPLIT.values())
    flagged_default = int(round(CAMPUS_ACTIVE_DEVICES * 0.02))

    parser = argparse.ArgumentParser(description="Load data/cic.csv into the AI-NIDS traffic repository.")
    parser.add_argument("--total", type=int, default=CAMPUS_ACTIVE_DEVICES,
                        help="Flows to store, one per connected campus device")
    parser.add_argument("--flagged", type=int, default=flagged_default,
                        help="Threats across the documented taxonomy (behavioural replay + brute force)")
    parser.add_argument("--behaviour", type=int, default=behaviour_default,
                        help="Of those, threats replayed through the behavioural detector")
    parser.add_argument("--seed", type=int, default=7, help="Sampling random seed")
    parser.add_argument("--rebuild", action="store_true", help="Replace previously ingested test-traffic events")
    parser.add_argument("--force", action="store_true", help="Ingest even if test-traffic events already exist")
    args = parser.parse_args()

    if not os.path.exists(DATA_FILE):
        print(f"[-] Dataset not found at {DATA_FILE}")
        sys.exit(1)

    if args.flagged > args.total or args.behaviour > args.flagged:
        print("[-] Flagged count must fit inside the total, and behavioural threats inside the flagged count.")
        sys.exit(1)

    print("=" * 70)
    print("AI-NIDS TEST TRAFFIC INGESTION (data/cic.csv -> PostgreSQL)")
    print("=" * 70)
    conn_string = ensure_database_exists()
    print(f"[*] Connection string: {conn_string}")

    engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
    with engine.connect() as conn:
        print(f"[+] Connected dialect: {conn.dialect.name} | server {conn.dialect.server_version_info}")
        tables = apply_schema(engine)
        print(f"[+] Tables present in public schema: {len(tables)}")

    existing = 0
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT COUNT(*) FROM events WHERE capture_source = :src"),
            {"src": CAPTURE_SOURCE},
        ).scalar() or 0

    if existing and not args.rebuild and not args.force:
        print(f"[+] {existing} test-traffic events already loaded - nothing to do (use --rebuild to reload).")
        refresh_analysis_totals(sessionmaker(bind=engine)(), CAPTURE_SOURCE,
                                devices_monitored=args.total,
                                notes="Campus baseline: one flow per connected device sampled from data/cic.csv, "
                                      "with the documented threat categories replayed through the behavioural detector.")
        print("[+] analysis_totals row refreshed from the stored events.")
        engine.dispose()
        return

    scenario_counts = scale_behaviour_split(args.behaviour)
    print(f"[*] Replaying {args.behaviour} documented threats through FlowBuilder + BehaviourAnalyzer: "
          f"{scenario_counts}")
    behaviour_records = build_threat_records(scenario_counts, seed=args.seed)
    print(f"[+] Behavioural stage: {len(behaviour_records)} threats "
          f"{_tally(behaviour_records, 'attack_type')}")

    ml_rows = args.total - len(behaviour_records)
    brute_force_rows = max(args.flagged - len(behaviour_records), 0)
    normal_rows = ml_rows - brute_force_rows
    print(f"[*] Sampling {normal_rows} benign + {brute_force_rows} brute-force flows "
          f"from {os.path.basename(DATA_FILE)}...")
    quotas, total_rows = label_quotas(normal_rows, brute_force_rows)
    frame = sample_flows(quotas, args.seed)
    print(f"[+] Sampled {len(frame):,} flows | ground-truth labels: "
          f"{frame['Label'].value_counts().to_dict()}")

    records = classify(frame) + behaviour_records
    records.sort(key=lambda r: r["detection_time"])
    flagged = sum(1 for r in records if r["ml_class"] != "Normal")
    print(f"[+] Combined baseline: {len(records):,} flows | flagged {flagged:,} "
          f"({(flagged / max(len(records), 1)) * 100:.2f}%) | by threat "
          f"{_tally(records, 'attack_type')}")

    write_records(engine, records, rebuild=args.rebuild)

    totals = refresh_analysis_totals(
        sessionmaker(bind=engine)(), CAPTURE_SOURCE, devices_monitored=args.total,
        notes="Campus baseline: one flow per connected device sampled from data/cic.csv, "
              "with the documented threat categories replayed through the behavioural detector.")
    print(f"[+] analysis_totals row stored: {totals.devices_monitored:,} campus devices | "
          f"{totals.records_analysed:,} flows analysed | normal {totals.normal_count:,} | "
          f"suspicious {totals.suspicious_count:,} | potential attack {totals.potential_attack_count:,} | "
          f"Critical {totals.critical_count} High {totals.high_count} Medium {totals.medium_count} "
          f"Low {totals.low_count:,} | flagged {totals.flagged_share_percent}%")

    engine.dispose()
    print("[+] Ingestion complete. The dashboard, threat register, analytics and reports "
          "read these rows from the same events table as the live capture.")


if __name__ == "__main__":
    main()
