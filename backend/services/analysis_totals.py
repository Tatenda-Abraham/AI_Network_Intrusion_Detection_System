"""
AI-NIDS Analysis Totals
Chinhoyi University of Technology - Group 5

The dashboard's headline figures are stored as rows in the analysis_totals table rather
than recomputed from a constant at request time, so opening PostgreSQL shows exactly what
the console claims to have analysed. One row per traffic source: the campus ingester
refreshes the test-data row, the live monitor refreshes the capture row after each window.
"""

from datetime import datetime

from sqlalchemy import func

from backend.models import AnalysisTotal, Event


def refresh_analysis_totals(session, capture_source: str, devices_monitored: int = None,
                            notes: str = None) -> AnalysisTotal:
    """Recount one source's stored events and write the headline figures for it."""
    rows = (
        session.query(Event.ml_class, Event.severity, func.count(Event.id))
        .filter(Event.capture_source == capture_source)
        .group_by(Event.ml_class, Event.severity)
        .all()
    )
    span = (
        session.query(func.min(Event.detection_time), func.max(Event.detection_time))
        .filter(Event.capture_source == capture_source)
        .first()
    )

    records = normal = suspicious = potential = 0
    tiers = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for ml_class, severity, count in rows:
        records += count
        if ml_class == "Normal":
            normal += count
        elif ml_class == "Suspicious":
            suspicious += count
        else:
            potential += count
        if severity in tiers:
            tiers[severity] += count

    flagged = suspicious + potential
    row = session.query(AnalysisTotal).filter(
        AnalysisTotal.capture_source == capture_source).first()
    if row is None:
        row = AnalysisTotal(capture_source=capture_source)
        session.add(row)

    # devices_monitored is the campus device count behind a baseline; live capture counts
    # flows it saw rather than devices it owns, so an absent figure stays zero. A caller
    # that only wants a recount passes neither of these and keeps what is already stored.
    if devices_monitored is not None or row.devices_monitored is None:
        row.devices_monitored = devices_monitored or 0
    row.records_analysed = records
    row.normal_count = normal
    row.suspicious_count = suspicious
    row.potential_attack_count = potential
    row.critical_count = tiers["Critical"]
    row.high_count = tiers["High"]
    row.medium_count = tiers["Medium"]
    row.low_count = tiers["Low"]
    row.flagged_share_percent = round(flagged / records * 100, 2) if records else 0.0
    row.traffic_window_start = span[0]
    row.traffic_window_end = span[1]
    row.notes = notes if notes is not None else row.notes
    row.generated_at = datetime.utcnow()
    session.commit()
    return row
