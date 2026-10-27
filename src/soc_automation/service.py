"""Offline orchestration with atomic batches and durable rejection audit."""

from soc_automation.ingestion import InputError, Limits, normalize, parse
from soc_automation.state import StateError, Store
from soc_automation.triage import Policy, decide


def ingest(
    store: Store,
    data: bytes,
    *,
    source_id: str | None = None,
    limits: Limits | None = None,
    policy: Policy | None = None,
) -> list[dict]:
    policy = policy or Policy()
    try:
        batch = parse(data, limits)
        if source_id is not None and len(batch) != 1:
            raise InputError("Explicit identifier requires a single alert")
        prepared = []
        for item in batch:
            alert, original = normalize(item, source_id=source_id, limits=limits)
            prepared.append((alert, original, decide(alert, policy)))
        return store.ingest_batch(prepared)
    except (ValueError, StateError):
        store.rejection()
        raise


def investigate(store: Store, alert_ids: list[str], provider) -> dict:
    """Changed evidence never replaces prior results."""
    import sqlite3
    from uuid import uuid4

    from soc_automation.investigation import build, request_identity

    correlation_id = str(uuid4())
    try:
        ids, fingerprint = request_identity(alert_ids)
        alerts = [store.show_alert(identifier, evidence=True) for identifier in ids]
        report = build(alerts, provider)
        report.update(
            investigation_id="inv-" + fingerprint,
            request_fingerprint=fingerprint,
            audit_correlation_id=correlation_id,
        )
        return store.save_investigation(report, fingerprint)
    except (ValueError, StateError, OSError, sqlite3.Error):
        store.investigation_failure(correlation_id)
        raise
