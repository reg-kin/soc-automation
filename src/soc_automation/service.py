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
