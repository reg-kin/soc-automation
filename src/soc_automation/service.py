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


def prepare_case(store, investigation_id, settings, *, revise=False):
    """Local-only evidence validation and immutable review artifact."""
    from soc_automation.cases import render

    report = store.show_investigation(investigation_id)
    alerts = [store.show_alert(i, evidence=True) for i in report["source_alert_ids"]]
    payload = render(report, alerts)
    store.validate_case_evidence(report)
    return store.prepare_publication(investigation_id, settings.target, payload, revise=revise)


def _publication(store, publication_id, client):
    import json

    from soc_automation.cases import digest

    row = store.show_case_publication(publication_id)
    payload = json.loads(row["payload_json"])
    if row["target"] != client.settings.target or digest(payload) != row["payload_sha256"]:
        raise StateError("Publication target or payload mismatch")
    return row, payload


def _verify_receipt(receipt, payload):
    import re

    if (
        not isinstance(receipt, dict)
        or not isinstance(receipt.get("id"), str)
        or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", receipt["id"])
        or not isinstance(receipt.get("version"), str)
        or not 1 <= len(receipt["version"]) <= 256
        or any(receipt.get(k) != v for k, v in payload.items())
    ):
        raise StateError("Remote case verification failed")
    return {"id": receipt["id"], "version": receipt["version"]}


def publish_case(store, publication_id, client, *, approval_hash, authorized=False):
    """Authorization is a service contract, independent of CLI parsing."""
    if authorized is not True:
        raise StateError("Explicit case creation authorization required")
    row, payload = _publication(store, publication_id, client)
    if approval_hash != row["payload_sha256"]:
        raise StateError("Reviewed approval hash required")
    if row["state"] == "published":
        return row
    if not store.claim_publication(publication_id, approval_hash):
        raise StateError("Publication already claimed; reconcile without resending")
    try:
        receipt = _verify_receipt(client.create(payload), payload)
        store.publication_outcome(publication_id, receipt)
    except Exception:
        store.publication_outcome(publication_id)
        raise StateError("Publication outcome uncertain; reconcile without resending") from None
    return store.show_case_publication(publication_id)


def reconcile_case(store, publication_id, client):
    """Read-only reconciliation. Zero or ambiguous matches never enable a resend."""
    row, payload = _publication(store, publication_id, client)
    if row["state"] == "published":
        return row
    if row["state"] not in {"sending", "uncertain"}:
        raise StateError("Publication has not been sent")
    result = client.find(payload["tags"][0])
    if (
        not isinstance(result, dict)
        or type(result.get("total")) is not int
        or result["total"] != 1
        or len(result.get("cases", [])) != 1
    ):
        raise StateError("No unique reconciliation match; resend prohibited")
    candidate = result["cases"][0]
    receipt = _verify_receipt(client.get(candidate["id"]), payload)
    if receipt["id"] != candidate["id"]:
        raise StateError("Case identity mismatch")
    store.publication_outcome(publication_id, receipt)
    return store.show_case_publication(publication_id)
