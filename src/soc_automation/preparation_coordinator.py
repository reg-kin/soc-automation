"""One bounded, offline preparation pass over the existing global queue.

Admission uses a global outstanding-work ceiling of twice processing capacity.
Discovery admission checks and enqueues share one write transaction.
No elapsed-time guarantee is made.
"""

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field

from soc_automation.cases import RENDERER_VERSION, ReportIneligible, render
from soc_automation.discovery import _identity
from soc_automation.preparation import _bound
from soc_automation.state import (
    EvidenceConflict,
    PreparationMismatch,
    RendererMismatch,
    ReportEvidenceIneligible,
)


@dataclass
class PassResult:
    recovered: int = 0
    discovered: int = 0
    resolved: int = 0
    claimed: int = 0
    completed: int = 0
    failed: int = 0
    discovery_budget_exhausted: bool = False
    processing_budget_exhausted: bool = False
    stopped: str | None = None
    outcomes: list[dict] = field(default_factory=list)


def _contention(exc):
    return (isinstance(exc, sqlite3.OperationalError)
            and getattr(exc, "sqlite_errorcode", 0) & 255
            in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED))


def _ownership(store, job):
    """Tri-state ownership check: unknown must never authorize failure mutation."""
    try:
        current = store.show_case_preparation(job["id"])
    except Exception:
        return None
    return (current["state"] == "leased"
            and current["lease_owner"] == job["lease_owner"]
            and current["lease_generation"] == job["lease_generation"]
            and current["lease_until"] > time.time())


def _payload(store, job):
    report = json.loads(job["report_json"])
    if hashlib.sha256(job["report_json"].encode()).hexdigest() != job["report_sha256"]:
        raise EvidenceConflict("Frozen report digest mismatch")
    store.validate_case_evidence(report)
    return render(report, [store.show_alert(i, evidence=True)
                           for i in report["source_alert_ids"]])


def run_pass(store, target, *, discovery_limit=100, processing_limit=50,
             recovery_limit=100, lease_seconds=60):
    """Validate before writes, recover, drain backlog, discover fairly, then drain.

    Limits are integers (discovery 2..1000, processing/recovery 1..1000,
    lease <=86400). Outcomes contain at most processing_limit entries and no
    report text or exception messages. Claims select only this target.
    Discovery counts eligible resolutions, including idempotent enqueue reuse.
    """
    _identity(target, RENDERER_VERSION)
    for value in (discovery_limit, processing_limit, recovery_limit):
        _bound(value)
    if discovery_limit < 2:
        raise ValueError("Discovery budget must fund both lanes")
    _bound(lease_seconds, 86400)
    result = PassResult()

    def process():
        while result.claimed < processing_limit:
            job = store.claim_case_preparation(lease_seconds=lease_seconds, target=target)
            if job is None:
                return
            result.claimed += 1
            outcome = {"job_id": job["id"], "status": "unexpected"}
            result.outcomes.append(outcome)
            args = job["id"], job["lease_owner"], job["lease_generation"]
            try:
                if job["renderer_version"] != RENDERER_VERSION:
                    failure = "renderer_mismatch"
                else:
                    payload = _payload(store, job)
                    store.complete_case_preparation(*args, payload=payload)
                    result.completed += 1
                    outcome["status"] = "completed"
                    continue
            except Exception as exc:
                owned = _ownership(store, job)
                if owned is False:
                    outcome["status"] = result.stopped = "lease_lost"
                    return
                if owned is None:
                    outcome["status"] = result.stopped = "ownership_unknown"
                    return
                if isinstance(exc, RendererMismatch):
                    failure = "renderer_mismatch"
                elif isinstance(exc, (EvidenceConflict, ReportEvidenceIneligible,
                                      PreparationMismatch)):
                    failure = "permanent"
                elif isinstance(exc, ReportIneligible):
                    failure = "renderer_mismatch"
                elif _contention(exc):
                    failure = "transient"
                else:
                    result.stopped = "unexpected"
                    return
            try:
                failed = store.fail_case_preparation(*args, failure=failure)
            except Exception as exc:
                owned = _ownership(store, job)
                outcome["status"] = result.stopped = (
                    "lease_lost" if owned is False else
                    "contention" if _contention(exc) else "unexpected")
                return
            result.failed += 1
            outcome.update(status=failure, state=failed["state"])

    try:
        result.recovered = store.recover_case_preparations(limit=recovery_limit)
        process()
        if result.stopped:
            return result
        checkpoint = store.initialize_case_preparation_discovery(target)
        budget = discovery_limit
        # Reserve scan budget and an admission slot for the second lane. Rotate
        # priority from durable admission order, so blocked scans and replay
        # cannot cancel the next lane's turn.
        lanes = [lane for lane in ("historical", "live")
                 if store.preview_case_preparation_discovery(
                     target, lane=lane, limit=1)["records"]]
        allocations = []
        if len(lanes) == 1 and budget:
            allocations = [(lanes[0], budget)]
        elif len(lanes) == 2 and budget >= 2:
            if store.case_preparation_discovery_live_first(target):
                lanes.reverse()
            allocations = [(lanes[0], (budget + 1) // 2), (lanes[1], budget // 2)]
        if allocations:
            for lane, limit in allocations:
                page = store.advance_case_preparation_discovery(
                    target, lane=lane, expected_revision=checkpoint["revision"], limit=limit,
                    outstanding_limit=2 * processing_limit - (
                        1 if len(lanes) == 2 and lane == lanes[0] else 0))
                checkpoint = page["checkpoint"]
                result.resolved += len(page["records"])
                result.discovered += sum(r["eligible"] for r in page["records"])
        pending = any(store.preview_case_preparation_discovery(
            target, lane=lane, limit=1)["records"] for lane in ("historical", "live"))
        result.discovery_budget_exhausted = pending
        process()
        result.processing_budget_exhausted = (
            result.claimed == processing_limit
            and bool(store.eligible_case_preparations(limit=1, target=target)))
    except Exception as exc:
        result.stopped = "contention" if _contention(exc) else "unexpected"
    return result
