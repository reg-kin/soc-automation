"""Bounded investigation execution. This module has no publication interface."""

import json
import queue
import threading
import time
from uuid import uuid4

from soc_automation.coordination import FailureCode, InvestigationQueue, bounded
from soc_automation.evidence import RetrievalCode, validate
from soc_automation.service import construct_investigation
from soc_automation.state import EvidenceConflict, StateError

TRANSIENT = {RetrievalCode.TRANSPORT, RetrievalCode.RATE_LIMIT, RetrievalCode.SERVER}
PERMANENT = {
    RetrievalCode.AUTH,
    RetrievalCode.CONFIGURATION,
    RetrievalCode.INVALID_REFERENCE,
    RetrievalCode.CONFLICT,
    RetrievalCode.INVALID_EVIDENCE,
}


class RetrievalFailure(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code.value)


class WorkerProvider:
    def __init__(self, provider):
        self.provider = provider
        self.transient = False

    def retrieve_many(self, references):
        results = self.provider.retrieve_many(references)
        if not isinstance(results, list) or len(results) != len(references):
            raise RetrievalFailure(RetrievalCode.INVALID_EVIDENCE)
        validated = [validate(r, ref) for ref, r in zip(references, results, strict=True)]
        # Permanent failures always take precedence, including mixed batches.
        for result in validated:
            if result.code in PERMANENT:
                raise RetrievalFailure(result.code)
        self.transient = any(r.code in TRANSIENT for r in validated)
        return validated


class InvestigationWorker:
    def __init__(
        self,
        store,
        provider,
        *,
        clock=time.time,
        monotonic=time.monotonic,
        lease_seconds=60,
        heartbeat_seconds=10,
        execution_seconds=300,
        max_job_age=86400,
        retry_seconds=60,
        owner=None,
    ):
        bounded(lease_seconds, 86400)
        bounded(execution_seconds, 86400)
        bounded(max_job_age, 604800)
        bounded(retry_seconds, 86400)
        if not 0 < heartbeat_seconds < lease_seconds / 2:
            raise ValueError("Heartbeat must be shorter than half the lease")
        self.queue = InvestigationQueue(store, clock=clock)
        self.provider = provider
        self.monotonic = monotonic
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.execution_seconds = execution_seconds
        self.max_job_age = max_job_age
        self.retry_seconds = retry_seconds
        self.owner = owner or str(uuid4())

    def _construct(self, job):
        """Only construction runs in the daemon thread; it cannot persist a report.

        The supervising thread renews during blocking requests and stops waiting at
        a monotonic deadline. Uncooperative providers can never commit late results.
        """
        result = queue.Queue(maxsize=1)
        provider = WorkerProvider(self.provider)

        def execute():
            try:
                report = construct_investigation(
                    self.queue.store, json.loads(job["selection_json"]), provider
                )
                result.put((report, None))
            except BaseException as error:
                result.put((None, error))

        threading.Thread(target=execute, daemon=True).start()
        deadline = self.monotonic() + self.execution_seconds
        while True:
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise StateError("Investigation execution deadline exceeded")
            try:
                report, error = result.get(timeout=min(self.heartbeat_seconds, remaining))
                if self.monotonic() >= deadline:
                    raise StateError("Investigation execution deadline exceeded")
                if error is not None:
                    raise error
                return report, provider.transient
            except queue.Empty:
                self.queue.renew(
                    job["id"],
                    self.owner,
                    job["lease_generation"],
                    lease_seconds=self.lease_seconds,
                )

    def run(self, *, max_jobs=1):
        bounded(max_jobs, 1000)
        outcomes = []
        for _ in range(max_jobs):
            job = self.queue.claim(
                self.owner, lease_seconds=self.lease_seconds, reject_incompatible=True
            )
            if job is None:
                break
            if job["state"] == "failed":
                outcomes.append(self.queue.inspect(job["id"]))
                continue
            args = (job["id"], self.owner, job["lease_generation"])
            try:
                existing = self.queue.existing_report(job)
                if existing is not None:
                    report = self.queue.complete(*args, existing, adopt=True)
                else:
                    expired = self.queue.clock() - job["created_at"] >= self.max_job_age
                    if expired:
                        self.queue.finish(*args, failure=FailureCode.PERMANENT)
                        outcomes.append(self.queue.inspect(job["id"]))
                        continue
                    report, transient = self._construct(job)
                    retry = (
                        transient
                        and job["attempt_count"] < job["max_attempts"]
                        and self.queue.clock() + self.retry_seconds
                        < job["created_at"] + self.max_job_age
                    )
                    if retry:
                        self.queue.finish(
                            *args,
                            failure=FailureCode.TRANSIENT,
                            retry_seconds=self.retry_seconds,
                        )
                    else:
                        self.queue.complete(
                            *args,
                            report,
                            partial_failure=(
                                FailureCode.TRANSIENT
                                if transient and job["attempt_count"] == job["max_attempts"]
                                else FailureCode.PERMANENT
                            ),
                        )
            except (RetrievalFailure, EvidenceConflict, ValueError):
                self.queue.finish(*args, failure=FailureCode.PERMANENT)
            outcomes.append(self.queue.inspect(job["id"]))
        return outcomes
