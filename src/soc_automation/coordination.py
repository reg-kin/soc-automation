"""Durable coordination only: no evidence retrieval, execution, or publication."""

import json
import time
from enum import StrEnum
from uuid import uuid4

from soc_automation import investigation
from soc_automation.ingestion import encode
from soc_automation.state import StateError, _identifier


class FailureCode(StrEnum):
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    LEASE_EXPIRED = "lease_expired"
    ENGINE_MISMATCH = "engine_mismatch"


class CoordinationError(StateError):
    """A fixed failure code suitable for callers; never classify exception text."""

    def __init__(self, code):
        self.code = code
        super().__init__(code.value)


ELIGIBLE = """
SELECT a.id AS alert_id, json_extract(i.decision_json,'$.priority') AS priority,
 a.created_at AS ingested_at
FROM alerts a JOIN ingested_alerts i ON i.alert_id=a.id
WHERE a.state='triaged' AND json_extract(i.decision_json,'$.validity')='VALID'
 AND json_extract(i.decision_json,'$.disposition') IN ('INVESTIGATE','URGENT_INVESTIGATION')
 AND json_extract(i.decision_json,'$.priority') IN ('P1','P2','P3','P4')
 AND NOT EXISTS (SELECT 1 FROM investigation_alerts x WHERE x.alert_id=a.id)
 AND NOT EXISTS (SELECT 1 FROM investigation_job_alerts x WHERE x.alert_id=a.id)
ORDER BY priority, a.created_at, a.id LIMIT ?
"""


def bounded(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("Invalid bound")
    return value


class InvestigationQueue:
    def __init__(self, store, *, clock=time.time):
        self.store = store
        self.clock = clock

    def _audit(self, conn, job, event, now):
        conn.execute(
            "INSERT INTO investigation_coordination_audit"
            "(job_id,event,generation,owner,occurred_at) VALUES(?,?,?,?,?)",
            (job["id"], event, job["lease_generation"], job["lease_owner"], now),
        )

    def preview(self, limit=100):
        bounded(limit, 1000)
        with self.store._connection(readonly=True) as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            return [dict(row) for row in conn.execute(ELIGIBLE, (limit,))]

    def enqueue(self, limit=100, *, max_attempts=3):
        bounded(limit, 1000)
        bounded(max_attempts, 100)
        with self.store._connection() as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            now = self.clock()
            result = []
            for alert in conn.execute(ELIGIBLE, (limit,)).fetchall():
                selection, fingerprint = investigation.request_identity([alert["alert_id"]])
                job_id = str(uuid4())
                conn.execute(
                    "INSERT INTO investigation_jobs(id,request_fingerprint,engine_version,"
                    "selection_json,priority,created_at,available_at,max_attempts) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (
                        job_id,
                        fingerprint,
                        investigation.ENGINE_VERSION,
                        encode(selection),
                        alert["priority"],
                        now,
                        now,
                        max_attempts,
                    ),
                )
                conn.execute(
                    "INSERT INTO investigation_job_alerts VALUES(?,?)", (job_id, alert["alert_id"])
                )
                job = dict(
                    conn.execute(
                        "SELECT * FROM investigation_jobs WHERE id=?", (job_id,)
                    ).fetchone()
                )
                self._audit(conn, job, "enqueued", now)
                result.append(job)
            return result

    def claim(self, owner, *, lease_seconds=60):
        _identifier(owner, 128)
        bounded(lease_seconds, 86400)
        with self.store._connection() as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            now = self.clock()
            row = conn.execute(
                "SELECT * FROM investigation_jobs WHERE state IN ('queued','retry_wait') "
                "AND available_at<=? AND attempt_count<max_attempts "
                "ORDER BY priority,created_at,id LIMIT 1",
                (now,),
            ).fetchone()
            if row is None:
                return None
            if row["engine_version"] != investigation.ENGINE_VERSION:
                raise CoordinationError(FailureCode.ENGINE_MISMATCH)
            conn.execute(
                "UPDATE investigation_jobs SET state='leased',failure_code=NULL,"
                "lease_owner=?,lease_until=?,"
                "lease_generation=lease_generation+1,attempt_count=attempt_count+1 WHERE id=?",
                (owner, now + lease_seconds, row["id"]),
            )
            job = dict(
                conn.execute("SELECT * FROM investigation_jobs WHERE id=?", (row["id"],)).fetchone()
            )
            conn.execute(
                "INSERT INTO investigation_job_attempts VALUES(?,?,?,?,NULL,NULL)",
                (job["id"], job["lease_generation"], owner, now),
            )
            self._audit(conn, job, "claimed", now)
            return job

    def _owned(self, conn, job_id, owner, generation, now):
        row = conn.execute(
            "SELECT * FROM investigation_jobs WHERE id=? AND state='leased' "
            "AND lease_owner=? AND lease_generation=? AND lease_until>?",
            (job_id, owner, generation, now),
        ).fetchone()
        if row is None:
            raise StateError("Lease ownership lost")
        if row["engine_version"] != investigation.ENGINE_VERSION:
            raise CoordinationError(FailureCode.ENGINE_MISMATCH)
        return dict(row)

    def renew(self, job_id, owner, generation, *, lease_seconds=60):
        bounded(lease_seconds, 86400)
        with self.store._connection() as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            now = self.clock()
            job = self._owned(conn, job_id, owner, generation, now)
            until = max(now + lease_seconds, job["lease_until"] + 0.000001)
            conn.execute("UPDATE investigation_jobs SET lease_until=? WHERE id=?", (until, job_id))
            self._audit(conn, job, "renewed", now)
            return until

    def _finish(self, conn, job, now, code, retry_seconds):
        retry = code in (FailureCode.TRANSIENT, FailureCode.LEASE_EXPIRED)
        state = (
            "retry_wait"
            if retry and job["attempt_count"] < job["max_attempts"]
            else "completed"
            if code is None
            else "failed"
        )
        conn.execute(
            "UPDATE investigation_job_attempts SET finished_at=?,outcome=? "
            "WHERE job_id=? AND generation=?",
            (now, code or "completed", job["id"], job["lease_generation"]),
        )
        conn.execute(
            "UPDATE investigation_jobs SET state=?,available_at=?,failure_code=?,"
            "lease_owner=NULL,lease_until=NULL WHERE id=?",
            (state, now + retry_seconds, code, job["id"]),
        )
        self._audit(conn, job, state, now)

    def finish(self, job_id, owner, generation, *, failure=None, retry_seconds=60):
        bounded(retry_seconds, 86400)
        if failure is not None and not isinstance(failure, FailureCode):
            raise ValueError("Typed failure code required")
        with self.store._connection() as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            now = self.clock()
            job = self._owned(conn, job_id, owner, generation, now)
            if failure is None:
                raise StateError(
                    "Successful queue completion requires Milestone 5B report persistence"
                )
            self._finish(conn, job, now, failure, retry_seconds)

    def recover(self, limit=100, *, retry_seconds=60):
        bounded(limit, 1000)
        bounded(retry_seconds, 86400)
        with self.store._connection() as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            now = self.clock()
            rows = conn.execute(
                "SELECT * FROM investigation_jobs WHERE state='leased' AND lease_until<=? "
                "ORDER BY lease_until,id LIMIT ?",
                (now, limit),
            ).fetchall()
            for row in rows:
                self._finish(conn, dict(row), now, FailureCode.LEASE_EXPIRED, retry_seconds)
            return len(rows)

    def inspect(self, job_id):
        with self.store._connection(readonly=True) as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            row = conn.execute("SELECT * FROM investigation_jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise StateError("Unknown investigation job")
            result = dict(row)
            result["selection"] = json.loads(result.pop("selection_json"))
            result["attempts"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM investigation_job_attempts WHERE job_id=? ORDER BY generation",
                    (job_id,),
                )
            ]
            result["audit"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM investigation_coordination_audit WHERE job_id=? ORDER BY id",
                    (job_id,),
                )
            ]
            return result

    def list_jobs(self, limit=100):
        bounded(limit, 1000)
        with self.store._connection(readonly=True) as conn:
            conn.create_function("coordination_now", 0, self.clock)
            self.store._validate(conn)
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM investigation_jobs ORDER BY created_at,id LIMIT ?", (limit,)
                )
            ]
