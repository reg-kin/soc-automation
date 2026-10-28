"""Transactional preparation persistence only; no worker, polling or network access."""

import hashlib
import json
import math
import time
from uuid import uuid4

SUMMARY = (
    "id,investigation_id,target,renderer_version,report_sha256,evidence_fingerprint,"
    "audit_sequence,created_at,state,available_at,max_attempts,attempt_count,"
    "lease_generation,lease_owner,lease_until,failure_code,publication_id"
)
READY = "state IN ('queued','retry_wait') AND available_at<=? AND attempt_count<max_attempts"


def _bound(value, maximum=1000):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("Invalid bound")
    return value


class PreparationStore:
    """Store mixin. All mutations use Store's immediate transaction boundary."""

    def _preparation_row(self, conn, job_id, *, snapshot=False):
        from soc_automation.state import StateError

        row = conn.execute(
            f"SELECT {'*' if snapshot else SUMMARY} FROM case_preparation_jobs WHERE id=?",  # noqa: S608
            (job_id,),
        ).fetchone()
        if row is None:
            raise StateError("Unknown preparation job")
        return dict(row)

    def _preparation_payload(self, conn, report):
        from soc_automation.cases import ReportIneligible, render
        from soc_automation.state import StateError

        if report["status"] != "completed" or report["evidence_gaps"]:
            raise ReportIneligible("Incomplete investigation report")
        self._validate_report_evidence(conn, report)
        alerts = []
        for identifier in report["source_alert_ids"]:
            row = conn.execute(
                "SELECT a.state,i.* FROM alerts a JOIN ingested_alerts i ON i.alert_id=a.id "
                "WHERE a.id=?", (identifier,),
            ).fetchone()
            if row is None:
                raise StateError("Missing persisted alert")
            alerts.append({
                "alert_id": identifier, "state": row["state"],
                "original_ref": row["original_sha256"],
                "decision": json.loads(row["decision_json"]),
                "normalized": json.loads(row["normalized_json"]),
                "original": json.loads(row["original_json"]),
            })
        return render(report, alerts)

    def enqueue_case_preparation(self, investigation_id, target, *, max_attempts=3):
        """Freeze an eligible persisted report; identical identity retains its original budget."""
        from soc_automation.state import _canonical_case_target

        _bound(max_attempts, 100)
        if not _canonical_case_target(target):
            raise ValueError("Canonical case target required")
        with self._connection() as conn:
            self._validate(conn)
            return self._enqueue_case_preparation(conn, investigation_id, target, max_attempts)

    def _enqueue_case_preparation(self, conn, investigation_id, target, max_attempts):
        from soc_automation.cases import RENDERER_VERSION
        from soc_automation.state import EvidenceConflict, StateError

        row = conn.execute(
            "SELECT * FROM investigations WHERE id=?", (investigation_id,),
        ).fetchone()
        if row is None:
            raise StateError("Unknown investigation")
        self._preparation_payload(conn, json.loads(row["report_json"]))
        digest = hashlib.sha256(row["report_json"].encode()).hexdigest()
        prior = conn.execute(
            "SELECT * FROM case_preparation_jobs WHERE investigation_id=? AND target=? "
            "AND renderer_version=? ORDER BY created_at,id LIMIT 1",
            (investigation_id, target, RENDERER_VERSION),
        ).fetchone()
        if prior is not None:
            if (prior["report_json"] != row["report_json"]
                    or prior["evidence_fingerprint"] != row["evidence_fingerprint"]):
                raise EvidenceConflict("Preparation snapshot changed")
            return self._preparation_row(conn, prior["id"])
        identifier = str(uuid4())
        conn.execute(
            "INSERT INTO case_preparation_jobs(id,investigation_id,target,renderer_version,"
            "report_json,report_sha256,evidence_fingerprint,created_at,"
            "available_at,max_attempts) "
            "VALUES(?,?,?,?,?,?,?,coordination_now(),coordination_now(),?)",
            (identifier, investigation_id, target, RENDERER_VERSION, row["report_json"],
             digest, row["evidence_fingerprint"], max_attempts),
        )
        return self._preparation_row(conn, identifier)

    def claim_case_preparation(self, *, lease_seconds=60):
        """Claim one ready job with a new opaque owner token; return None when none is ready."""
        _bound(lease_seconds, 86400)
        with self._connection() as conn:
            self._validate(conn)
            row = conn.execute(
                f"SELECT id FROM case_preparation_jobs WHERE {READY} "  # noqa: S608
                "ORDER BY available_at,created_at,id LIMIT 1", (time.time(),),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE case_preparation_jobs SET state='leased',failure_code=NULL,lease_owner=?,"
                "lease_until=coordination_now()+?,attempt_count=attempt_count+1,"
                "lease_generation=lease_generation+1,audit_sequence=audit_sequence+1 WHERE id=?",
                (str(uuid4()), lease_seconds, row["id"]),
            )
            return self._preparation_row(conn, row["id"], snapshot=True)

    def _preparation_owned(self, conn, job_id, owner, generation):
        from soc_automation.state import StateError, _identifier

        _identifier(owner, 128)
        _bound(generation, 100)
        job = self._preparation_row(conn, job_id, snapshot=True)
        if (job["state"] != "leased" or job["lease_owner"] != owner
                or job["lease_generation"] != generation or job["lease_until"] <= time.time()):
            raise StateError("Preparation lease ownership lost")
        return job

    def renew_case_preparation(self, job_id, owner, generation, *, lease_seconds=60):
        """Extend an exact, unexpired lease monotonically; audit every renewal."""
        _bound(lease_seconds, 86400)
        with self._connection() as conn:
            self._validate(conn)
            job = self._preparation_owned(conn, job_id, owner, generation)
            until = max(time.time() + lease_seconds, math.nextafter(job["lease_until"], math.inf))
            cursor = conn.execute(
                "UPDATE case_preparation_jobs SET lease_until=?,audit_sequence=audit_sequence+1 "
                "WHERE id=? AND state='leased' AND lease_owner=? AND lease_generation=?",
                (until, job_id, owner, generation),
            )
            self._preparation_updated(cursor)
            return self._preparation_row(conn, job_id)

    @staticmethod
    def _preparation_updated(cursor):
        from soc_automation.state import StateError

        if cursor.rowcount != 1:
            raise StateError("Preparation lease ownership lost")

    def _preparation_failure(self, conn, job, code):
        retry = (code in ("transient", "lease_expired")
                 and job["attempt_count"] < job["max_attempts"])
        cursor = conn.execute(
            "UPDATE case_preparation_jobs SET state=?,failure_code=?,lease_owner=NULL,"
            "lease_until=NULL,available_at=CASE WHEN ? THEN coordination_now()+? "
            "ELSE available_at END,audit_sequence=audit_sequence+1 "
            "WHERE id=? AND state='leased' AND lease_owner=? AND lease_generation=?",
            ("retry_wait" if retry else "failed", code, retry,
             60 * 2 ** (job["attempt_count"] - 1), job["id"],
             job["lease_owner"], job["lease_generation"]),
        )
        self._preparation_updated(cursor)

    def fail_case_preparation(self, job_id, owner, generation, *, failure):
        """Fail an exact live lease; only transient failures retry, with exponential backoff."""
        if failure not in ("transient", "permanent", "renderer_mismatch"):
            raise ValueError("Invalid preparation failure code")
        with self._connection() as conn:
            self._validate(conn)
            job = self._preparation_owned(conn, job_id, owner, generation)
            self._preparation_failure(conn, job, failure)
            return self._preparation_row(conn, job_id)

    def recover_case_preparations(self, *, limit=100):
        """Recover a bounded batch of expired leases; preserve terminating owner in audit."""
        _bound(limit)
        with self._connection() as conn:
            self._validate(conn)
            rows = conn.execute(
                "SELECT * FROM case_preparation_jobs WHERE state='leased' "
                "AND lease_until<=coordination_now() ORDER BY lease_until,id LIMIT ?", (limit,),
            ).fetchall()
            for row in rows:
                self._preparation_failure(conn, row, "lease_expired")
            return len(rows)

    def complete_case_preparation(self, job_id, owner, generation, *, payload=None,
                                  publication_id=None):
        """Atomically prepare or adopt the current matching publication and complete a live lease.

        Supply exactly one payload or publication ID. No implicit revisions are permitted.
        """
        from soc_automation.cases import RENDERER_VERSION
        from soc_automation.ingestion import encode
        from soc_automation.state import EvidenceConflict, StateError

        if (payload is None) == (publication_id is None):
            raise ValueError("Supply payload or publication ID")
        with self._connection() as conn:
            self._validate(conn)
            job = self._preparation_owned(conn, job_id, owner, generation)
            if job["renderer_version"] != RENDERER_VERSION:
                raise StateError("Preparation renderer mismatch")
            current = conn.execute(
                "SELECT * FROM investigations WHERE id=?", (job["investigation_id"],),
            ).fetchone()
            if (current is None or current["report_json"] != job["report_json"]
                    or current["evidence_fingerprint"] != job["evidence_fingerprint"]
                    or hashlib.sha256(job["report_json"].encode()).hexdigest()
                    != job["report_sha256"]):
                raise EvidenceConflict("Preparation snapshot changed")
            expected = self._preparation_payload(conn, json.loads(job["report_json"]))
            if payload is not None:
                if encode(payload) != encode(expected):
                    raise StateError("Preparation payload mismatch")
                publication = self._prepare_publication(
                    conn, job["investigation_id"], job["target"], payload,
                )
                publication_id = publication["id"]
            else:
                publication = conn.execute(
                    "SELECT * FROM case_publications WHERE id=?", (publication_id,),
                ).fetchone()
                if publication is None or publication["payload_json"] != encode(expected):
                    raise StateError("Preparation publication mismatch")
            self._preparation_owned(conn, job_id, owner, generation)
            # Schema 8 validates the current prepared head, investigation and target.
            # Exact rendering is checked above; retain the database association guard.
            cursor = conn.execute(
                "UPDATE case_preparation_jobs SET state='completed',publication_id=?,"
                "lease_owner=NULL,lease_until=NULL,audit_sequence=audit_sequence+1 "
                "WHERE id=? AND state='leased' AND lease_owner=? AND lease_generation=?",
                (publication_id, job_id, owner, generation),
            )
            self._preparation_updated(cursor)
            if time.time() >= job["lease_until"]:
                raise StateError("Preparation lease ownership lost")
            return self._preparation_row(conn, job_id)

    def show_case_preparation(self, job_id, *, snapshot=False):
        """Read job metadata; frozen report text requires explicit snapshot=True."""
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            return self._preparation_row(conn, job_id, snapshot=snapshot)

    def case_preparation_audit(self, job_id, *, after_id=0, limit=100):
        """Read append-only audit with bounded keyset pagination."""
        _bound(limit)
        if type(after_id) is not int or after_id < 0:
            raise ValueError("Invalid audit cursor")
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            self._preparation_row(conn, job_id)
            return [dict(row) for row in conn.execute(
                "SELECT * FROM case_preparation_audit WHERE job_id=? AND id>? ORDER BY id LIMIT ?",
                (job_id, after_id, limit),
            )]

    def eligible_case_preparations(self, *, limit=100):
        """Bounded ready-job metadata, ordered identically to claims."""
        _bound(limit)
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            return [dict(row) for row in conn.execute(
                f"SELECT {SUMMARY} FROM case_preparation_jobs WHERE {READY} "  # noqa: S608
                "ORDER BY available_at,created_at,id LIMIT ?", (time.time(), limit),
            )]

    def case_preparation_stats(self):
        """Fixed-size state counts and readiness/expiry totals in one read snapshot."""
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            counts = dict.fromkeys(("queued", "leased", "retry_wait", "completed", "failed"), 0)
            counts.update(dict(conn.execute(
                "SELECT state,count(*) FROM case_preparation_jobs GROUP BY state"
            )))
            return {"state_counts": counts, **dict(conn.execute(
                "SELECT coalesce(sum(" + READY + "),0) AS eligible,"
                "coalesce(sum(state='leased' AND lease_until<=?),0) AS expired "
                "FROM case_preparation_jobs", (time.time(), time.time()),
            ).fetchone())}
