"""Transactional persistent state and migration ownership."""

import hashlib
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

TRANSITIONS = {
    "registered": frozenset({"triaged", "failed"}),
    "triaged": frozenset({"investigating", "failed"}),
    "investigating": frozenset({"completed", "failed"}),
    "completed": frozenset(),
    "failed": frozenset(),
}
SCHEMA_VERSION = 8


class StateError(RuntimeError):
    """Persistent state is missing, incompatible, or invalid."""


class EvidenceConflict(StateError):
    """Immutable persisted evidence differs from the supplied snapshot."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _identifier(value: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("Invalid identifier")
    if any(ord(char) < 32 for char in value):
        raise ValueError("Invalid identifier")
    return value


def _canonical_case_target(value):
    """Validate the existing canonical destination format at the SQL boundary."""
    from soc_automation.config import ConfigurationError, KibanaTargetSettings

    suffix = "/default/securitySolution"
    if not isinstance(value, str) or not value.endswith(suffix):
        return False
    try:
        return KibanaTargetSettings(value[:-len(suffix)]).target == value
    except (ConfigurationError, ValueError, TypeError):
        return False


class Store:
    def __init__(self, path: Path, timeout: int = 5):
        self.path = Path(path)
        self.timeout = timeout

    @contextmanager
    def _connection(
        self, *, create: bool = False, readonly: bool = False
    ) -> Iterator[sqlite3.Connection]:
        # URI mode=rw avoids creating an empty database on health checks or ordinary operations.
        target = self.path.as_uri() + (
            "?mode=rwc" if create else "?mode=ro" if readonly else "?mode=rw"
        )
        connection = sqlite3.connect(target, uri=True, timeout=self.timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.create_function("coordination_now", 0, time.time)
        connection.create_function(
            "sha256_text",
            1,
            lambda value: hashlib.sha256(value.encode()).hexdigest(),
            deterministic=True,
        )
        connection.create_function("canonical_case_target", 1, _canonical_case_target,
                                   deterministic=True)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN" if readonly else "BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection(create=True) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise StateError("Database schema is newer than this application")
            for number in range(version + 1, SCHEMA_VERSION + 1):
                migration = (
                    files("soc_automation")
                    .joinpath(f"migrations/{number:03d}_initial.sql")
                    .read_text(encoding="utf-8")
                )
                # executescript implicitly commits; execute complete statements individually.
                statement = ""
                for line in migration.splitlines(keepends=True):
                    statement += line
                    if sqlite3.complete_statement(statement):
                        connection.execute(statement)
                        statement = ""
                if statement.strip():
                    raise StateError("Incomplete migration")
                connection.execute(f"PRAGMA user_version={number}")
            self._validate(connection)

    @staticmethod
    def _validate(connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise StateError("Database must be initialized with a supported schema")
        expected = {
            "case_preparation_jobs",
            "case_preparation_ready",
            "case_preparation_publication",
            "case_preparation_audit",
            "case_preparation_audit_job",
            "preparation_initial",
            "preparation_identity",
            "preparation_transition",
            "preparation_completion",
            "preparation_audit_insert",
            "preparation_audit_transition",
            "preparation_audit_guard",
            "review_sequence",
            "case_review_events",
            "case_review_publication",
            "review_initial",
            "publication_approval_guard",
            "publication_head_insert",
            "preparation_no_delete",
            "preparation_audit_no_update",
            "preparation_audit_no_delete",
            "review_no_update",
            "review_no_delete",
            "investigation_job_report_initial",
            "investigation_job_report_guard",
            "investigation_jobs_ready",
            "investigation_job_initial",
            "investigation_job_no_delete",
            "investigation_membership_guard",
            "investigation_membership_no_update",
            "investigation_membership_no_delete",
            "investigation_attempt_guard",
            "investigation_attempt_no_delete",
            "investigation_attempt_initial",
            "investigation_job_lease_time",
            "investigation_job_terminal",
            "investigation_jobs",
            "investigation_job_alerts",
            "investigation_job_attempts",
            "investigation_coordination_audit",
            "investigation_job_transition",
            "investigation_job_identity",
            "investigation_coordination_no_update",
            "investigation_coordination_no_delete",
            "case_publications",
            "publication_heads",
            "publication_head_forward",
            "publication_marker_unique",
            "publication_current_claim",
            "publication_head_guard",
            "publication_head_no_delete",
            "case_publication_audit",
            "publication_transition",
            "publication_initial_state",
            "publication_audit_insert",
            "publication_audit_transition",
            "publication_frozen",
            "publication_no_delete",
            "publication_audit_no_update",
            "publication_audit_no_delete",
            "alerts",
            "audit_records",
            "audit_alert_id",
            "validate_alert_transition",
            "audit_registration",
            "audit_transition",
            "audit_no_update",
            "audit_no_delete",
            "investigation_alerts",
            "investigations",
            "investigation_evidence",
            "investigation_references",
            "investigation_audit",
            "ingested_alerts",
            "ingestion_audit",
            "ingestion_no_update",
            "ingestion_no_delete",
            "ingestion_audit_no_update",
            "ingestion_audit_no_delete",
        }
        present = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        if not expected <= present:
            raise StateError("Database schema objects are missing")

    def healthcheck(self) -> None:
        with self._connection() as connection:
            self._validate(connection)
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise StateError("Database integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise StateError("Database reference check failed")

    def register_alert(
        self, source: str, source_alert_id: str, correlation_id: str | None = None
    ) -> dict:
        source = _identifier(source, 128)
        source_alert_id = _identifier(source_alert_id, 512)
        correlation_id = (
            _identifier(correlation_id, 128) if correlation_id is not None else str(uuid4())
        )
        with self._connection() as connection:
            self._validate(connection)
            now = _timestamp()
            connection.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, 'registered', ?, ?) "
                "ON CONFLICT(source, source_alert_id) DO NOTHING",
                (str(uuid4()), source, source_alert_id, correlation_id, now, now),
            )
            return dict(
                connection.execute(
                    "SELECT * FROM alerts WHERE source=? AND source_alert_id=?",
                    (source, source_alert_id),
                ).fetchone()
            )

    def transition(self, alert_id: str, new_state: str) -> dict:
        with self._connection() as connection:
            self._validate(connection)
            row = connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if row is None:
                raise StateError("Unknown alert")
            if new_state not in TRANSITIONS[row["state"]]:
                raise StateError("Invalid processing transition")
            connection.execute(
                "UPDATE alerts SET state=?, updated_at=? WHERE id=?",
                (new_state, _timestamp(), alert_id),
            )
            return dict(
                connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            )

    def audit_records(self, alert_id: str) -> list[dict]:
        with self._connection() as connection:
            self._validate(connection)
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM audit_records WHERE alert_id=? ORDER BY id", (alert_id,)
                )
            ]

    def rejection(self) -> None:
        """Persist a fixed reason only, never submitted input or exception text."""
        with self._connection() as connection:
            self._validate(connection)
            connection.execute(
                "INSERT INTO ingestion_audit(alert_id,event,reason,occurred_at) "
                "VALUES(NULL,'rejected','input_or_identity_rejected',?)",
                (_timestamp(),),
            )

    def ingest_batch(self, prepared: list[tuple]) -> list[dict]:
        """Register evidence, decision and transition in one batch transaction."""
        import hashlib
        import json
        from dataclasses import asdict

        from soc_automation.ingestion import encode

        results = []
        with self._connection() as connection:
            self._validate(connection)
            for alert, original, decision in prepared:
                identity = hashlib.sha256(
                    encode([alert.source_index, alert.source_alert_id]).encode()
                ).hexdigest()
                row = connection.execute(
                    "SELECT a.*, i.original_sha256, i.decision_json FROM alerts a "
                    "LEFT JOIN ingested_alerts i ON i.alert_id=a.id "
                    "WHERE a.source=? AND a.source_alert_id=?",
                    (alert.source_system, identity),
                ).fetchone()
                now = _timestamp()
                if row is not None:
                    if row["original_sha256"] != alert.original_ref:
                        raise StateError("Source identity already has different evidence")
                    connection.execute(
                        "INSERT INTO ingestion_audit(alert_id,event,reason,occurred_at) "
                        "VALUES(?,'duplicate','original_decision_retained',?)",
                        (row["id"], now),
                    )
                    results.append(
                        {
                            "alert_id": row["id"],
                            "duplicate": True,
                            "decision": json.loads(row["decision_json"]),
                        }
                    )
                    continue
                alert_id = str(uuid4())
                connection.execute(
                    "INSERT INTO alerts VALUES(?,?,?,?,'registered',?,?)",
                    (alert_id, alert.source_system, identity, str(uuid4()), now, now),
                )
                connection.execute(
                    "INSERT INTO ingested_alerts VALUES(?,?,?,?,?,?,?)",
                    (
                        alert_id,
                        alert.source_index,
                        alert.source_alert_id,
                        original,
                        alert.original_ref,
                        encode(asdict(alert)),
                        encode(decision),
                    ),
                )
                for event, reason in (
                    ("ingested", "offline_input"),
                    ("triaged", "policy_decision"),
                ):
                    connection.execute(
                        "INSERT INTO ingestion_audit(alert_id,event,reason,occurred_at) "
                        "VALUES(?,?,?,?)",
                        (alert_id, event, reason, now),
                    )
                connection.execute(
                    "UPDATE alerts SET state='triaged',updated_at=? WHERE id=?", (now, alert_id)
                )
                results.append({"alert_id": alert_id, "duplicate": False, "decision": decision})
        return results

    def show_alert(self, alert_id: str, *, evidence: bool = False) -> dict:
        """Allowlisted summary by default; evidence retrieval is an explicit Python API."""
        import json

        with self._connection() as connection:
            self._validate(connection)
            row = connection.execute(
                "SELECT a.state, i.* FROM alerts a JOIN ingested_alerts i ON i.alert_id=a.id "
                "WHERE a.id=?",
                (alert_id,),
            ).fetchone()
            if row is None:
                raise StateError("Unknown ingested alert")
            result = {
                "alert_id": row["alert_id"],
                "state": row["state"],
                "original_ref": row["original_sha256"],
                "decision": json.loads(row["decision_json"]),
            }
            if evidence:
                result["normalized"] = json.loads(row["normalized_json"])
                result["original"] = json.loads(row["original_json"])
            return result

    def show_investigation(self, investigation_id: str) -> dict:
        import json

        with self._connection() as connection:
            self._validate(connection)
            row = connection.execute(
                "SELECT report_json FROM investigations WHERE id=?", (investigation_id,)
            ).fetchone()
            if row is None:
                raise StateError("Unknown investigation")
            return json.loads(row[0])

    def investigation_failure(self, correlation_id: str) -> None:
        with self._connection() as connection:
            self._validate(connection)
            connection.execute(
                "INSERT INTO investigation_audit"
                "(investigation_id,correlation_id,event,occurred_at) "
                "VALUES(NULL,?,'failed',?)",
                (correlation_id, _timestamp()),
            )

    def save_investigation(self, report: dict, fingerprint: str) -> dict:
        with self._connection() as connection:
            self._validate(connection)
            return self._save_investigation(connection, report, fingerprint)

    def _save_investigation(self, connection, report, fingerprint):
        """Persist under the caller's transaction, preserving immutable evidence."""
        import hashlib
        import json

        from soc_automation.ingestion import encode

        snapshot = hashlib.sha256(encode(report["retrieved_evidence"]).encode()).hexdigest()
        for item in report["retrieved_evidence"]:
            if item["status"] != "found":
                continue
            ref = item["reference"]
            prior = connection.execute(
                "SELECT sha256 FROM investigation_evidence WHERE source_index=? AND document_id=?",
                (ref["index"], ref["id"]),
            ).fetchone()
            if prior is not None and prior[0] != item["sha256"]:
                raise EvidenceConflict("Conflicting source evidence")
            connection.execute(
                "INSERT OR IGNORE INTO investigation_evidence VALUES(?,?,?,?)",
                (ref["index"], ref["id"], item["sha256"], encode(item["document"])),
            )
        prior = connection.execute(
            "SELECT * FROM investigations WHERE request_fingerprint=?", (fingerprint,)
        ).fetchone()
        if prior is not None:
            if prior["evidence_fingerprint"] != snapshot:
                raise EvidenceConflict("Investigation evidence changed")
            result = json.loads(prior["report_json"])
            event = "duplicate"
        else:
            result = report
            connection.execute(
                "INSERT INTO investigations VALUES(?,?,?,?)",
                (report["investigation_id"], fingerprint, encode(report), snapshot),
            )
            for ref in report["evidence_references"]:
                connection.execute(
                    "INSERT INTO investigation_references VALUES(?,?,?)",
                    (report["investigation_id"], ref["alert_id"], encode(ref)),
                )
            for alert_id in report["source_alert_ids"]:
                connection.execute(
                    "INSERT INTO investigation_alerts VALUES(?,?)",
                    (report["investigation_id"], alert_id),
                )
                row = connection.execute(
                    "SELECT state FROM alerts WHERE id=?", (alert_id,)
                ).fetchone()
                if row[0] == "triaged":
                    connection.execute(
                        "UPDATE alerts SET state='investigating',updated_at=? WHERE id=?",
                        (_timestamp(), alert_id),
                    )
            event = "completed"
        connection.execute(
            "INSERT INTO investigation_audit"
            "(investigation_id,correlation_id,event,occurred_at) "
            "VALUES(?,?,?,?)",
            (result["investigation_id"], report["audit_correlation_id"], event, _timestamp()),
        )
        return result

    def prepare_publication(self, investigation_id, target, payload, *, revise=False):
        from soc_automation.cases import digest
        from soc_automation.ingestion import encode

        with self._connection() as connection:
            self._validate(connection)
            previous = connection.execute(
                "SELECT p.* FROM case_publications p JOIN publication_heads h "
                "ON p.id=h.publication_id WHERE h.investigation_id=? AND h.target=?",
                (investigation_id, target),
            ).fetchone()
            if previous is not None:
                if previous["payload_json"] == encode(payload):
                    return dict(previous)
                if not revise:
                    raise StateError("Frozen publication differs; explicitly prepare a revision")
                if connection.execute(
                    "SELECT 1 FROM case_publications WHERE investigation_id=? AND target=? "
                    "AND state!='prepared'",
                    (investigation_id, target),
                ).fetchone():
                    raise StateError("Revision prohibited after send")
            identifier = str(uuid4())
            connection.execute(
                "INSERT INTO case_publications VALUES(?,?,?,?,?,NULL,'prepared',NULL,NULL,?)",
                (
                    identifier,
                    investigation_id,
                    target,
                    encode(payload),
                    digest(payload),
                    _timestamp(),
                ),
            )
            connection.execute(
                "INSERT INTO publication_heads VALUES(?,?,?) "
                "ON CONFLICT(investigation_id,target) DO UPDATE "
                "SET publication_id=excluded.publication_id",
                (investigation_id, target, identifier),
            )
            return dict(
                connection.execute(
                    "SELECT * FROM case_publications WHERE id=?", (identifier,)
                ).fetchone()
            )

    def show_case_publication(self, publication_id):
        with self._connection() as connection:
            self._validate(connection)
            row = connection.execute(
                "SELECT * FROM case_publications WHERE id=?", (publication_id,)
            ).fetchone()
            if row is None:
                raise StateError("Unknown publication")
            result = dict(row)
            result["audit"] = [
                dict(r)
                for r in connection.execute(
                    "SELECT * FROM case_publication_audit WHERE publication_id=? ORDER BY id",
                    (publication_id,),
                )
            ]
            return result

    def claim_publication(self, publication_id, approval_hash):
        with self._connection() as connection:
            self._validate(connection)
            cursor = connection.execute(
                "UPDATE case_publications SET state='sending',approval_sha256=? "
                "WHERE id=? AND state='prepared' AND payload_sha256=? "
                "AND id IN (SELECT publication_id FROM publication_heads)",
                (approval_hash, publication_id, approval_hash),
            )
            return cursor.rowcount == 1

    def publication_outcome(self, publication_id, receipt=None):
        with self._connection() as connection:
            self._validate(connection)
            if receipt is None:
                connection.execute(
                    "UPDATE case_publications SET state='uncertain' WHERE id=? AND state='sending'",
                    (publication_id,),
                )
            else:
                connection.execute(
                    "UPDATE case_publications SET state='published',"
                    "remote_case_id=?,remote_version=? "
                    "WHERE id=? AND state IN ('sending','uncertain')",
                    (receipt["id"], receipt["version"], publication_id),
                )

    def validate_case_evidence(self, report):
        """Cross-check the immutable report against the separately stored evidence ledger."""
        with self._connection() as connection:
            self._validate(connection)
            self._validate_report_evidence(connection, report)

    def _validate_report_evidence(self, connection, report, *, allow_gaps=False):
        from soc_automation.cases import digest
        from soc_automation.ingestion import encode

        row = connection.execute(
            "SELECT evidence_fingerprint FROM investigations WHERE id=?",
            (report["investigation_id"],),
        ).fetchone()
        if row is None or row[0] != digest(report["retrieved_evidence"]):
            raise StateError("Investigation snapshot mismatch")
        for item in report["retrieved_evidence"]:
            if allow_gaps and item["status"] != "found":
                continue
            ref = item["reference"]
            saved = connection.execute(
                "SELECT sha256,original_json FROM investigation_evidence "
                "WHERE source_index=? AND document_id=?",
                (ref["index"], ref["id"]),
            ).fetchone()
            if (
                saved is None
                or saved[0] != item.get("sha256")
                or saved[1] != encode(item.get("document"))
            ):
                raise StateError("Stored evidence mismatch")
