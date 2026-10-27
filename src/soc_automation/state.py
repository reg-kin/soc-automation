"""Transactional persistent state and migration ownership."""

import sqlite3
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
SCHEMA_VERSION = 3


class StateError(RuntimeError):
    """Persistent state is missing, incompatible, or invalid."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _identifier(value: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("Invalid identifier")
    if any(ord(char) < 32 for char in value):
        raise ValueError("Invalid identifier")
    return value


class Store:
    def __init__(self, path: Path, timeout: int = 5):
        self.path = Path(path)
        self.timeout = timeout

    @contextmanager
    def _connection(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        # URI mode=rw avoids creating an empty database on health checks or ordinary operations.
        target = self.path.as_uri() + ("?mode=rwc" if create else "?mode=rw")
        connection = sqlite3.connect(target, uri=True, timeout=self.timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
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
        import hashlib
        import json

        from soc_automation.ingestion import encode

        snapshot = hashlib.sha256(encode(report["retrieved_evidence"]).encode()).hexdigest()
        with self._connection() as connection:
            self._validate(connection)
            for item in report["retrieved_evidence"]:
                if item["status"] != "found":
                    continue
                ref = item["reference"]
                prior = connection.execute(
                    "SELECT sha256 FROM investigation_evidence "
                    "WHERE source_index=? AND document_id=?",
                    (ref["index"], ref["id"]),
                ).fetchone()
                if prior is not None and prior[0] != item["sha256"]:
                    raise StateError("Conflicting source evidence")
                connection.execute(
                    "INSERT OR IGNORE INTO investigation_evidence VALUES(?,?,?,?)",
                    (ref["index"], ref["id"], item["sha256"], encode(item["document"])),
                )
            prior = connection.execute(
                "SELECT * FROM investigations WHERE request_fingerprint=?", (fingerprint,)
            ).fetchone()
            if prior is not None:
                if prior["evidence_fingerprint"] != snapshot:
                    raise StateError("Investigation evidence changed")
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
