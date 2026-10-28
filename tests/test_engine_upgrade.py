"""Engine upgrade compatibility using offline evidence and temporary SQLite only."""

import json
from pathlib import Path

import pytest

from soc_automation import investigation
from soc_automation.coordination import FailureCode, InvestigationQueue
from soc_automation.evidence import FixtureEvidenceProvider
from soc_automation.service import ingest, investigate
from soc_automation.state import Store
from soc_automation.triage import Policy
from soc_automation.worker import InvestigationWorker

FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.mark.parametrize("pending", ["queued", "delayed_retry", "expired_lease"])
def test_legacy_job_terminal_mismatch_and_explicit_manual_investigation(
    tmp_path, monkeypatch, pending
):
    store = Store(tmp_path / "upgrade.db")
    store.initialize()
    source = json.loads((FIXTURES / "stages.json").read_text())[0]
    identifier = ingest(store, json.dumps(source).encode(), policy=Policy(default_priority="P2"))[
        0
    ]["alert_id"]
    now = [1000.0]
    q = InvestigationQueue(store, clock=lambda: now[0])
    provider = FixtureEvidenceProvider(FIXTURES / "evidence")
    with monkeypatch.context() as legacy:
        legacy.setattr(investigation, "ENGINE_VERSION", "3.0")
        job = q.enqueue(1, max_attempts=3)[0]
        # Retain a real historical report without excluding the already enqueued job.
        historical = investigate(store, [identifier], provider)
        if pending != "queued":
            q.claim("legacy", lease_seconds=10)
        if pending == "delayed_retry":
            q.finish(job["id"], "legacy", 1, failure=FailureCode.TRANSIENT, retry_seconds=10)

    assert investigation.ENGINE_VERSION == "3.1"
    with store._connection(readonly=True) as conn:
        historical_rows = {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()  # noqa: S608
            for table in (
                "investigations",
                "investigation_alerts",
                "investigation_references",
                "investigation_evidence",
                "investigation_audit",
                "investigation_job_alerts",
            )
        }

    class ForbiddenProvider:
        def retrieve_many(self, references):
            raise AssertionError("Mismatched jobs must not retrieve evidence")

    worker = InvestigationWorker(store, ForbiddenProvider(), clock=q.clock, owner="current")
    if pending != "queued":
        before = q.inspect(job["id"])
        assert worker.run() == []
        assert q.inspect(job["id"]) == before
        now[0] += 10
        if pending == "expired_lease":
            assert worker.run() == []  # Workers do not recover leases.
            assert q.recover(retry_seconds=5) == 1
            recovered = q.inspect(job["id"])
            assert recovered["state"] == "retry_wait"
            assert recovered["failure_code"] == "lease_expired"
            assert recovered["attempt_count"] == recovered["lease_generation"] == 1
            assert recovered["attempts"][0]["outcome"] == "lease_expired"
            assert worker.run() == []
            now[0] += 5
        assert q.health()["ready_retries"] == 1

    prior = q.inspect(job["id"])
    failed = worker.run()[0]
    generation = 1 if pending == "queued" else 2
    assert failed["id"] == job["id"]
    assert failed["engine_version"] == "3.0"
    assert failed["request_fingerprint"] == job["request_fingerprint"]
    assert failed["state"] == "failed"
    assert failed["failure_code"] == "engine_mismatch"
    assert failed["investigation_id"] is None
    assert failed["lease_owner"] is failed["lease_until"] is None
    assert failed["attempt_count"] == failed["lease_generation"] == generation
    assert failed["attempt_count"] < failed["max_attempts"]
    assert failed["attempts"][:-1] == prior["attempts"]
    assert failed["attempts"][-1] == {
        "job_id": job["id"],
        "generation": generation,
        "owner": "current",
        "started_at": now[0],
        "finished_at": now[0],
        "outcome": "engine_mismatch",
    }
    expected_events = ["enqueued"]
    if pending != "queued":
        expected_events += ["claimed", "retry_wait"]
    expected_events += ["claimed", "failed"]
    assert [entry["event"] for entry in failed["audit"]] == expected_events
    assert failed["audit"][:-2] == prior["audit"]
    assert [(a["generation"], a["owner"], a["occurred_at"]) for a in failed["audit"][-2:]] == [
        (generation, "current", now[0]),
        (generation, "current", now[0]),
    ]

    now[0] += 1000
    assert q.recover(retry_seconds=1) == 0
    assert q.preview() == q.enqueue() == []
    assert q.claim("another") is None
    assert worker.run() == []
    assert q.inspect(job["id"]) == failed

    corrected = investigate(store, failed["selection"], provider)
    assert corrected["engine_version"] == "3.1"
    assert corrected["status"] == "completed"
    assert corrected["source_alert_ids"] == historical["source_alert_ids"]
    assert corrected["investigation_id"] != historical["investigation_id"]
    assert corrected["request_fingerprint"] != historical["request_fingerprint"]
    assert investigate(store, failed["selection"], provider) == corrected
    assert store.show_investigation(historical["investigation_id"]) == historical
    assert q.inspect(job["id"]) == failed
    assert q.preview() == q.enqueue() == []
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM investigation_jobs").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM investigations").fetchone()[0] == 2
        for table, rows in historical_rows.items():
            current = conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()  # noqa: S608
            assert current[: len(rows)] == rows
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_failed_legacy_membership_alone_blocks_replacement(tmp_path, monkeypatch):
    store = Store(tmp_path / "membership.db")
    store.initialize()
    source = json.loads((FIXTURES / "stages.json").read_text())[0]
    identifier = ingest(store, json.dumps(source).encode(), policy=Policy(default_priority="P2"))[
        0
    ]["alert_id"]
    q = InvestigationQueue(store, clock=lambda: 1000.0)
    with monkeypatch.context() as legacy:
        legacy.setattr(investigation, "ENGINE_VERSION", "3.0")
        job = q.enqueue(1)[0]
    # No provider interface: mismatch must finish before any evidence retrieval.
    failed = InvestigationWorker(store, object(), clock=q.clock).run()[0]
    assert failed["failure_code"] == "engine_mismatch"
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT state FROM alerts WHERE id=?", (identifier,)).fetchone()[0] == (
            "triaged"
        )
        assert conn.execute("SELECT count(*) FROM investigation_alerts").fetchone()[0] == 0
        assert [tuple(r) for r in conn.execute("SELECT * FROM investigation_job_alerts")] == [
            (job["id"], identifier)
        ]
    assert q.recover() == 0
    assert q.preview() == q.enqueue() == []
    assert q.inspect(job["id"]) == failed
