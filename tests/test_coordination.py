"""Offline queue contracts using temporary databases and a deterministic clock."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import pytest

from soc_automation import investigation, state
from soc_automation.coordination import FailureCode, InvestigationQueue
from soc_automation.evidence import FixtureEvidenceProvider
from soc_automation.service import ingest, investigate
from soc_automation.state import StateError, Store
from soc_automation.triage import Policy

FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.fixture
def queue(tmp_path):
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    ingest(store, (FIXTURES / "stages.json").read_bytes(), policy=Policy(default_priority="P2"))
    now = [1000.0]
    return InvestigationQueue(store, clock=lambda: now[0]), now


def test_order_duplicates_and_readonly(queue):
    q, _ = queue
    preview = q.preview()
    assert preview == sorted(
        preview, key=lambda r: (r["priority"], r["ingested_at"], r["alert_id"])
    )
    # A reserved writer does not block preview (which must not reserve a write).
    with q.store._connection():
        assert q.preview() == preview
    jobs = q.enqueue()
    assert len(jobs) == len(preview) > 0
    assert q.enqueue() == []
    assert q.preview() == []
    assert all(len(q.inspect(j["id"])["selection"]) == 1 for j in jobs)


def test_concurrent_enqueue_claim(queue):
    q, _ = queue
    expected = len(q.preview())
    with ThreadPoolExecutor(4) as pool:
        batches = list(pool.map(lambda _: q.enqueue(), range(4)))
    assert sum(map(len, batches)) == expected
    with ThreadPoolExecutor(4) as pool:
        claimed = list(pool.map(lambda n: q.claim(str(n)), range(4)))
    ids = [j["id"] for j in claimed if j]
    assert len(ids) == len(set(ids)) == min(4, expected)


def test_lease_retry_restart_and_fencing(queue):
    q, now = queue
    job = q.enqueue(1, max_attempts=2)[0]
    first = q.claim("one", lease_seconds=10)
    now[0] += 5
    assert q.renew(job["id"], "one", 1, lease_seconds=10) == 1015
    with pytest.raises(StateError):
        q.finish(job["id"], "other", 1)
    now[0] = 1015
    with pytest.raises(StateError):
        q.renew(job["id"], "one", 1)
    restarted = InvestigationQueue(Store(q.store.path), clock=lambda: now[0])
    assert restarted.recover(retry_seconds=1) == 1
    assert restarted.recover() == 0
    assert restarted.claim("two") is None
    now[0] += 1
    second = restarted.claim("two")
    assert second["lease_generation"] == first["lease_generation"] + 1
    restarted.renew(job["id"], "two", 2)
    with pytest.raises(StateError):
        q.finish(job["id"], "one", 1)
    restarted.finish(job["id"], "two", 2, failure=FailureCode.TRANSIENT)
    result = q.inspect(job["id"])
    assert result["state"] == "failed"
    assert len(result["attempts"]) == 2
    assert q.claim("three") is None


def test_success_permanent_typed_and_versions(queue, monkeypatch):
    q, _ = queue
    q.enqueue()
    monkeypatch.setattr(investigation, "ENGINE_VERSION", "future")
    with pytest.raises(StateError):
        q.claim("owner")
    monkeypatch.setattr(investigation, "ENGINE_VERSION", "3.0")
    job = q.claim("owner")
    with pytest.raises(ValueError):
        q.finish(job["id"], "owner", 1, failure="timeout text")
    q.finish(job["id"], "owner", 1, failure=FailureCode.PERMANENT)
    assert q.inspect(job["id"])["state"] == "failed"
    job = q.claim("owner")
    with pytest.raises(StateError, match="report persistence"):
        q.finish(job["id"], "owner", 1)
    assert q.inspect(job["id"])["state"] == "leased"


def test_immutable_identity_audit_and_rollback(queue):
    q, _ = queue
    job = q.enqueue(1)[0]
    for sql in (
        "UPDATE investigation_jobs SET selection_json='[\"other\"]'",
        "DELETE FROM investigation_jobs",
        "UPDATE investigation_coordination_audit SET event='changed'",
        "DELETE FROM investigation_coordination_audit",
        "DELETE FROM investigation_job_alerts",
        "UPDATE investigation_jobs SET state='completed'",
    ):
        with pytest.raises(sqlite3.IntegrityError), q.store._connection() as conn:
            conn.execute(sql)
    with q.store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER reject_audit BEFORE INSERT ON investigation_coordination_audit "
            "BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        q.claim("owner")
    assert q.inspect(job["id"])["attempt_count"] == 0


def test_manual_membership_and_ineligible_inputs(queue):
    q, _ = queue
    ids = [r["alert_id"] for r in q.preview()]
    investigate(q.store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
    assert q.preview() == []
    assert q.enqueue() == []


def test_v5_upgrade_preserves_publication(tmp_path, monkeypatch):
    store = Store(tmp_path / "v5.db")
    with monkeypatch.context() as m:
        m.setattr(state, "SCHEMA_VERSION", 5)
        with patch.object(Store, "_validate"):
            store.initialize()
        m.setattr(Store, "_validate", staticmethod(lambda c: None))
        ids = [r["alert_id"] for r in ingest(store, (FIXTURES / "stages.json").read_bytes())]
        report = investigate(store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
        publication = store.prepare_publication(
            report["investigation_id"], "offline", {"tags": ["migration-test"]}
        )
        before = store.show_case_publication(publication["id"])
    store.initialize()
    assert store.show_case_publication(publication["id"]) == before
    store.healthcheck()
    with store._connection(readonly=True) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == state.SCHEMA_VERSION


def test_v6_migration_rollback(tmp_path, monkeypatch):
    store = Store(tmp_path / "v5.db")
    with monkeypatch.context() as m:
        m.setattr(state, "SCHEMA_VERSION", 5)
        with patch.object(Store, "_validate"):
            store.initialize()
    original = files("soc_automation").joinpath("migrations/006_initial.sql").read_text()

    class Broken:
        def joinpath(self, path):
            return self

        def read_text(self, **kwargs):
            return original + "\nINVALID SQL;\n"

    monkeypatch.setattr(state, "files", lambda _: Broken())
    with pytest.raises(sqlite3.Error):
        store.initialize()
    with sqlite3.connect(store.path) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == 5
        assert not c.execute(
            "SELECT name FROM sqlite_master WHERE name='investigation_jobs'"
        ).fetchall()


@pytest.mark.parametrize(
    "disposition,validity,eligible",
    [
        ("INVESTIGATE", "VALID", True),
        ("URGENT_INVESTIGATION", "VALID", True),
        ("TEST_ONLY", "VALID", False),
        ("MANUAL_REVIEW", "VALID", False),
        ("INVESTIGATE", "INVALID", False),
    ],
)
def test_exact_eligibility(tmp_path, disposition, validity, eligible):
    # Build retained ingestion decisions through the existing ingestion persistence seam.
    from soc_automation.ingestion import normalize
    from soc_automation.triage import decide

    store = Store(tmp_path / "eligibility.db")
    store.initialize()
    item = json.loads((FIXTURES.parent / "standard.json").read_text())
    alert, original = normalize(item)
    decision = decide(alert)
    decision.update(disposition=disposition, validity=validity)
    identifier = store.ingest_batch([(alert, original, decision)])[0]["alert_id"]
    store.register_alert("manual", "un-ingested")
    q = InvestigationQueue(store)
    assert [r["alert_id"] for r in q.preview()] == ([identifier] if eligible else [])
    if eligible:
        store.transition(identifier, "investigating")
        assert q.preview() == []


def test_cli(queue, monkeypatch, capsys):
    from soc_automation.cli import main

    q, _ = queue
    monkeypatch.setenv("SOC_DATABASE_PATH", str(q.store.path))
    assert main(["plan-investigations", "--limit", "1"]) == 0
    assert main(["enqueue-investigations", "--limit", "1"]) == 0
    job = q.list_jobs()[0]
    assert main(["show-investigation-job", "--job-id", job["id"]]) == 0
    assert main(["list-investigation-jobs"]) == 0
    assert main(["recover-investigation-jobs"]) == 0
    assert main(["enqueue-investigations", "--limit", "0"]) == 1
    assert capsys.readouterr().out


def test_expired_completion_attempt_immutability(queue):
    q, now = queue
    q.enqueue(1, max_attempts=1)
    job = q.claim("owner", lease_seconds=1)
    now[0] += 1
    with pytest.raises(StateError):
        q.finish(job["id"], "owner", 1)
    assert q.recover() == 1
    assert q.inspect(job["id"])["state"] == "failed"
    with pytest.raises(sqlite3.IntegrityError), q.store._connection() as conn:
        conn.execute("UPDATE investigation_job_attempts SET outcome='completed'")


def test_priority_and_tie_order(tmp_path, monkeypatch):
    from soc_automation.ingestion import normalize
    from soc_automation.triage import decide

    store = Store(tmp_path / "ordered.db")
    store.initialize()
    monkeypatch.setattr(state, "_timestamp", lambda: "2026-01-01T00:00:00+00:00")
    prepared = []
    for number, priority in enumerate(("P4", "P2", "P1", "P2", "P3")):
        item = json.loads((FIXTURES.parent / "standard.json").read_text())
        item["_id"] = str(number)
        alert, original = normalize(item)
        decision = decide(alert)
        decision["priority"] = priority
        prepared.append((alert, original, decision))
    store.ingest_batch(prepared)
    q = InvestigationQueue(store)
    preview = q.preview()
    assert [r["priority"] for r in preview] == ["P1", "P2", "P2", "P3", "P4"]
    assert preview[1]["alert_id"] < preview[2]["alert_id"]
    selected = q.enqueue(2)
    assert [json.loads(j["selection_json"])[0] for j in selected] == [
        r["alert_id"] for r in preview[:2]
    ]
    assert q.preview() == preview[2:]


def test_transient_retry_delay(queue):
    q, now = queue
    job = q.enqueue(1)[0]
    q.claim("owner")
    q.finish(job["id"], "owner", 1, failure=FailureCode.TRANSIENT, retry_seconds=7)
    assert q.inspect(job["id"])["state"] == "retry_wait"
    assert q.claim("owner") is None
    now[0] += 7
    assert q.claim("owner")["lease_generation"] == 2
    q.renew(job["id"], "owner", 2)
    q.finish(job["id"], "owner", 2, failure=FailureCode.PERMANENT)
    assert q.inspect(job["id"])["state"] == "failed"


@pytest.mark.parametrize("expired", [False, True])
def test_attempt_outcome_requires_current_lease(queue, expired):
    q, now = queue
    q.enqueue(1)
    job = q.claim("owner", lease_seconds=10)
    if expired:
        now[0] += 10
    with pytest.raises(sqlite3.IntegrityError), q.store._connection() as conn:
        conn.create_function("coordination_now", 0, q.clock)
        conn.execute(
            "UPDATE investigation_job_attempts SET finished_at=?,outcome=?",
            (now[0], "permanent" if expired else "lease_expired"),
        )
    assert q.inspect(job["id"])["attempts"][0]["outcome"] is None


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE investigation_jobs SET state='completed',lease_owner=NULL,lease_until=NULL",
        "UPDATE investigation_jobs SET state='failed',failure_code='permanent',"
        "lease_owner=NULL,lease_until=NULL",
        "UPDATE investigation_job_attempts SET finished_at=999,outcome='permanent'",
        "UPDATE investigation_jobs SET failure_code='permanent',lease_until=1061",
    ],
)
def test_inconsistent_terminal_and_attempt_records_rejected(queue, sql):
    q, _ = queue
    q.enqueue(1)
    q.claim("owner")
    with pytest.raises(sqlite3.IntegrityError), q.store._connection() as conn:
        conn.create_function("coordination_now", 0, q.clock)
        conn.execute(sql)


def test_reopened_store_registers_trigger_clock(queue, monkeypatch):
    q, now = queue
    q.enqueue(1)
    q.claim("owner", lease_seconds=1)
    now[0] += 1
    monkeypatch.setattr(state.time, "time", lambda: now[0])
    reopened = Store(q.store.path)
    reopened.initialize()
    with pytest.raises(sqlite3.IntegrityError, match="expired"), reopened._connection() as conn:
        assert conn.execute("SELECT coordination_now()").fetchone()[0] == now[0]
        conn.execute("UPDATE investigation_jobs SET lease_until=2000")
    restarted = InvestigationQueue(reopened, clock=lambda: now[0])
    assert restarted.recover() == 1
    assert restarted.inspect(q.list_jobs()[0]["id"])["attempts"][0]["outcome"] == "lease_expired"
