"""Execution contracts: synthetic providers, isolated SQLite, no remote services."""

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import pytest

from soc_automation import investigation, state
from soc_automation.cli import main
from soc_automation.coordination import InvestigationQueue
from soc_automation.evidence import FixtureEvidenceProvider, Retrieval, RetrievalCode
from soc_automation.service import construct_investigation, ingest, investigate
from soc_automation.state import StateError, Store
from soc_automation.triage import Policy
from soc_automation.worker import InvestigationWorker

FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    ingest(store, (FIXTURES / "stages.json").read_bytes(), policy=Policy(default_priority="P2"))
    now = [1000.0]
    q = InvestigationQueue(store, clock=lambda: now[0])
    provider = FixtureEvidenceProvider(FIXTURES / "evidence")
    return q, now, provider


def worker(q, provider, **kwargs):
    return InvestigationWorker(q.store, provider, clock=q.clock, **kwargs)


def count(q, table="investigations"):
    with q.store._connection(readonly=True) as c:
        # Table names are test constants, never user input.
        return c.execute("SELECT count(*) FROM " + table).fetchone()[0]  # noqa: S608


class FailureProvider:
    def __init__(self, reason, status="failed"):
        self.reason, self.status = reason, status

    def retrieve_many(self, refs):
        return [Retrieval(r, self.status, reason=self.reason) for r in refs]


def test_success_and_publication_boundary(setup, monkeypatch):
    q, _, provider = setup
    q.enqueue(1)

    def forbidden(*a, **kw):
        raise AssertionError("Publication is forbidden")

    monkeypatch.setattr("soc_automation.service.publish_case", forbidden)
    monkeypatch.setattr("soc_automation.kibana.KibanaClient.create", forbidden)
    row = worker(q, provider).run()[0]
    assert row["state"] == "completed"
    assert row["investigation_id"]
    assert row["attempts"][0]["outcome"] == "completed"
    assert count(q) == 1
    assert count(q, "case_publications") == 0


def test_partial(setup):
    q, _, _ = setup
    q.enqueue(1)
    row = worker(q, FailureProvider("document_missing", "missing")).run()[0]
    report = q.store.show_investigation(row["investigation_id"])
    assert row["state"] == "failed"
    assert report["status"] == "partial"
    assert report["evidence_gaps"]


@pytest.mark.parametrize("reason", ["transport_failure", "rate_limited", "server_error"])
def test_retry_then_exhaustion(setup, reason):
    q, now, _ = setup
    q.enqueue(1, max_attempts=2)
    w = worker(q, FailureProvider(reason), retry_seconds=1)
    row = w.run()[0]
    assert row["state"] == "retry_wait"
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0
    now[0] += 1
    row = w.run()[0]
    assert row["state"] == "failed"
    report = q.store.show_investigation(row["investigation_id"])
    assert report["status"] == "partial"
    assert report["evidence_gaps"][0]["reason"] == reason


@pytest.mark.parametrize(
    "reason,code",
    [
        ("authentication_failed", RetrievalCode.AUTH),
        ("authorization_failed", RetrievalCode.AUTH),
        ("tls_verification_failed", RetrievalCode.CONFIGURATION),
        ("index_not_permitted", RetrievalCode.INVALID_REFERENCE),
        ("identity_or_document_invalid", RetrievalCode.CONFLICT),
    ],
)
def test_permanent(setup, reason, code):
    q, _, _ = setup
    q.enqueue(1)
    row = worker(q, FailureProvider(reason)).run()[0]
    assert row["state"] == "failed"
    assert row["failure_code"] == "permanent"
    assert row["investigation_id"] is None
    assert count(q) == 0
    assert FailureProvider(reason).retrieve_many([None])[0].code == code


def test_existing_adoption(setup):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    report = investigate(q.store, json.loads(job["selection_json"]), provider)

    class NoRetrieval:
        def retrieve_many(self, refs):
            raise AssertionError("Existing reports require no retrieval")

    row = worker(q, NoRetrieval()).run()[0]
    assert q.store.show_investigation(row["investigation_id"]) == report
    assert count(q) == 1


def test_manual_wins_race(setup):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    winner = []

    class ConcurrentManual:
        def retrieve_many(self, refs):
            winner.append(investigate(q.store, json.loads(job["selection_json"]), provider))
            return provider.retrieve_many(refs)

    row = worker(q, ConcurrentManual()).run()[0]
    assert row["state"] == "completed"
    assert q.store.show_investigation(row["investigation_id"]) == winner[0]
    assert count(q) == 1


def test_conflicting_ledger(setup):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    original = provider.retrieve_many

    class Conflict:
        def retrieve_many(self, refs):
            # A different request has already retained this source identity.
            results = original(refs)
            with q.store._connection() as c:
                for r in results:
                    c.execute(
                        "INSERT INTO investigation_evidence VALUES(?,?,?,?)",
                        (r.reference.index, r.reference.id, "different", "{}"),
                    )
            return results

    row = worker(q, Conflict()).run()[0]
    assert row["id"] == job["id"]
    assert row["state"] == "failed"
    assert count(q) == 0


def test_concurrent_workers(setup):
    q, _, provider = setup
    jobs = q.enqueue()
    with ThreadPoolExecutor(4) as pool:
        outcomes = list(pool.map(lambda _: worker(q, provider).run(max_jobs=10), range(4)))
    rows = [r for batch in outcomes for r in batch]
    assert len(rows) == len(jobs)
    assert len({r["id"] for r in rows}) == len(jobs)
    assert all(r["state"] == "completed" for r in rows)


def test_expiry_during_retrieval(setup):
    q, now, provider = setup
    q.enqueue(1)

    class Expiring:
        def retrieve_many(self, refs):
            now[0] += 61
            return provider.retrieve_many(refs)

    with pytest.raises(StateError):
        worker(q, Expiring()).run()
    assert count(q) == 0
    assert q.recover() == 1


def test_stale_generation(setup):
    q, now, provider = setup
    job = q.enqueue(1)[0]
    q.claim("old", lease_seconds=1)
    report = construct_investigation(q.store, json.loads(job["selection_json"]), provider)
    now[0] += 1
    q.recover(retry_seconds=1)
    now[0] += 1
    q.claim("new")
    with pytest.raises(StateError):
        q.complete(job["id"], "old", 1, report)
    assert count(q) == 0


def test_heartbeat_during_blocking_retrieval(setup, monkeypatch):
    q, now, provider = setup
    q.enqueue(1)
    renewed = threading.Event()
    original = InvestigationQueue.renew

    def renew(self, *args, **kwargs):
        now[0] += 0.1
        result = original(self, *args, **kwargs)
        renewed.set()
        return result

    monkeypatch.setattr(InvestigationQueue, "renew", renew)

    class Blocking:
        def retrieve_many(self, refs):
            assert renewed.wait(2)
            return provider.retrieve_many(refs)

    row = worker(q, Blocking(), heartbeat_seconds=0.01).run()[0]
    assert row["state"] == "completed"
    assert "renewed" in [r["event"] for r in row["audit"]]


@pytest.mark.parametrize("crash_at", ["before", "during", "audit"])
def test_crash_and_atomic_rollback(setup, monkeypatch, crash_at):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    q.claim("owner")
    report = construct_investigation(q.store, json.loads(job["selection_json"]), provider)
    original = Store._save_investigation

    def crash(self, conn, *args):
        if crash_at == "during":
            original(self, conn, *args)
        raise KeyboardInterrupt

    if crash_at == "audit":
        with q.store._connection() as c:
            c.execute(
                "CREATE TRIGGER reject_worker_audit BEFORE INSERT ON "
                "investigation_coordination_audit BEGIN SELECT RAISE(ABORT,'test'); END"
            )
        error = sqlite3.IntegrityError
    else:
        monkeypatch.setattr(Store, "_save_investigation", crash)
        error = KeyboardInterrupt
    with pytest.raises(error):
        q.complete(job["id"], "owner", 1, report)
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0
    row = q.inspect(job["id"])
    assert row["state"] == "leased"
    assert row["investigation_id"] is None
    assert row["attempts"][0]["outcome"] is None


def test_engine_mismatch(setup, monkeypatch):
    q, _, provider = setup
    q.enqueue(1)
    monkeypatch.setattr(investigation, "ENGINE_VERSION", "future")
    row = worker(q, provider).run()[0]
    assert row["state"] == "failed"
    assert row["failure_code"] == "engine_mismatch"
    assert count(q) == 0


def test_retrieval_without_transaction(setup):
    q, _, provider = setup
    q.enqueue(1)

    class AssertUnlocked:
        def retrieve_many(self, refs):
            # A second writer could not begin if the worker held a write transaction.
            with Store(q.store.path, timeout=0)._connection() as c:
                assert c.in_transaction
            return provider.retrieve_many(refs)

    assert worker(q, AssertUnlocked()).run()[0]["state"] == "completed"


def test_age_limit(setup):
    q, now, provider = setup
    q.enqueue(1)
    now[0] += 10
    row = worker(q, provider, max_job_age=5).run()[0]
    assert row["state"] == "failed"
    assert count(q) == 0


def test_age_exhaustion_partial(setup):
    q, _, _ = setup
    q.enqueue(1)
    row = worker(q, FailureProvider("transport_failure"), max_job_age=5).run()[0]
    assert row["state"] == "failed"
    assert q.store.show_investigation(row["investigation_id"])["status"] == "partial"


def test_cli_bounded(setup, monkeypatch):
    q, _, _ = setup
    # CLI uses real UTC; enqueue with that same clock for this test.
    real_q = InvestigationQueue(q.store)
    real_q.enqueue()
    monkeypatch.setenv("SOC_DATABASE_PATH", str(q.store.path))
    assert (
        main(
            [
                "run-investigation-worker",
                "--once",
                "--provider",
                "fixture",
                "--evidence-dir",
                str(FIXTURES / "evidence"),
            ]
        )
        == 0
    )
    assert count(q) == 1


def test_v7_migration_rollback_and_upgrade(tmp_path, monkeypatch):
    store = Store(tmp_path / "migration.db")
    with monkeypatch.context() as m:
        m.setattr(state, "SCHEMA_VERSION", 6)
        with patch.object(Store, "_validate"):
            store.initialize()
    original = files("soc_automation").joinpath("migrations/007_initial.sql").read_text()

    class Broken:
        def joinpath(self, path):
            return self

        def read_text(self, **kwargs):
            return original + "\nINVALID SQL;\n"

    with monkeypatch.context() as m:
        m.setattr(state, "files", lambda _: Broken())
        with pytest.raises(sqlite3.Error):
            store.initialize()
    with sqlite3.connect(store.path) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == 6
        assert "investigation_id" not in [
            r[1] for r in c.execute("PRAGMA table_info(investigation_jobs)")
        ]
    store.initialize()
    store.healthcheck()


def test_retry_eventually_successful(setup):
    q, now, provider = setup
    q.enqueue(1)
    assert worker(q, FailureProvider("read_timeout")).run()[0]["state"] == "retry_wait"
    assert count(q) == 0
    now[0] += 60
    row = worker(q, provider).run()[0]
    assert row["state"] == "completed"
    assert len(row["attempts"]) == 2


def test_partial_adoption(setup):
    q, _, _ = setup
    job = q.enqueue(1)[0]
    partial = investigate(
        q.store, json.loads(job["selection_json"]), FailureProvider("document_missing", "missing")
    )
    row = worker(q, object()).run()[0]
    assert row["state"] == "failed"
    assert row["investigation_id"] == partial["investigation_id"]


def test_bounded_wait_discards_late_result(setup):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    released = threading.Event()
    finished = threading.Event()
    ticks = iter([0, 0, 2])

    class Blocking:
        def retrieve_many(self, refs):
            assert released.wait(2)
            results = provider.retrieve_many(refs)
            finished.set()
            return results

    w = worker(
        q, Blocking(), execution_seconds=1, heartbeat_seconds=0.01, monotonic=lambda: next(ticks)
    )
    try:
        with pytest.raises(StateError, match="deadline"):
            w.run()
    finally:
        released.set()
        assert finished.wait(2)
    assert count(q) == 0
    assert q.inspect(job["id"])["state"] == "leased"


def test_lease_loss_during_heartbeat(setup, monkeypatch):
    q, _, provider = setup
    q.enqueue(1)
    released = threading.Event()
    finished = threading.Event()

    class Blocking:
        def retrieve_many(self, refs):
            assert released.wait(2)
            result = provider.retrieve_many(refs)
            finished.set()
            return result

    def lost(*args, **kwargs):
        raise StateError("Lease ownership lost")

    monkeypatch.setattr(InvestigationQueue, "renew", lost)
    try:
        with pytest.raises(StateError):
            worker(q, Blocking(), heartbeat_seconds=0.01).run()
    finally:
        released.set()
        assert finished.wait(2)
    assert count(q) == 0


def test_interruption_cannot_complete(setup):
    q, _, _ = setup
    q.enqueue(1)

    class Interrupted:
        def retrieve_many(self, refs):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        worker(q, Interrupted()).run()
    assert count(q) == 0


def test_expiry_inside_commit_rolls_back(setup, monkeypatch):
    q, now, provider = setup
    job = q.enqueue(1)[0]
    q.claim("owner", lease_seconds=1)
    report = construct_investigation(q.store, json.loads(job["selection_json"]), provider)
    original = Store._save_investigation

    def slow(self, *args):
        result = original(self, *args)
        now[0] += 1
        return result

    monkeypatch.setattr(Store, "_save_investigation", slow)
    with pytest.raises(StateError):
        q.complete(job["id"], "owner", 1, report)
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0


@pytest.mark.parametrize("phase", ["before", "during", "after_audit"])
def test_process_crash_durability(setup, phase):
    import subprocess
    import sys

    q, now, provider = setup
    job = q.enqueue(1)[0]
    q.claim("crashing")
    report = construct_investigation(q.store, json.loads(job["selection_json"]), provider)
    script = """
import json
import os
import sys
from pathlib import Path
from soc_automation.state import Store
from soc_automation.coordination import InvestigationQueue
store = Store(Path(sys.argv[1]))
original = Store._save_investigation
def crash(self, conn, *args):
    if sys.argv[3] == 'after_audit':
        return original(self, conn, *args)
    if sys.argv[3] == 'during':
        original(self, conn, *args)
    os._exit(73)
Store._save_investigation = crash
original_audit = InvestigationQueue._audit
def crash_audit(self, *args):
    original_audit(self, *args)
    os._exit(73)
if sys.argv[3] == 'after_audit':
    InvestigationQueue._audit = crash_audit
InvestigationQueue(store, clock=lambda: 1000.0).complete(
    sys.argv[2], 'crashing', 1, json.load(sys.stdin))
"""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script, str(q.store.path), job["id"], phase],
        input=json.dumps(report),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 73, result.stderr
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0
    row = q.inspect(job["id"])
    assert row["state"] == "leased"
    assert row["attempts"][0]["outcome"] is None
    assert count(q, "investigation_alerts") == 0
    assert count(q, "investigation_references") == 0
    assert count(q, "investigation_audit") == 0
    assert [a["event"] for a in row["audit"]] == ["enqueued", "claimed"]
    now[0] += 61
    assert q.recover(retry_seconds=1) == 1
    now[0] += 1
    recovered = worker(q, provider).run()[0]
    assert recovered["state"] == "completed"
    assert [a["outcome"] for a in recovered["attempts"]] == ["lease_expired", "completed"]
    assert count(q) == 1
    assert count(q, "investigation_audit") == 1


def test_incompatible_schema_rejected(setup):
    q, _, provider = setup
    with q.store._connection() as c:
        c.execute("DROP TRIGGER investigation_job_report_guard")
    with pytest.raises(StateError):
        worker(q, provider).run()


def test_provider_has_no_open_worker_transaction(setup, monkeypatch):
    from contextlib import contextmanager

    q, _, provider = setup
    q.enqueue(1)
    active = []
    original = Store._connection

    @contextmanager
    def tracked(self, **kwargs):
        with original(self, **kwargs) as connection:
            active.append(connection)
            try:
                yield connection
            finally:
                active.remove(connection)

    monkeypatch.setattr(Store, "_connection", tracked)

    class Checking:
        def retrieve_many(self, refs):
            assert not active
            return provider.retrieve_many(refs)

    assert worker(q, Checking()).run()[0]["state"] == "completed"


@pytest.mark.parametrize("permanent", [False, True])
def test_mixed_batch_never_persists_early(setup, permanent):
    q, _, provider = setup
    item = json.loads((FIXTURES / "stages.json").read_text())[0]
    item["_id"] = "mixed"
    item["_source"]["kibana.alert.ancestors"].append(
        {"index": "synthetic-events", "id": "1", "type": "event", "depth": 0}
    )
    identifier = ingest(q.store, json.dumps(item).encode(), policy=Policy(default_priority="P1"))[
        0
    ]["alert_id"]
    job = q.enqueue(1)[0]
    assert json.loads(job["selection_json"]) == [identifier]

    class Mixed:
        def retrieve_many(self, refs):
            return [
                provider.retrieve(refs[0]),
                Retrieval(
                    refs[1],
                    "failed",
                    reason="authentication_failed" if permanent else "server_error",
                ),
            ]

    row = worker(q, Mixed()).run()[0]
    assert row["state"] == ("failed" if permanent else "retry_wait")
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0


def test_investigation_audit_failure_rolls_back(setup):
    q, _, provider = setup
    q.enqueue(1)
    with q.store._connection() as c:
        c.execute(
            "CREATE TRIGGER reject_report_audit BEFORE INSERT ON investigation_audit "
            "BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        worker(q, provider).run()
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0
    assert q.list_jobs()[0]["state"] == "leased"


def test_ready_result_after_deadline_cannot_persist(setup, monkeypatch):
    import queue

    q, _, provider = setup
    job = q.enqueue(1)[0]
    ticks = [0.0]
    original = queue.Queue.get

    def delayed_return(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        ticks[0] = 2.0
        return result

    monkeypatch.setattr(queue.Queue, "get", delayed_return)
    with pytest.raises(StateError, match="deadline"):
        worker(q, provider, execution_seconds=1, monotonic=lambda: ticks[0]).run()
    assert count(q) == 0
    assert count(q, "investigation_evidence") == 0
    assert q.inspect(job["id"])["state"] == "leased"


def test_initial_job_cannot_link_report(setup):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    report = investigate(q.store, json.loads(job["selection_json"]), provider)
    # Use a separate job identity so uniqueness cannot mask the missing insert guard.
    with pytest.raises(sqlite3.IntegrityError, match="invalid initial job report"):
        with q.store._connection() as c:
            c.execute(
                "INSERT INTO investigation_jobs(id,request_fingerprint,engine_version,"
                "selection_json,priority,created_at,available_at,max_attempts,investigation_id) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    "invalid-link",
                    "different",
                    job["engine_version"],
                    job["selection_json"],
                    "P2",
                    1000,
                    1000,
                    3,
                    report["investigation_id"],
                ),
            )


def test_partial_cli_link_and_publication_rejection(setup, monkeypatch, capsys):
    from soc_automation.service import prepare_case

    q, _, _ = setup
    job = q.enqueue(1)[0]
    partial = worker(q, FailureProvider("document_missing", "missing")).run()[0]
    monkeypatch.setenv("SOC_DATABASE_PATH", str(q.store.path))
    assert main(["show-investigation-job", "--job-id", job["id"]]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["state"] == "failed"
    assert shown["investigation_id"] == partial["investigation_id"]
    with pytest.raises(ValueError, match="not eligible"):
        prepare_case(q.store, shown["investigation_id"], object())
    assert count(q, "case_publications") == 0
    # A permanent retrieval failure has the same terminal state but no report link.
    q.enqueue(1)
    failed = worker(q, FailureProvider("authentication_failed")).run()[0]
    assert main(["show-investigation-job", "--job-id", failed["id"]]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["state"] == "failed"
    assert shown["investigation_id"] is None


@pytest.mark.parametrize("rollback_first", [False, True])
def test_v7_preserves_populated_v6_tables(tmp_path, monkeypatch, rollback_first):
    store = Store(tmp_path / "populated-v6.db")
    with monkeypatch.context() as m:
        m.setattr(state, "SCHEMA_VERSION", 6)
        m.setattr(Store, "_validate", staticmethod(lambda c: None))
        store.initialize()
        ids = [r["alert_id"] for r in ingest(store, (FIXTURES / "stages.json").read_bytes())]
        investigate(store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
        # Multiple revisions and their audit must survive byte-for-byte.
        report = investigate(store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
        store.prepare_publication(report["investigation_id"], "offline", {"tags": ["first"]})
        store.prepare_publication(
            report["investigation_id"], "offline", {"tags": ["second"]}, revise=True
        )
    with store._connection(readonly=True) as c:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        before = {
            name: c.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall()  # noqa: S608
            for name in tables
        }
    if rollback_first:
        migration = files("soc_automation").joinpath("migrations/007_initial.sql").read_text()

        class Broken:
            def joinpath(self, path):
                return self

            def read_text(self, **kwargs):
                return migration + "\nINVALID SQL;\n"

        with monkeypatch.context() as m:
            m.setattr(state, "files", lambda _: Broken())
            with pytest.raises(sqlite3.Error):
                store.initialize()
        with store._connection(readonly=True) as c:
            assert c.execute("PRAGMA user_version").fetchone()[0] == 6
            for name, rows in before.items():
                assert c.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall() == rows  # noqa: S608
    store.initialize()
    with store._connection(readonly=True) as c:
        for name, rows in before.items():
            assert c.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall() == rows  # noqa: S608
        assert c.execute("PRAGMA foreign_key_check").fetchall() == []
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


@pytest.mark.parametrize(
    "field,value", [("engine_version", "incompatible"), ("source_alert_ids", [])]
)
def test_existing_incompatible_report_is_never_adopted(setup, field, value):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    report = construct_investigation(q.store, json.loads(job["selection_json"]), provider)
    report[field] = value
    q.store.save_investigation(report, job["request_fingerprint"])
    before = q.store.show_investigation(report["investigation_id"])
    with pytest.raises(StateError, match="Incompatible"):
        worker(q, object()).run()
    row = q.inspect(job["id"])
    assert row["state"] == "leased"
    assert row["investigation_id"] is None
    assert q.store.show_investigation(report["investigation_id"]) == before


def test_manual_partial_wins_conflicting_worker_race(setup):
    q, _, provider = setup
    job = q.enqueue(1)[0]
    winner = []

    class ManualPartial:
        def retrieve_many(self, refs):
            winner.append(
                investigate(
                    q.store,
                    json.loads(job["selection_json"]),
                    FailureProvider("document_missing", "missing"),
                )
            )
            return provider.retrieve_many(refs)

    row = worker(q, ManualPartial()).run()[0]
    assert row["state"] == "failed"
    assert row["investigation_id"] is None
    assert q.store.show_investigation(winner[0]["investigation_id"]) == winner[0]
    assert count(q) == 1
    assert count(q, "investigation_evidence") == 0
    assert count(q, "investigation_audit") == 1


@pytest.mark.parametrize("execution", ["manual", "worker", "legacy_job"])
def test_numeric_user_engine_upgrade_preserves_history(setup, monkeypatch, execution):
    q, _, provider = setup
    current_version = investigation.ENGINE_VERSION
    assert current_version == "3.1"
    identifier = q.preview(1)[0]["alert_id"]

    class NumericProvider:
        calls = 0

        def retrieve_many(self, refs):
            self.calls += 1
            results = provider.retrieve_many(refs)
            for result in results:
                if result.status == "found":
                    result.document["_source"]["user.id"] = 0
            return results

    numeric = NumericProvider()
    if execution == "worker":
        job = q.enqueue(1)[0]
        assert job["engine_version"] == current_version
    with monkeypatch.context() as legacy:
        legacy.setattr(investigation, "ENGINE_VERSION", "3.0")
        if execution == "legacy_job":
            job = q.enqueue(1)[0]
        historical = construct_investigation(q.store, [identifier], numeric)
        # Reproduce the old engine's rejection of integer context, retaining the
        # identical evidence bytes so snapshot conflict checks cannot mask reuse.
        historical.update(
            status="partial",
            timeline=[],
            observed_facts=[],
            supported_inferences=[],
            evidence_gaps=[{"reason": "invalid_context_or_timestamp"}],
        )
        q.store.save_investigation(historical, historical["request_fingerprint"])
    with q.store._connection(readonly=True) as conn:
        audit = list(conn.execute("SELECT * FROM investigation_audit"))
    calls = numeric.calls
    if execution == "legacy_job":
        outcome = worker(q, numeric).run()[0]
        assert outcome["failure_code"] == "engine_mismatch"
        assert outcome["investigation_id"] is None
        assert numeric.calls == calls
        assert count(q) == 1
    else:
        if execution == "worker":
            assert q.existing_report(job) is None
            outcome = worker(q, numeric).run()[0]
            assert outcome["state"] == "completed"
            corrected = q.store.show_investigation(outcome["investigation_id"])
        else:
            corrected = investigate(q.store, [identifier], numeric)
        assert numeric.calls > calls
        assert corrected["status"] == "completed"
        assert corrected["engine_version"] == current_version
        assert corrected["request_fingerprint"] != historical["request_fingerprint"]
        assert corrected["investigation_id"] != historical["investigation_id"]
        assert count(q) == 2
        assert investigate(q.store, [identifier], numeric) == corrected
    assert q.store.show_investigation(historical["investigation_id"]) == historical
    with q.store._connection(readonly=True) as conn:
        assert list(conn.execute("SELECT * FROM investigation_audit"))[: len(audit)] == audit
