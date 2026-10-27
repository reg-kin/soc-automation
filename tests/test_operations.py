"""Operational snapshots and safe, post-commit observations on isolated databases."""

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest
import test_worker as worker_tests
from test_worker import FailureProvider, worker

from soc_automation.cli import main
from soc_automation.coordination import FailureCode, InvestigationQueue
from soc_automation.logging import OPERATIONAL_EVENTS, JsonFormatter
from soc_automation.state import Store

setup = worker_tests.setup


@pytest.mark.parametrize("role", ["worker", "recovery"])
def test_systemd_invocations_have_explicit_runtime_bounds(role):
    from configparser import ConfigParser

    deploy = Path(__file__).resolve().parents[1] / "deploy"
    service = ConfigParser(interpolation=None)
    service.read(deploy / f"soc-investigation-{role}.service")
    assert service["Service"]["Type"] == "oneshot"
    # Type=oneshot otherwise defaults to an unlimited start timeout.
    assert service["Service"]["TimeoutStartSec"] == {"worker": "1h", "recovery": "2min"}[role]
    assert "Install" not in service
    timer = ConfigParser(interpolation=None)
    timer.read(deploy / f"soc-investigation-{role}.timer")
    assert timer["Timer"]["Unit"] == f"soc-investigation-{role}.service"
    assert timer["Timer"]["OnUnitInactiveSec"] == "5min"
    assert "Install" not in timer


def test_empty_health(tmp_path):
    store = Store(tmp_path / "empty.db")
    store.initialize()
    calls = []
    q = InvestigationQueue(store, clock=lambda: calls.append(1) or 1000)
    before = store.path.read_bytes()
    h = q.health(1)
    assert calls == [1]
    assert h["state_counts"] == dict.fromkeys(
        ["queued", "leased", "retry_wait", "completed", "failed"], 0
    )
    assert h["pending_total"] == 0
    assert not h["pending_truncated"]
    assert store.path.read_bytes() == before


def test_health_snapshot_and_boundaries(setup):
    q, now, provider = setup
    q.enqueue(3)
    worker(q, provider).run()
    worker(q, FailureProvider("document_missing", "missing")).run()
    worker(q, FailureProvider("authentication_failed")).run()
    h = q.health(1)
    assert h["linked_partial_reports"] == 1
    assert h["failed_without_reports"] == 1
    assert h["state_counts"]["completed"] == 1
    assert h["state_counts"]["failed"] == 2
    assert h["overdue_leases"] == 0


def test_health_lease_retry_boundaries(setup):
    q, now, _ = setup
    q.enqueue(1)
    job = q.claim("test", lease_seconds=10)
    assert q.health()["overdue_leases"] == 0
    now[0] += 10
    assert q.health()["overdue_leases"] == 1
    assert q.recover(retry_seconds=5) == 1
    assert q.health()["delayed_retries"] == 1
    assert q.health()["ready_retries"] == 0
    now[0] += 5
    assert q.health()["ready_retries"] == 1
    assert q.health()["delayed_retries"] == 0
    assert q.inspect(job["id"])["state"] == "retry_wait"


def test_large_history_and_readonly_snapshot(tmp_path, monkeypatch):
    store = Store(tmp_path / "large.db")
    store.initialize()
    q = InvestigationQueue(store, clock=lambda: 1000)
    # Seed legal initial rows, then use the real fenced transitions for history.
    with store._connection() as conn:
        conn.executemany(
            "INSERT INTO investigation_jobs(id,request_fingerprint,engine_version,selection_json,"
            "priority,created_at,available_at,max_attempts) VALUES(?,?,?,?,?,?,?,?)",
            [(str(i), str(i), "old", '["alert"]', "P2", i, 0, 1) for i in range(1005)],
        )
    for _ in range(1001):
        job = q.claim("test", reject_incompatible=True)
        assert job["state"] == "failed"
    original = store._connection
    traces = []

    @contextmanager
    def readonly(**kwargs):
        assert kwargs == {"readonly": True}
        with original(**kwargs) as conn:
            conn.set_trace_callback(traces.append)
            yield conn

    monkeypatch.setattr(store, "_connection", readonly)
    h = q.health(2)
    assert h["state_counts"]["failed"] == 1001
    assert h["failed_without_reports"] == 1001
    assert h["ready_queued"] == 4
    assert h["pending_total"] == 4
    assert h["pending_returned"] == 2
    assert h["pending_truncated"]
    assert [r["id"] for r in h["oldest_pending_jobs"]] == ["1001", "1002"]
    assert not any(s.startswith(("INSERT", "UPDATE", "DELETE")) for s in traces)


@pytest.mark.parametrize("event", sorted(OPERATIONAL_EVENTS))
def test_event_schema_and_redaction(event):
    record = logging.LogRecord("soc_automation", logging.INFO, "", 0, event, (), None)
    record.operational = {
        "job_id": "job-1",
        "worker_id": "worker-1",
        "lease_generation": 2,
        "attempt_number": 2,
        "queue_state": "failed",
        "diagnostic_code": "permanent",
        "investigation_id": "report-1",
        "duration_seconds": 1.5,
        "headers": "SECRET",
        "evidence": "SECRET",
        "configuration": "SECRET",
    }
    record.exc_info = (ValueError, ValueError("SECRET"), None)
    record.args = ("SECRET",)
    value = JsonFormatter().format(record)
    assert "SECRET" not in value
    data = json.loads(value)
    assert data["event"] == event
    assert data["attempt_number"] == 2
    assert data["duration_seconds"] == 1.5
    record.operational = {
        "job_id": "http://SECRET",
        "attempt_number": True,
        "duration_seconds": float("nan"),
        "diagnostic_code": "SECRET",
    }
    assert set(json.loads(JsonFormatter().format(record))) == {"timestamp", "level", "event"}


def test_worker_events_after_commit_and_rollback(setup, monkeypatch):
    q, _, provider = setup
    q.enqueue(2)
    observed = []

    def observe(event, job, **kwargs):
        # A separate connection can see committed terminal state/report/audit.
        current = q.inspect(job["id"])
        if event == "job_completed":
            assert current["state"] == "completed"
            assert current["investigation_id"]
            assert current["audit"][-1]["event"] == "completed"
        observed.append(event)

    monkeypatch.setattr("soc_automation.worker.operational_event", observe)
    worker(q, provider).run()
    assert observed == ["job_claim", "job_completed"]
    observed.clear()
    with q.store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER fail_completion BEFORE UPDATE ON investigation_jobs "
            "WHEN NEW.state='completed' BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        worker(q, provider).run()
    assert observed == ["job_claim"]


def test_recovery_event_after_commit(setup, monkeypatch):
    q, now, _ = setup
    q.enqueue(1)
    job = q.claim("test", lease_seconds=1)
    now[0] += 1
    observed = []

    def observe(event, recovered, **kwargs):
        assert q.inspect(job["id"])["state"] == "retry_wait"
        assert recovered["lease_owner"] == "test"
        assert kwargs["code"] == FailureCode.LEASE_EXPIRED
        observed.append(event)

    monkeypatch.setattr("soc_automation.coordination.operational_event", observe)
    assert q.recover() == 1
    assert observed == ["expired_lease_recovery"]


def test_cli_json_batch_success_contract(setup, monkeypatch, capsys):
    q, _, _ = setup
    monkeypatch.setenv("SOC_DATABASE_PATH", str(q.store.path))
    assert main(["investigation-queue-health", "--limit", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["pending_limit"] == 1
    q.enqueue(1)
    monkeypatch.setattr(
        "soc_automation.cli.FixtureEvidenceProvider",
        lambda _: FailureProvider("authentication_failed"),
    )
    assert main(["run-investigation-worker", "--once", "--evidence-dir", "/unused"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["state"] == "failed"
    assert main(["run-investigation-worker", "--once", "--evidence-dir", "/unused"]) == 0
    assert json.loads(capsys.readouterr().out) == []


@pytest.mark.parametrize(
    "args",
    [
        ["run-investigation-worker", "--once", "--max-jobs", "1"],
        ["investigate", "--once"],
        ["investigate", "--max-j=2"],
        ["healthcheck", "--limit", "5"],
        ["show-investigation-job"],
        ["list-investigation-jobs", "--max-attempts", "3"],
    ],
)
def test_cli_option_contract(args):
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2


@pytest.mark.parametrize(
    "args",
    [
        ["investigation-queue-health", "--limit", "0"],
        ["run-investigation-worker", "--max-jobs", "0", "--evidence-dir", "/unused"],
        ["run-investigation-worker", "--max-jobs", "1001", "--evidence-dir", "/unused"],
    ],
)
def test_cli_invalid_bounds(setup, monkeypatch, args):
    q, _, _ = setup
    monkeypatch.setenv("SOC_DATABASE_PATH", str(q.store.path))
    monkeypatch.setattr("soc_automation.cli.FixtureEvidenceProvider", lambda _: object())
    assert main(args) == 1


@pytest.mark.parametrize(
    "reason,status,event",
    [
        ("document_missing", "missing", "investigation_partial"),
        ("transport_failure", "failed", "retry_scheduled"),
        ("authentication_failed", "failed", "job_failed"),
    ],
)
def test_worker_outcome_events(setup, monkeypatch, reason, status, event):
    q, _, _ = setup
    q.enqueue(1)
    observed = []
    monkeypatch.setattr(
        "soc_automation.worker.operational_event",
        lambda name, job, **kw: observed.append((name, job, kw)),
    )
    worker(q, FailureProvider(reason, status)).run()
    assert [r[0] for r in observed] == ["job_claim", event]
    _, job, fields = observed[-1]
    assert job["lease_owner"]
    assert job["lease_generation"] == 1
    assert fields["duration"] >= 0
    assert q.inspect(job["id"])["state"] == job["state"]


def test_engine_mismatch_event(setup, monkeypatch):
    q, _, provider = setup
    q.enqueue(1)
    monkeypatch.setattr("soc_automation.investigation.ENGINE_VERSION", "future")
    observed = []
    monkeypatch.setattr(
        "soc_automation.worker.operational_event", lambda event, job, **kw: observed.append(event)
    )
    worker(q, provider).run()
    assert observed == ["job_claim", "engine_mismatch"]


@pytest.mark.parametrize("failure", ["deadline", "renewal"])
def test_execution_control_events(setup, monkeypatch, failure):
    import queue

    from soc_automation.state import StateError

    q, _, provider = setup
    q.enqueue(1)
    observed = []
    monkeypatch.setattr(
        "soc_automation.worker.operational_event", lambda event, job, **kw: observed.append(event)
    )
    if failure == "deadline":
        ticks = iter([0, 2])
        w = worker(q, provider, execution_seconds=1, monotonic=lambda: next(ticks))
        expected = "execution_deadline"
    else:

        def empty(*args, **kwargs):
            raise queue.Empty

        def lost(*args, **kwargs):
            raise StateError("SECRET")

        monkeypatch.setattr(queue.Queue, "get", empty)
        monkeypatch.setattr(InvestigationQueue, "renew", lost)
        w = worker(q, provider)
        expected = "lease_renewal_failed"
    with pytest.raises(StateError):
        w.run()
    assert observed == ["job_claim", expected]
    assert q.health()["state_counts"]["leased"] == 1
