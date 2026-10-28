"""Milestone 5C-2: offline journeys across ingestion, coordination and local review."""

import hashlib
import json
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from soc_automation.cases import digest
from soc_automation.cli import main
from soc_automation.coordination import InvestigationQueue
from soc_automation.evidence import FixtureEvidenceProvider, Reference, Retrieval
from soc_automation.ingestion import encode
from soc_automation.investigation import request_identity
from soc_automation.logging import JsonFormatter
from soc_automation.service import construct_investigation, ingest, investigate, prepare_case
from soc_automation.state import StateError, Store
from soc_automation.triage import Policy
from soc_automation.worker import InvestigationWorker


@pytest.fixture
def journey(tmp_path, monkeypatch):
    logger = logging.getLogger("soc_automation")
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "propagate", True)

    def forbidden(*args, **kwargs):
        pytest.fail("Publication or authorization crossed the local execution boundary")

    for target in (
        "soc_automation.kibana.KibanaClient.__init__",
        "soc_automation.kibana.KibanaClient.create",
        "soc_automation.service.publish_case",
        "soc_automation.state.Store.claim_publication",
        "soc_automation.state.Store.publication_outcome",
    ):
        monkeypatch.setattr(target, forbidden)
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    directory = tmp_path / "evidence"
    directory.mkdir()
    documents = []
    for i in range(3):
        ref = Reference("logs-endpoint.events.process-synthetic", f"event-{i}")
        evidence = {
            "_index": ref.index,
            "_id": ref.id,
            "_source": {
                "@timestamp": f"2026-10-01T12:00:0{i}Z",
                "host": {"id": "synthetic-host"},
                "user": {"id": "synthetic-user"},
                "process": {"entity_id": f"process-{i}"},
                "event": {"category": ["process"], "action": "start"},
            },
        }
        (directory / FixtureEvidenceProvider.filename(ref)).write_text(encode(evidence))
        documents.append(
            {
                "_index": ".alerts-security.alerts-synthetic",
                "_id": f"alert-{i}",
                "_source": {
                    **evidence["_source"],
                    "kibana.alert.rule.rule_id": f"synthetic-rule-{i}",
                    "kibana.alert.rule.name": "Synthetic endpoint process",
                    "kibana.alert.severity": "high",
                    "kibana.alert.risk_score": 75,
                    "kibana.alert.ancestors": [
                        {"index": ref.index, "id": ref.id, "type": "event", "depth": 0}
                    ],
                },
            }
        )
    data = encode(documents).encode()
    ids = [r["alert_id"] for r in ingest(store, data, policy=Policy())]
    now = [1000.0]
    return SimpleNamespace(
        store=store,
        path=store.path,
        data=data,
        ids=ids,
        now=now,
        provider=FixtureEvidenceProvider(directory),
        directory=directory,
    )


def queue(j):
    return InvestigationQueue(Store(j.path), clock=lambda: j.now[0])


def run(j, provider=None, **kwargs):
    # Worker execution cannot create local review artifacts; explicit preparation can.
    with pytest.MonkeyPatch.context() as patch:

        def forbidden(*args, **kwargs):
            pytest.fail("Worker attempted local case preparation")

        store = Store(j.path)
        patch.setattr(store, "prepare_publication", forbidden)
        return InvestigationWorker(
            store, provider or j.provider, clock=lambda: j.now[0], **kwargs
        ).run()


def rows(j, table):
    with Store(j.path)._connection(readonly=True) as conn:
        return [tuple(r) for r in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]  # noqa: S608


def empty_reports(j):
    for table in (
        "investigations",
        "investigation_evidence",
        "investigation_alerts",
        "investigation_references",
        "investigation_audit",
        "case_publications",
    ):
        assert rows(j, table) == []


class Failure:
    def __init__(self, reason, status="failed"):
        self.reason, self.status = reason, status

    def retrieve_many(self, refs):
        return [Retrieval(ref, self.status, reason=self.reason) for ref in refs]


def assert_completed(j, job):
    assert queue(j).inspect(job["id"]) == job
    report = Store(j.path).show_investigation(job["investigation_id"])
    assert job["state"] == report["status"] == "completed"
    assert request_identity(job["selection"])[1] == job["request_fingerprint"]
    assert report["request_fingerprint"] == job["request_fingerprint"]
    assert report["source_alert_ids"] == job["selection"]
    assert (report["investigation_id"], job["selection"][0]) in rows(j, "investigation_alerts")
    expected_references = [
        {"alert_id": identifier, **ancestor}
        for identifier in job["selection"]
        for ancestor in Store(j.path).show_alert(identifier, evidence=True)["normalized"][
            "ancestors"
        ]
    ]
    assert report["evidence_references"] == expected_references
    assert report["retrieved_evidence"]
    assert report["evidence_gaps"] == []
    assert len(report["timeline"]) == len(report["retrieved_evidence"])
    assert {encode(item["reference"]) for item in report["retrieved_evidence"]} == {
        encode({"index": ref["index"], "id": ref["id"]}) for ref in expected_references
    }
    for ref in expected_references:
        assert (report["investigation_id"], ref["alert_id"], encode(ref)) in rows(
            j, "investigation_references"
        )
    for item in report["retrieved_evidence"]:
        assert item["status"] == "found"
        expected = hashlib.sha256(encode(item["document"]).encode()).hexdigest()
        assert item["sha256"] == expected
        assert (
            item["reference"]["index"],
            item["reference"]["id"],
            expected,
            encode(item["document"]),
        ) in rows(j, "investigation_evidence")
    assert job["attempts"][-1]["outcome"] == "completed"
    assert job["audit"][-1]["event"] == "completed"
    assert any(r[1] == report["investigation_id"] for r in rows(j, "investigation_audit"))
    return report


def test_pipeline_restart_idempotency_and_frozen_local_case(journey):
    j = journey
    with j.store._connection(readonly=True) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 7
    for identifier in j.ids:
        alert = j.store.show_alert(identifier, evidence=True)
        assert alert["decision"]["priority"] == "P2"
        assert alert["decision"]["disposition"] == "URGENT_INVESTIGATION"
        assert alert["normalized"]["ancestors"]
        assert (
            alert["original_ref"] == hashlib.sha256(encode(alert["original"]).encode()).hexdigest()
        )
    before = rows(j, "ingested_alerts")
    ingest(Store(j.path), j.data, policy=Policy())
    assert rows(j, "ingested_alerts") == before
    assert len(queue(j).preview()) == 3
    jobs = queue(j).enqueue()
    assert queue(j).enqueue() == []
    # A manually completed compatible report survives restart and is adopted.
    first_job = min(jobs, key=lambda job: (job["priority"], job["created_at"], job["id"]))
    report = investigate(Store(j.path), json.loads(first_job["selection_json"]), j.provider)
    adopted = run(j, Failure("authentication_failed"))[0]
    assert adopted["investigation_id"] == report["investigation_id"]
    assert_completed(j, adopted)
    assert Store(j.path).show_investigation(report["investigation_id"]) == report
    assert rows(j, "case_publications") == []
    prepared = prepare_case(
        Store(j.path), report["investigation_id"], SimpleNamespace(target="offline")
    )
    assert prepared["state"] == "prepared"
    assert prepared["approval_sha256"] is None
    assert prepared["payload_sha256"] == digest(json.loads(prepared["payload_json"]))
    snapshot = rows(j, "case_publications")
    publication_audit = rows(j, "case_publication_audit")
    for _ in jobs[1:]:
        assert_completed(j, run(j)[0])
        assert rows(j, "case_publications") == snapshot
        assert rows(j, "case_publication_audit") == publication_audit
    assert len(rows(j, "investigations")) == 3
    assert len(rows(j, "investigation_references")) == 3
    frozen_evidence = rows(j, "investigation_evidence")
    assert run(j) == []
    assert queue(j).enqueue() == []
    assert rows(j, "case_publications") == snapshot
    assert rows(j, "investigation_evidence") == frozen_evidence
    with pytest.raises(sqlite3.IntegrityError):
        with Store(j.path)._connection() as conn:
            conn.execute("UPDATE case_publications SET payload_json='{}'")
    with pytest.raises(sqlite3.IntegrityError):
        with Store(j.path)._connection() as conn:
            conn.execute("UPDATE investigation_evidence SET original_json='{}'")


@pytest.mark.parametrize("reason", ["transport_failure", "rate_limited", "server_error"])
def test_transient_restart_delay_and_recovery(journey, reason):
    j = journey
    queue(j).enqueue(1)
    first = run(j, Failure(reason), retry_seconds=5)[0]
    assert first["state"] == "retry_wait"
    empty_reports(j)
    assert queue(j).health()["delayed_retries"] == 1
    assert run(j) == []
    assert first["available_at"] == j.now[0] + 5
    j.now[0] += 4.999
    assert run(j) == []
    j.now[0] = first["available_at"]
    # Crash after claim: no work is automatically reclaimed before explicit recovery.
    claimed = queue(j).claim("crashed", lease_seconds=1)
    j.now[0] += 1
    assert queue(j).health()["overdue_leases"] == 1
    assert run(j) == []
    assert queue(j).recover(retry_seconds=1) == 1
    empty_reports(j)
    j.now[0] += 1
    result = run(j)[0]
    assert_completed(j, result)
    assert result["lease_generation"] == claimed["lease_generation"] + 1
    assert [a["outcome"] for a in result["attempts"]] == [
        "transient",
        "lease_expired",
        "completed",
    ]


@pytest.mark.parametrize(
    "reason,status,attempts",
    [
        ("document_missing", "missing", 1),
        ("transport_failure", "failed", 2),
    ],
)
def test_partial_terminal_and_local_preparation_rejected(journey, reason, status, attempts):
    j = journey
    queue(j).enqueue(1, max_attempts=attempts)
    for _ in range(attempts):
        result = run(j, Failure(reason, status), retry_seconds=1)[0]
        j.now[0] += 1
    assert result["state"] == "failed"
    report = Store(j.path).show_investigation(result["investigation_id"])
    assert report["status"] == "partial"
    assert report["evidence_gaps"][0]["reason"] == reason
    assert queue(j).health()["linked_partial_reports"] == 1
    with pytest.raises(ValueError, match="not eligible"):
        prepare_case(Store(j.path), report["investigation_id"], SimpleNamespace(target="offline"))
    assert rows(j, "case_publications") == []


@pytest.mark.parametrize(
    "reason",
    [
        "authentication_failed",
        "authorization_failed",
        "tls_verification_failed",
        "index_not_permitted",
        "identity_or_document_invalid",
    ],
)
def test_permanent_fail_closed_diagnostics(journey, reason, caplog):
    j = journey
    queue(j).enqueue(1)
    with caplog.at_level("INFO", logger="soc_automation"):
        result = run(j, Failure(reason))[0]
    assert result["state"] == "failed"
    assert result["failure_code"] == "permanent"
    assert result["investigation_id"] is None
    empty_reports(j)
    assert queue(j).health()["failed_without_reports"] == 1
    events = [json.loads(JsonFormatter().format(r)) for r in caplog.records]
    assert [e["event"] for e in events] == ["job_claim", "job_failed"]
    assert events[-1]["diagnostic_code"] == "permanent"
    assert reason not in json.dumps(events)


@pytest.mark.parametrize("phase", ["retrieval_expiry", "transaction_crash"])
def test_atomic_failure_stale_generation_and_restart(journey, monkeypatch, phase):
    j = journey
    job = queue(j).enqueue(1)[0]
    if phase == "retrieval_expiry":

        class Expiring:
            def retrieve_many(self, refs):
                j.now[0] += 61
                return j.provider.retrieve_many(refs)

        with pytest.raises(StateError):
            run(j, Expiring())
    else:
        original = Store._save_investigation

        def crash(self, *args):
            original(self, *args)
            raise KeyboardInterrupt

        with monkeypatch.context() as patch:
            patch.setattr(Store, "_save_investigation", crash)
            with pytest.raises(KeyboardInterrupt):
                run(j)
        j.now[0] += 61
    empty_reports(j)
    stale = queue(j).inspect(job["id"])
    assert stale["state"] == "leased"
    assert stale["attempts"][0]["outcome"] is None
    assert queue(j).recover(retry_seconds=1) == 1
    j.now[0] += 1
    replacement = queue(j).claim(stale["lease_owner"])
    assert replacement["lease_generation"] == stale["lease_generation"] + 1
    report = construct_investigation(Store(j.path), stale["selection"], j.provider)
    with pytest.raises(StateError, match="ownership"):
        queue(j).complete(job["id"], stale["lease_owner"], stale["lease_generation"], report)
    empty_reports(j)
    queue(j).complete(
        job["id"], replacement["lease_owner"], replacement["lease_generation"], report
    )
    assert_completed(j, queue(j).inspect(job["id"]))


def test_concurrent_workers_and_health(journey):
    j = journey
    jobs = queue(j).enqueue()
    health = queue(j).health(1)
    assert health["ready_queued"] == health["pending_total"] == 3
    assert health["pending_truncated"]
    assert health["oldest_pending_jobs"][0]["id"] == min(r["id"] for r in jobs)
    barrier = Barrier(3, timeout=10)

    class Competing:
        def retrieve_many(self, refs):
            # All three workers must hold separate leases before any can finish.
            barrier.wait()
            return j.provider.retrieve_many(refs)

    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(lambda _: run(j, Competing()), range(3)))
    completed = [r for batch in results for r in batch]
    assert len(completed) == 3
    assert len({r["attempts"][0]["owner"] for r in completed}) == 3
    assert all(len(r["attempts"]) == 1 for r in completed)
    assert {r["id"] for r in completed} == {r["id"] for r in jobs}
    for result in completed:
        assert_completed(j, result)
    assert len(rows(j, "investigations")) == len(rows(j, "investigation_evidence")) == 3
    assert queue(j).health()["state_counts"]["completed"] == 3


def test_cli_job_failure_process_failure_and_json(journey, monkeypatch, capsys):
    j = journey
    queue(j).enqueue(1)
    monkeypatch.setenv("SOC_DATABASE_PATH", str(j.path))
    monkeypatch.setattr(
        "soc_automation.cli.FixtureEvidenceProvider", lambda _: Failure("authentication_failed")
    )
    assert main(["run-investigation-worker", "--once", "--evidence-dir", str(j.directory)]) == 0
    failed = json.loads(capsys.readouterr().out)[0]
    assert failed["state"] == "failed"
    assert main(["investigation-queue-health"]) == 0
    assert json.loads(capsys.readouterr().out)["failed_without_reports"] == 1
    assert main(["show-investigation-job", "--job-id", "unknown"]) == 1
    assert capsys.readouterr().out == ""


def test_changed_source_cannot_mutate_retained_evidence(journey):
    j = journey
    first = queue(j).enqueue(1)[0]
    assert_completed(j, run(j)[0])
    retained = rows(j, "investigation_evidence")
    # A second alert references the same source identity with changed content.
    original_id = json.loads(first["selection_json"])[0]
    original = Store(j.path).show_alert(original_id, evidence=True)["original"]
    document = {**original, "_id": "conflicting-alert"}
    ingest(Store(j.path), encode(document).encode())
    queue(j).enqueue()

    class Changed:
        def retrieve_many(self, refs):
            results = j.provider.retrieve_many(refs)
            return [
                Retrieval(
                    r.reference,
                    "found",
                    {
                        **r.document,
                        "_source": {
                            **r.document["_source"],
                            "event": {"category": ["process"], "action": "changed"},
                        },
                    },
                )
                for r in results
            ]

    # Exercise all queued alerts; UUID ordering can place the conflict anywhere.
    outcomes = []
    for _ in range(3):
        outcomes.extend(run(j, Changed()))
    failed = [r for r in outcomes if r["state"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["investigation_id"] is None
    assert failed[0]["failure_code"] == "permanent"
    assert all(row in rows(j, "investigation_evidence") for row in retained)
    assert len(rows(j, "investigations")) == 3
