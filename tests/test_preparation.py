"""Offline Store queue lifecycle, fencing, and transaction rollback contracts."""

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from soc_automation.cases import render
from soc_automation.evidence import FixtureEvidenceProvider
from soc_automation.service import ingest, investigate
from soc_automation.state import EvidenceConflict, PreparationMismatch, StateError, Store

TARGET = "https://example.test/default/securitySolution"
FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.fixture
def queue(tmp_path):
    store = Store(tmp_path / "state.db")
    store.initialize()
    ids = [r["alert_id"] for r in ingest(store, (FIXTURES / "stages.json").read_bytes())]
    report = investigate(store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
    payload = render(report, [store.show_alert(i, evidence=True)
                              for i in report["source_alert_ids"]])
    return store, report, payload


def enqueue(queue, **kwargs):
    store, report, _ = queue
    return store.enqueue_case_preparation(report["investigation_id"], TARGET, **kwargs)


def lease_args(job):
    return job["id"], job["lease_owner"], job["lease_generation"]


def test_enqueue_identity_and_bounded_reads(queue):
    store, report, _ = queue
    job = enqueue(queue)
    assert enqueue(queue, max_attempts=5) == job
    assert "report_json" not in job
    assert store.show_case_preparation(job["id"], snapshot=True)["report_json"]
    assert store.eligible_case_preparations(limit=1) == [job]
    assert store.case_preparation_stats()["eligible"] == 1
    assert len(store.case_preparation_audit(job["id"], limit=1)) == 1
    assert store.case_preparation_audit(job["id"], after_id=1) == []
    for bound in (0, -1, True, 1001):
        with pytest.raises(ValueError):
            store.eligible_case_preparations(limit=bound)
    with pytest.raises(ValueError):
        store.enqueue_case_preparation(report["investigation_id"], "http://example.test")
    with pytest.raises(StateError):
        store.enqueue_case_preparation("missing", TARGET)
    # Inject corruption after deliberately disabling immutability in this test only.
    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        changed = dict(report, audit_correlation_id="changed")
        from soc_automation.ingestion import encode

        conn.execute("UPDATE investigations SET report_json=? WHERE id=?",
                     (encode(changed), report["investigation_id"]))
    with pytest.raises(EvidenceConflict):
        enqueue(queue)


@pytest.mark.parametrize("mutation", ["partial", "gap", "hash", "fact"])
def test_ineligible_reports(queue, mutation):
    store, report, _ = queue
    report = copy.deepcopy(report)
    if mutation == "partial":
        report["status"] = "partial"
    elif mutation == "gap":
        report["evidence_gaps"] = ["missing"]
    elif mutation == "hash":
        report["retrieved_evidence"][0]["sha256"] = "0" * 64
    else:
        report["observed_facts"][0]["context"]["host.id"] = "invented"
    from soc_automation.ingestion import encode

    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET report_json=? WHERE id=?",
                     (encode(report), report["investigation_id"]))
    with pytest.raises((StateError, ValueError)):
        enqueue(queue)
    assert store.case_preparation_stats()["state_counts"]["queued"] == 0


def test_competing_claims_and_generated_tokens(queue):
    store, _, _ = queue
    enqueue(queue)
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = list(pool.map(lambda _: store.claim_case_preparation(), range(4)))
    claimed = [job for job in jobs if job is not None]
    assert len(claimed) == 1
    assert claimed[0]["attempt_count"] == claimed[0]["lease_generation"] == 1
    assert [r["event"] for r in store.case_preparation_audit(claimed[0]["id"])] == [
        "enqueued", "claimed",
    ]


def test_fencing_renewal_expiry_and_recovery(queue):
    store, _, payload = queue
    with patch("time.time", return_value=100):
        enqueue(queue, max_attempts=2)
        job = store.claim_case_preparation()
        for owner, generation in [("wrong", 1), (job["lease_owner"], 2)]:
            with pytest.raises(StateError):
                store.renew_case_preparation(job["id"], owner, generation)
            with pytest.raises(StateError):
                store.fail_case_preparation(job["id"], owner, generation, failure="permanent")
            with pytest.raises(StateError):
                store.complete_case_preparation(job["id"], owner, generation, payload=payload)
        renewed = store.renew_case_preparation(*lease_args(job), lease_seconds=1)
        assert renewed["lease_until"] > job["lease_until"]
    with patch("time.time", return_value=renewed["lease_until"]):
        with pytest.raises(StateError):
            store.renew_case_preparation(*lease_args(job))
        with pytest.raises(StateError):
            store.fail_case_preparation(*lease_args(job), failure="permanent")
        with pytest.raises(StateError):
            store.complete_case_preparation(*lease_args(job), payload=payload)
        assert store.case_preparation_stats()["expired"] == 1
        # A fresh Store instance recovers a crashed process's persisted lease.
        assert Store(store.path).recover_case_preparations() == 1
        recovered = store.show_case_preparation(job["id"])
        assert recovered["failure_code"] == "lease_expired"
        assert recovered["available_at"] == renewed["lease_until"] + 60
        assert store.claim_case_preparation() is None
    with patch("time.time", return_value=recovered["available_at"]):
        next_job = store.claim_case_preparation()
        assert next_job["lease_owner"] != job["lease_owner"]
        assert next_job["lease_generation"] == 2
        with pytest.raises(StateError):
            store.renew_case_preparation(*lease_args(job))
    with patch("time.time", return_value=next_job["lease_until"]):
        assert store.recover_case_preparations() == 1
        assert store.show_case_preparation(job["id"])["state"] == "failed"
        assert store.recover_case_preparations() == 0
    audit = store.case_preparation_audit(job["id"])
    assert audit[-1]["owner"] == next_job["lease_owner"]
    assert audit[-1]["diagnostic_code"] == "lease_expired"


def test_retry_budget_and_backoff(queue):
    store, _, _ = queue
    now = 100
    with patch("time.time", return_value=now):
        enqueue(queue, max_attempts=3)
    for attempt in range(1, 4):
        with patch("time.time", return_value=now):
            job = store.claim_case_preparation()
            result = store.fail_case_preparation(*lease_args(job), failure="transient")
            if attempt < 3:
                assert result["available_at"] == now + 60 * 2 ** (attempt - 1)
                assert result["state"] == "retry_wait"
                assert store.claim_case_preparation() is None
                now = result["available_at"]
            else:
                assert result["state"] == "failed"
                assert result["available_at"] == job["available_at"]
    assert store.claim_case_preparation() is None
    with pytest.raises(StateError):
        store.fail_case_preparation(*lease_args(job), failure="transient")


@pytest.mark.parametrize("code", ["permanent", "renderer_mismatch"])
def test_permanent_failures_never_retry(queue, code):
    store, _, _ = queue
    enqueue(queue)
    job = store.claim_case_preparation()
    with pytest.raises(ValueError):
        store.fail_case_preparation(*lease_args(job), failure="lease_expired")
    assert store.fail_case_preparation(*lease_args(job), failure=code)["state"] == "failed"
    assert store.claim_case_preparation() is None


def test_atomic_completion_rollback_and_adoption(queue):
    store, _, payload = queue
    enqueue(queue)
    job = store.claim_case_preparation()
    with store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER fail_completion BEFORE INSERT ON case_preparation_audit "
            "WHEN NEW.event='completed' BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.complete_case_preparation(*lease_args(job), payload=payload)
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM publication_heads").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM case_publication_audit").fetchone()[0] == 0
    assert store.show_case_preparation(job["id"])["state"] == "leased"
    assert len(store.case_preparation_audit(job["id"])) == 2
    with store._connection() as conn:
        conn.execute("DROP TRIGGER fail_completion")
    completed = store.complete_case_preparation(*lease_args(job), payload=payload)
    assert completed["state"] == "completed"
    publication = store.show_case_publication(completed["publication_id"])
    assert publication["state"] == "prepared"
    assert json.loads(publication["payload_json"]) == payload
    assert store.case_preparation_audit(job["id"])[-1]["owner"] == job["lease_owner"]
    with pytest.raises(StateError):
        store.complete_case_preparation(*lease_args(job), publication_id=publication["id"])


@pytest.mark.parametrize("adopt", [False, True])
def test_existing_publication_reused(queue, adopt):
    store, report, payload = queue
    publication = store.prepare_publication(report["investigation_id"], TARGET, payload)
    enqueue(queue)
    job = store.claim_case_preparation()
    kwargs = {"publication_id": publication["id"]} if adopt else {"payload": payload}
    assert store.complete_case_preparation(*lease_args(job), **kwargs)["publication_id"] == (
        publication["id"]
    )


def test_publication_mismatch_and_no_implicit_revision(queue):
    store, report, payload = queue
    enqueue(queue)
    job = store.claim_case_preparation()
    wrong = dict(payload, title="wrong", tags=["different-marker"])
    with pytest.raises(StateError):
        store.complete_case_preparation(*lease_args(job), payload=wrong)
    publication = store.prepare_publication(report["investigation_id"], TARGET, wrong)
    with pytest.raises(StateError):
        store.complete_case_preparation(*lease_args(job), publication_id=publication["id"])
    with pytest.raises(StateError):
        store.complete_case_preparation(*lease_args(job), payload=payload)
    valid = store.prepare_publication(report["investigation_id"], TARGET, payload, revise=True)
    newer = store.prepare_publication(
        report["investigation_id"], TARGET, dict(wrong, tags=["new-marker"]), revise=True
    )
    with pytest.raises(PreparationMismatch):
        store.complete_case_preparation(*lease_args(job), publication_id=valid["id"])
    assert store.show_case_publication(newer["id"])["state"] == "prepared"
    assert store.show_case_preparation(job["id"])["state"] == "leased"


def test_stale_evidence_completion(queue):
    store, report, payload = queue
    enqueue(queue)
    job = store.claim_case_preparation()
    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET evidence_fingerprint=? WHERE id=?",
                     ("0" * 64, report["investigation_id"]))
    with pytest.raises(EvidenceConflict):
        store.complete_case_preparation(*lease_args(job), payload=payload)
    assert store.show_case_preparation(job["id"])["state"] == "leased"


def test_claim_audit_rollback_and_append_only(queue):
    store, _, _ = queue
    job = enqueue(queue)
    with store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER fail_claim BEFORE INSERT ON case_preparation_audit "
            "WHEN NEW.event='claimed' BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.claim_case_preparation()
    assert store.show_case_preparation(job["id"]) == job
    for sql in (
        "DELETE FROM case_preparation_audit", "UPDATE case_preparation_audit SET owner='forged'",
        "DELETE FROM case_preparation_jobs",
        "INSERT INTO case_preparation_audit(job_id,event,generation,occurred_at) "
        "SELECT id,'enqueued',0,0 FROM case_preparation_jobs",
    ):
        with pytest.raises(sqlite3.IntegrityError), store._connection() as conn:
            conn.execute(sql)


def test_completion_expiry_rolls_back_prepared_publication(queue):
    store, _, payload = queue
    with patch("time.time", return_value=100):
        enqueue(queue)
        job = store.claim_case_preparation()
    original = store._prepare_publication
    clock_value = [101]

    def prepare_then_expire(*args, **kwargs):
        result = original(*args, **kwargs)
        clock_value[0] = 160
        return result

    with (patch("time.time", side_effect=lambda: clock_value[0]),
          patch.object(store, "_prepare_publication", side_effect=prepare_then_expire),
          pytest.raises(StateError)):
        store.complete_case_preparation(*lease_args(job), payload=payload)
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 0
    assert store.show_case_preparation(job["id"])["state"] == "leased"
    assert len(store.case_preparation_audit(job["id"])) == 2


def test_wrong_target_publication_and_delayed_claim(queue):
    store, report, payload = queue
    with patch("time.time", return_value=200):
        enqueue(queue)
    with patch("time.time", return_value=199):
        assert store.claim_case_preparation() is None
        assert store.eligible_case_preparations() == []
    with patch("time.time", return_value=200):
        job = store.claim_case_preparation()
        publication = store.prepare_publication(
            report["investigation_id"], "https://other.test/default/securitySolution", payload,
        )
        with pytest.raises(PreparationMismatch):
            store.complete_case_preparation(*lease_args(job), publication_id=publication["id"])
    assert store.show_case_preparation(job["id"])["state"] == "leased"


def test_concurrent_idempotent_enqueue(queue):
    store, report, _ = queue
    from threading import Barrier

    barrier = Barrier(4)

    def submit(budget):
        barrier.wait()
        return Store(store.path).enqueue_case_preparation(
            report["investigation_id"], TARGET, max_attempts=budget,
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = list(pool.map(submit, range(1, 5)))
    assert all(job == jobs[0] for job in jobs)
    assert len(store.eligible_case_preparations()) == 1
    assert len(store.case_preparation_audit(jobs[0]["id"])) == 1


def test_wrong_investigation_adoption(queue):
    store, report, payload = queue
    # Use an identical report/payload under another persisted identity so the
    # deterministic payload check passes and the association guard is exercised.
    with store._connection() as conn:
        conn.execute(
            "INSERT INTO investigations SELECT ?,?,report_json,evidence_fingerprint "
            "FROM investigations WHERE id=?",
            ("other-investigation", "other-request", report["investigation_id"]),
        )
    publication = store.prepare_publication("other-investigation", TARGET, payload)
    enqueue(queue)
    job = store.claim_case_preparation()
    with pytest.raises(PreparationMismatch):
        store.complete_case_preparation(*lease_args(job), publication_id=publication["id"])
    assert store.show_case_preparation(job["id"])["publication_id"] is None
    assert len(store.case_preparation_audit(job["id"])) == 2


@pytest.mark.parametrize("adopt", [False, True])
@pytest.mark.parametrize("state", ["sending", "uncertain", "published"])
def test_non_prepared_publication_rejected(queue, adopt, state):
    from review_helpers import approve

    store, report, payload = queue
    publication = store.prepare_publication(report["investigation_id"], TARGET, payload)
    approve(store, publication["id"])
    assert store.claim_publication(publication["id"], publication["payload_sha256"])
    if state == "uncertain":
        store.publication_outcome(publication["id"])
    elif state == "published":
        store.publication_outcome(publication["id"], {"id": "remote-case", "version": "1"})
    enqueue(queue)
    job = store.claim_case_preparation()
    kwargs = {"publication_id": publication["id"]} if adopt else {"payload": payload}
    with pytest.raises(PreparationMismatch):
        store.complete_case_preparation(*lease_args(job), **kwargs)
    assert store.show_case_preparation(job["id"])["state"] == "leased"
    assert len(store.case_preparation_audit(job["id"])) == 2


@pytest.mark.parametrize("adopt", [False, True])
def test_recovery_and_completion_at_expiry(queue, adopt):
    store, report, payload = queue
    publication = store.prepare_publication(report["investigation_id"], TARGET, payload)
    with patch("time.time", return_value=100):
        enqueue(queue)
        job = store.claim_case_preparation()
    kwargs = {"publication_id": publication["id"]} if adopt else {"payload": payload}
    with patch("time.time", return_value=159):
        assert Store(store.path).recover_case_preparations() == 0
    with patch("time.time", return_value=160):
        with pytest.raises(StateError):
            store.complete_case_preparation(*lease_args(job), **kwargs)
        assert Store(store.path).recover_case_preparations() == 1
    recovered = store.show_case_preparation(job["id"])
    with patch("time.time", return_value=recovered["available_at"]):
        new_job = store.claim_case_preparation()
        with pytest.raises(StateError):
            store.complete_case_preparation(*lease_args(job), **kwargs)
        completed = store.complete_case_preparation(*lease_args(new_job), **kwargs)
        assert completed["state"] == "completed"
        assert store.recover_case_preparations() == 0


def test_adoption_association_rollback(queue):
    store, report, payload = queue
    publication = store.prepare_publication(report["investigation_id"], TARGET, payload)
    enqueue(queue)
    job = store.claim_case_preparation()
    before = store.show_case_preparation(job["id"])
    audit = store.case_preparation_audit(job["id"])
    with store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER reject_association AFTER UPDATE ON case_preparation_jobs "
            "WHEN NEW.publication_id IS NOT NULL BEGIN SELECT RAISE(ABORT,'association'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="association"):
        store.complete_case_preparation(*lease_args(job), publication_id=publication["id"])
    assert store.show_case_preparation(job["id"]) == before
    assert store.case_preparation_audit(job["id"]) == audit
    assert store.show_case_publication(publication["id"])["state"] == "prepared"


@pytest.mark.parametrize("separate", [False, True])
def test_target_scoped_concurrent_claims(queue, separate):
    from threading import Barrier

    store, report, _ = queue
    foreign_target = "https://other.test/default/securitySolution"
    foreign = store.enqueue_case_preparation(report["investigation_id"], foreign_target)
    local = enqueue(queue)
    with pytest.raises(ValueError):
        store.claim_case_preparation(target="https://invalid")
    assert store.show_case_preparation(local["id"]) == local
    barrier = Barrier(4)

    def claim(index):
        connection = Store(store.path) if separate else store
        barrier.wait()
        return connection.claim_case_preparation(target=TARGET if index < 3 else foreign_target)

    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [job for job in pool.map(claim, range(4)) if job]
    assert {job["id"] for job in jobs} == {local["id"], foreign["id"]}
    assert all(job["attempt_count"] == job["lease_generation"] == 1 for job in jobs)
    assert all(len(store.case_preparation_audit(job["id"])) == 2 for job in jobs)
    assert store.claim_case_preparation(target=TARGET) is None


def test_target_claim_oldest_ready_order(queue):
    store, report, _ = queue
    with patch("time.time", return_value=100):
        foreign = store.enqueue_case_preparation(report["investigation_id"],
                                                 "https://other.test/default/securitySolution")
        first = enqueue(queue)
    other = investigate(store, [report["source_alert_ids"][0]],
                        FixtureEvidenceProvider(FIXTURES / "evidence"))
    second = store.enqueue_case_preparation(other["investigation_id"], TARGET)
    assert store.claim_case_preparation(target=TARGET)["id"] == first["id"]
    assert store.claim_case_preparation(target=TARGET)["id"] == second["id"]
    assert store.claim_case_preparation()["id"] == foreign["id"]
