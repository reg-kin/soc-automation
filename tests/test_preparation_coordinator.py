"""Bounded offline orchestration using real discovery and preparation transactions."""

import sqlite3
from unittest.mock import patch

import pytest
from test_preparation import TARGET, enqueue
from test_preparation import queue as preparation_queue

from soc_automation.preparation_coordinator import run_pass
from soc_automation.state import Store


@pytest.fixture
def queue(tmp_path):
    return preparation_queue.__wrapped__(tmp_path)


def test_empty(tmp_path):
    store = Store(tmp_path / "empty.db")
    store.initialize()
    result = run_pass(store, TARGET)
    assert result.stopped is None
    assert result.claimed == result.resolved == 0
    assert not result.discovery_budget_exhausted


@pytest.mark.parametrize("kwargs", [{"processing_limit": True}, {"discovery_limit": 0},
                                    {"recovery_limit": 1001}, {"lease_seconds": -1}])
def test_validation_before_mutation(queue, kwargs):
    store, _, _ = queue
    with patch.object(store, "recover_case_preparations") as recover:
        with pytest.raises(ValueError):
            run_pass(store, TARGET, **kwargs)
        recover.assert_not_called()
    with pytest.raises(ValueError):
        run_pass(store, "https://invalid")


def test_success_and_idempotence(queue):
    store, _, _ = queue
    result = run_pass(store, TARGET)
    assert result.completed == 1
    assert result.stopped is None
    assert run_pass(store, TARGET).completed == 0
    job_id = result.outcomes[0]["job_id"]
    job = store.show_case_preparation(job_id)
    publication = store.show_case_publication(job["publication_id"])
    assert publication["state"] == "prepared"
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 1


def test_backlog_first_and_adoption(queue):
    store, report, payload = queue
    publication = store.prepare_publication(report["investigation_id"], TARGET, payload)
    job = enqueue(queue)
    with patch.object(store, "advance_case_preparation_discovery",
                      wraps=store.advance_case_preparation_discovery) as advance:
        result = run_pass(store, TARGET, processing_limit=1, discovery_limit=2)
    assert result.completed == 1
    assert advance.call_count == 1
    assert store.show_case_preparation(job["id"])["publication_id"] == publication["id"]


def test_foreign_target_does_not_block(queue):
    store, report, _ = queue
    job = store.enqueue_case_preparation(report["investigation_id"],
                                         "https://other.test/default/securitySolution")
    result = run_pass(store, TARGET)
    assert result.stopped is None
    assert result.completed == 1
    assert store.show_case_preparation(job["id"])["state"] == "queued"


def test_foreign_claim_race(queue):
    store, report, _ = queue
    foreign = store.enqueue_case_preparation(report["investigation_id"],
                                             "https://other.test/default/securitySolution")
    with patch.object(store, "eligible_case_preparations", side_effect=AssertionError):
        result = run_pass(store, TARGET)
    assert result.stopped is None
    assert result.completed == 1
    assert store.show_case_preparation(foreign["id"])["state"] == "queued"


def test_lane_fairness_and_admission(queue):
    store, _, _ = queue
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    # Append live audit events through the existing idempotent investigation save.
    report = store.show_investigation(queue[1]["investigation_id"])
    store.save_investigation(report, report["request_fingerprint"])
    with patch.object(store, "advance_case_preparation_discovery",
                      wraps=store.advance_case_preparation_discovery) as advance:
        result = run_pass(store, TARGET, discovery_limit=2, processing_limit=2)
    assert result.resolved <= 2
    assert [c.kwargs["lane"] for c in advance.call_args_list] == ["historical", "live"]
    assert all(c.kwargs["limit"] > 0 for c in advance.call_args_list)
    assert store.case_preparation_discovery_checkpoint(TARGET)["revision"] > checkpoint["revision"]


def test_unexpected_completion_rolls_back_and_recovers(queue):
    store, _, _ = queue
    job = enqueue(queue)
    with store._connection() as conn:
        conn.execute("CREATE TRIGGER reject_completion BEFORE INSERT ON case_preparation_audit "
                     "WHEN NEW.event='completed' BEGIN SELECT RAISE(ABORT,'injected'); END")
    result = run_pass(store, TARGET)
    assert result.stopped == "unexpected"
    leased = store.show_case_preparation(job["id"])
    assert leased["state"] == "leased"
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 0
    with patch("time.time", return_value=leased["lease_until"]):
        assert run_pass(store, TARGET).recovered == 1


def test_contention_retry_and_exhaustion(queue):
    store, _, _ = queue
    job = enqueue(queue, max_attempts=1)
    error = sqlite3.OperationalError("arbitrary text")
    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
    with patch.object(store, "complete_case_preparation", side_effect=error):
        result = run_pass(store, TARGET)
    assert result.outcomes[0]["status"] == "transient"
    assert store.show_case_preparation(job["id"])["state"] == "failed"


def test_lease_loss(queue):
    store, _, _ = queue
    enqueue(queue)
    original = store.complete_case_preparation

    def expire(*args, **kwargs):
        with patch("time.time", return_value=10**12):
            return original(*args, **kwargs)

    with patch.object(store, "complete_case_preparation", side_effect=expire):
        # Ownership read also observes expiry.
        with patch("soc_automation.preparation_coordinator._ownership", return_value=False):
            result = run_pass(store, TARGET)
    assert result.stopped == "lease_lost"


def test_no_clients_or_publication(queue):
    store, _, _ = queue
    with (patch("soc_automation.kibana.KibanaClient", side_effect=AssertionError),
          patch.object(store, "claim_publication", side_effect=AssertionError),
          patch.object(store, "publication_outcome", side_effect=AssertionError)):
        assert run_pass(store, TARGET).completed == 1


@pytest.mark.parametrize("kind", ["renderer", "permanent", "unexpected", "retry"])
def test_failure_categories(queue, kind):
    from soc_automation.cases import ReportIneligible
    from soc_automation.state import EvidenceConflict

    store, _, _ = queue
    job = enqueue(queue)
    errors = {"renderer": ReportIneligible("any"), "permanent": EvidenceConflict("any"),
              "unexpected": RuntimeError("database is locked"),
              "retry": sqlite3.OperationalError("any")}
    errors["retry"].sqlite_errorcode = sqlite3.SQLITE_LOCKED
    with patch("soc_automation.preparation_coordinator._payload", side_effect=errors[kind]):
        result = run_pass(store, TARGET)
    saved = store.show_case_preparation(job["id"])
    expected = {"renderer": "renderer_mismatch", "permanent": "permanent",
                "unexpected": "unexpected", "retry": "transient"}[kind]
    assert result.outcomes[0]["status"] == expected
    assert saved["state"] == {"renderer": "failed", "permanent": "failed",
                              "unexpected": "leased", "retry": "retry_wait"}[kind]
    if kind == "retry":
        assert saved["available_at"] > saved["created_at"]
        assert run_pass(store, TARGET).claimed == 0


@pytest.mark.parametrize("mutation", ["partial", "incompatible"])
def test_ineligible_discovery(queue, mutation):
    from soc_automation.ingestion import encode

    store, report, _ = queue
    if mutation == "partial":
        report["status"] = "partial"
    else:
        report["engine_version"] = "unsupported"
    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET report_json=?", (encode(report),))
    result = run_pass(store, TARGET)
    assert result.stopped is None
    assert result.completed == result.discovered == 0
    assert result.resolved > 0


def test_budgets_and_backpressure(queue):
    store, _, _ = queue
    for index in range(2):
        store.enqueue_case_preparation(queue[1]["investigation_id"],
                                       f"https://foreign{index}.test/default/securitySolution")
    result = run_pass(store, TARGET, processing_limit=1, discovery_limit=2)
    assert result.completed == 0
    assert result.resolved == 0
    assert result.discovery_budget_exhausted
    assert not result.processing_budget_exhausted


def test_single_discovery_budget_progress(queue):
    store, _, _ = queue
    with pytest.raises(ValueError):
        run_pass(store, TARGET, discovery_limit=1, processing_limit=1)
    assert store.case_preparation_discovery_checkpoint(TARGET) is None


def test_no_network(queue):
    with patch("socket.socket", side_effect=AssertionError("network forbidden")):
        assert run_pass(queue[0], TARGET).completed == 1


def test_processing_limit_and_existing_backlog_priority(queue):
    from test_preparation import FIXTURES

    from soc_automation.evidence import FixtureEvidenceProvider
    from soc_automation.service import investigate

    store, report, _ = queue
    first = enqueue(queue)
    for identifier in report["source_alert_ids"][:2]:
        other = investigate(store, [identifier], FixtureEvidenceProvider(FIXTURES / "evidence"))
        store.enqueue_case_preparation(other["investigation_id"], TARGET)
    result = run_pass(store, TARGET, processing_limit=1, discovery_limit=2)
    assert result.claimed == result.completed == 1
    assert result.outcomes[0]["job_id"] == first["id"]
    assert result.processing_budget_exhausted
    assert result.discovery_budget_exhausted
    assert result.resolved == 2  # Existing identities resolve even at capacity.


def test_renderer_version_and_stale_generation(queue):
    store, _, _ = queue
    job = enqueue(queue)
    claim = store.claim_case_preparation

    def incompatible(**kwargs):
        return dict(claim(**kwargs), renderer_version="old")

    with patch.object(store, "claim_case_preparation", side_effect=incompatible):
        result = run_pass(store, TARGET)
    assert result.outcomes[0]["status"] == "renderer_mismatch"
    assert store.show_case_preparation(job["id"])["state"] == "failed"


def test_unknown_ownership_retains_lease(queue):
    store, _, _ = queue
    job = enqueue(queue)
    with (patch("soc_automation.preparation_coordinator._payload", side_effect=OSError),
          patch("soc_automation.preparation_coordinator._ownership", return_value=None)):
        result = run_pass(store, TARGET)
    assert result.stopped == "ownership_unknown"
    assert store.show_case_preparation(job["id"])["state"] == "leased"


def test_stale_claim_generation_is_fenced(queue):
    store, _, _ = queue
    job = enqueue(queue)
    claim = store.claim_case_preparation

    def stale(**kwargs):
        current = claim(**kwargs)
        return dict(current, lease_generation=current["lease_generation"] + 1)

    with patch.object(store, "claim_case_preparation", side_effect=stale):
        result = run_pass(store, TARGET)
    assert result.stopped == "lease_lost"
    assert store.show_case_preparation(job["id"])["state"] == "leased"
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 0


def test_discovery_transaction_rollback(queue):
    store, _, _ = queue
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    with store._connection() as conn:
        conn.execute("CREATE TRIGGER reject_discovery BEFORE UPDATE ON case_preparation_discovery "
                     "BEGIN SELECT RAISE(ABORT,'injected'); END")
    result = run_pass(store, TARGET)
    assert result.stopped == "unexpected"
    assert store.case_preparation_discovery_checkpoint(TARGET) == checkpoint
    assert store.case_preparation_stats()["state_counts"]["queued"] == 0


@pytest.mark.parametrize("separate", [False, True])
def test_coordinators_compete_for_capacity(queue, separate):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    store, report, _ = queue
    # Hold one slot so the two passes compete for the remaining slot.
    store.enqueue_case_preparation(report["investigation_id"],
                                   "https://held.test/default/securitySolution")
    targets = [TARGET, "https://other.test/default/securitySolution"]
    barrier = Barrier(2)

    def run(target):
        connection = Store(store.path) if separate else store
        barrier.wait()
        return run_pass(connection, target, processing_limit=1, discovery_limit=2)

    # Keep admitted work leased, simulating a worker stopped by an unexpected error.
    with patch("soc_automation.preparation_coordinator._payload", side_effect=RuntimeError):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, targets))
    assert sum(result.discovered for result in results) == 1
    counts = store.case_preparation_stats()["state_counts"]
    assert sum(counts[state] for state in ("queued", "retry_wait", "leased")) == 2
    assert sorted(result.resolved for result in results) == [0, 1]


@pytest.mark.parametrize("kind", ["payload", "head", "sent", "unexpected"])
def test_completion_classification_real_validation(queue, kind):
    from review_helpers import approve

    store, report, payload = queue
    job = enqueue(queue)
    if kind in ("head", "sent"):
        publication = store.prepare_publication(
            report["investigation_id"], TARGET,
            dict(payload, title="different") if kind == "head" else payload,
        )
        if kind == "sent":
            approve(store, publication["id"])
            store.claim_publication(publication["id"], publication["payload_sha256"])
    if kind == "payload":
        mocked = patch("soc_automation.preparation_coordinator._payload",
                       return_value=dict(payload, title="different"))
    elif kind == "unexpected":
        mocked = patch.object(store, "_prepare_publication", side_effect=KeyError("mismatch"))
    else:
        mocked = patch.object(store, "validate_case_evidence", wraps=store.validate_case_evidence)
    with mocked:
        result = run_pass(store, TARGET)
    saved = store.show_case_preparation(job["id"])
    assert result.outcomes[0]["status"] == ("unexpected" if kind == "unexpected" else "permanent")
    assert saved["state"] == ("leased" if kind == "unexpected" else "failed")


def test_one_free_slot_lane_progress_rotates(queue):
    from test_preparation import FIXTURES

    from soc_automation.evidence import FixtureEvidenceProvider
    from soc_automation.service import investigate

    store, report, _ = queue
    store.enqueue_case_preparation(report["investigation_id"],
                                   "https://held.test/default/securitySolution")
    initial = store.initialize_case_preparation_discovery(TARGET)
    live = investigate(store, [report["source_alert_ids"][0]],
                       FixtureEvidenceProvider(FIXTURES / "evidence"))
    first = run_pass(store, TARGET, processing_limit=1, discovery_limit=2)
    checkpoint = store.case_preparation_discovery_checkpoint(TARGET)
    assert first.completed == 1
    assert checkpoint["historical_cursor"] == 0
    assert checkpoint["live_cursor"] > initial["live_cursor"]
    # Keep the live lane pending. The next pass gives the sole free slot to history.
    store.save_investigation(live, live["request_fingerprint"])
    second = run_pass(store, TARGET, processing_limit=1, discovery_limit=2)
    assert second.completed == 1
    assert store.case_preparation_discovery_checkpoint(TARGET)["historical_cursor"] > 0


def test_real_write_contention_keeps_live_lease(queue):
    store, _, _ = queue
    job = enqueue(queue)
    worker = Store(store.path, timeout=0)
    complete = worker.complete_case_preparation
    lock = store._connection()

    def contend(*args, **kwargs):
        lock.__enter__()
        return complete(*args, **kwargs)

    try:
        with patch.object(worker, "complete_case_preparation", side_effect=contend):
            result = run_pass(worker, TARGET)
        assert result.stopped == "contention"
        assert store.show_case_preparation(job["id"])["state"] == "leased"
        assert len(store.case_preparation_audit(job["id"])) == 2
    finally:
        lock.__exit__(None, None, None)


def test_repeated_single_slot_admissions_are_fair(queue):
    store, report, _ = queue

    import json

    from test_preparation import FIXTURES

    from soc_automation.evidence import FixtureEvidenceProvider
    from soc_automation.service import ingest, investigate

    provider = FixtureEvidenceProvider(FIXTURES / "evidence")

    def save(index):
        alert = json.loads((FIXTURES / "stages.json").read_text())[0]
        alert["_id"] = f"fairness-{index}"
        identifier = ingest(store, json.dumps([alert]).encode())[0]["alert_id"]
        return investigate(store, [identifier], provider)["investigation_id"]

    for index in range(12):
        save(index)
    store.enqueue_case_preparation(report["investigation_id"],
                                   "https://held.test/default/securitySolution")
    store.initialize_case_preparation_discovery(TARGET)
    live_ids = {save(index) for index in range(12, 24)}
    winners = []
    for _ in range(10):
        # Reopen each pass: priority must survive coordinator restarts.
        worker = Store(store.path)
        for lane in ("historical", "live"):
            page = worker.preview_case_preparation_discovery(TARGET, lane=lane, limit=1)
            assert page["records"][0]["eligible"]
        # Another bounded discovery attempt sees no capacity. Both no-op CAS
        # updates must preserve the turn owed by the previous admission.
        checkpoint = worker.case_preparation_discovery_checkpoint(TARGET)
        for lane in ("historical", "live"):
            blocked = worker.advance_case_preparation_discovery(
                TARGET, lane=lane, expected_revision=checkpoint["revision"],
                limit=1, outstanding_limit=1,
            )
            assert blocked["records"] == []
            checkpoint = blocked["checkpoint"]
        result = run_pass(worker, TARGET, processing_limit=1, discovery_limit=2)
        assert result.stopped is None
        assert result.discovered == result.completed == 1
        job = worker.show_case_preparation(result.outcomes[0]["job_id"])
        winners.append("live" if job["investigation_id"] in live_ids else "historical")
        assert worker.case_preparation_stats()["state_counts"]["queued"] == 1
    assert winners == ["live", "historical"] * 5
