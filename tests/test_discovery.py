"""Discovery partitions, resolution, replay, and read-only persistence contracts."""

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
import test_preparation
from test_preparation import TARGET

from soc_automation.ingestion import encode
from soc_automation.state import StateError, Store


@pytest.fixture
def queue(tmp_path):
    return test_preparation.queue.__wrapped__(tmp_path)


def advance(store, lane="historical", revision=0, **kwargs):
    return store.advance_case_preparation_discovery(
        TARGET, lane=lane, expected_revision=revision, **kwargs,
    )


def test_historical_live_and_replay(queue):
    store, report, _ = queue
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    high = checkpoint["historical_high_water"]
    store.save_investigation(report, report["request_fingerprint"])
    first = advance(store, limit=1)
    assert first["next_cursor"] == high
    job_id = first["records"][0]["preparation_id"]
    assert first["records"][0]["eligible"]
    assert "report_json" not in str(first)
    live = advance(Store(store.path), "live", 1, limit=1)
    assert live["next_cursor"] > high
    assert live["records"][0]["preparation_id"] == job_id
    assert live["checkpoint"]["historical_cursor"] == high
    assert store.initialize_case_preparation_discovery(TARGET) == live["checkpoint"]
    assert advance(store, revision=2)["records"] == []


@pytest.mark.parametrize("mutation", ["partial", "gap", "hash", "fact"])
def test_entirely_ineligible_completed_event(queue, mutation):
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
    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET report_json=?", (encode(report),))
    store.initialize_case_preparation_discovery(TARGET)
    result = advance(store)
    assert [r["eligible"] for r in result["records"]] == [False]
    assert result["checkpoint"]["historical_cursor"] > 0
    assert store.case_preparation_stats()["eligible"] == 0


def test_pagination_empty_and_failed_events(queue):
    store, _, _ = queue
    for i in range(4):
        store.investigation_failure(str(i))
    store.initialize_case_preparation_discovery(TARGET)
    seen = []
    for revision in range(3):
        page = advance(store, revision=revision, limit=2)
        seen.extend(r["audit_id"] for r in page["records"])
    assert seen == list(range(1, 6))
    assert advance(store, revision=3)["records"] == []
    with store._connection(readonly=True) as conn:
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT a.id,i.report_json FROM investigation_audit a "
            "LEFT JOIN investigations i ON i.id=a.investigation_id "
            "WHERE a.id>? AND a.id<=? ORDER BY a.id LIMIT ?", (0, 5, 2),
        ).fetchall()
    assert any("INTEGER PRIMARY KEY" in row[3] for row in plan)
    assert not any("TEMP B-TREE" in row[3] for row in plan)


def test_concurrent_cas_and_invalid_inputs(queue):
    store, _, _ = queue
    store.initialize_case_preparation_discovery(TARGET)

    def compete(_):
        try:
            return advance(Store(store.path))
        except StateError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, range(2)))
    assert sum(result is not None for result in results) == 1
    with pytest.raises(StateError):
        advance(store)
    for invalid in (-1, True, 1.5, 2**63):
        with pytest.raises(ValueError):
            advance(store, revision=invalid)
    for limit in (0, True, 1001):
        with pytest.raises(ValueError):
            advance(store, limit=limit)
    with pytest.raises(ValueError):
        advance(store, lane="other")


def test_crash_rolls_back_enqueues_and_progress(queue):
    store, report, _ = queue
    store.initialize_case_preparation_discovery(TARGET)
    original = store._enqueue_case_preparation

    def interrupted(*args):
        original(*args)
        raise RuntimeError("interrupted")

    with patch.object(store, "_enqueue_case_preparation", side_effect=interrupted):
        with pytest.raises(RuntimeError):
            advance(store)
    assert store.case_preparation_stats()["eligible"] == 0
    assert store.case_preparation_discovery_checkpoint(TARGET)["revision"] == 0
    # A separately committed enqueue before interruption is also safe to replay.
    prior = store.enqueue_case_preparation(report["investigation_id"], TARGET)
    assert advance(Store(store.path))["records"][0]["preparation_id"] == prior["id"]


def test_readonly_preview(queue, tmp_path):
    missing = Store(tmp_path / "missing.db")
    with pytest.raises(sqlite3.OperationalError):
        missing.preview_case_preparation_discovery(TARGET, lane="historical")
    assert not missing.path.exists()
    store, _, _ = queue
    before = store.path.read_bytes()
    page = store.preview_case_preparation_discovery(TARGET, lane="historical")
    assert page["records"][0]["eligible"]
    assert store.case_preparation_discovery_checkpoint(TARGET) is None
    assert store.path.read_bytes() == before
    store.initialize_case_preparation_discovery(TARGET)
    before = store.path.read_bytes()
    store.preview_case_preparation_discovery(TARGET, lane="historical")
    assert store.path.read_bytes() == before


def test_upgrade_and_migration_rollback(tmp_path):
    import soc_automation.state as state

    store = Store(tmp_path / "upgrade.db")
    with patch.object(state, "SCHEMA_VERSION", 8), patch.object(Store, "_validate"):
        store.initialize()
    with store._connection() as conn:
        conn.execute("INSERT INTO investigation_audit VALUES(1,NULL,'old','failed','time')")
    # Fail after migration DDL; the migration and version change must both roll back.
    with patch.object(Store, "_validate", side_effect=RuntimeError("interrupted")):
        with pytest.raises(RuntimeError):
            store.initialize()
    with store._connection(readonly=True) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 8
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE name='case_preparation_discovery'"
        ).fetchone() is None
    store.initialize()
    assert store.initialize_case_preparation_discovery(TARGET)["historical_high_water"] == 1
    assert advance(store)["records"] == [
        {"audit_id": 1, "investigation_id": None, "eligible": False},
    ]
    with patch.object(state, "SCHEMA_VERSION", 8):
        with pytest.raises(StateError):
            store.initialize()


@pytest.mark.parametrize("error", [StateError, ValueError, KeyError, TypeError, IndexError])
@pytest.mark.parametrize("origin", ["_validate_report_evidence", "_preparation_payload", "render"])
def test_unexpected_validation_failure_aborts(queue, error, origin):
    store, _, _ = queue
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    target = ("soc_automation.cases.render" if origin == "render" else None)
    mocked = (patch(target, side_effect=error("unexpected")) if target else
              patch.object(store, origin, side_effect=error("unexpected")))
    with mocked, pytest.raises(error):
        advance(store)
    assert store.case_preparation_discovery_checkpoint(TARGET) == checkpoint
    assert store.case_preparation_stats()["eligible"] == 0


def test_validation_failure_after_enqueue_rolls_back(queue):
    store, report, _ = queue
    store.save_investigation(report, report["request_fingerprint"])
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    original = store._validate_report_evidence
    calls = 0

    def validate(*args, **kwargs):
        nonlocal calls
        calls += 1
        # Two preview validations, then one enqueue succeeds before the second fails.
        if calls == 4:
            raise ValueError("unexpected validator failure")
        return original(*args, **kwargs)

    with patch.object(store, "_validate_report_evidence", side_effect=validate):
        with pytest.raises(ValueError, match="unexpected validator failure"):
            advance(store)
    assert store.case_preparation_discovery_checkpoint(TARGET) == checkpoint
    assert store.case_preparation_stats()["eligible"] == 0
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_preparation_audit").fetchone()[0] == 0


def test_empty_live_page_then_new_report(queue):
    store, report, _ = queue
    # Start with only failures; the first persisted report arrives after an empty live page.
    other = Store(store.path.parent / "empty.db")
    other.initialize()
    other.investigation_failure("before-boundary")
    initial = other.initialize_case_preparation_discovery(TARGET)
    empty = advance(other, "live")
    assert empty["records"] == []
    assert empty["next_cursor"] == initial["historical_high_water"]
    # Populate an independent database through the normal ingestion/persistence path.
    from soc_automation.evidence import FixtureEvidenceProvider
    from soc_automation.service import ingest, investigate

    ids = [r["alert_id"] for r in ingest(
        other, (test_preparation.FIXTURES / "stages.json").read_bytes(),
    )]
    saved = investigate(other, ids, FixtureEvidenceProvider(test_preparation.FIXTURES / "evidence"))
    live = advance(other, "live", 1)
    assert [r["investigation_id"] for r in live["records"]] == [saved["investigation_id"]]
    assert live["records"][0]["eligible"]
    historical = advance(other, revision=2)
    assert [r["audit_id"] for r in historical["records"]] == [initial["historical_high_water"]]
    assert not historical["records"][0]["eligible"]


@pytest.mark.parametrize("raw", ["{", 'null', '{"status":"completed","evidence_gaps":[]}'])
def test_corrupt_persisted_report_aborts(queue, raw):
    store, _, _ = queue
    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET report_json=?", (raw,))
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    with pytest.raises((ValueError, KeyError, TypeError)):
        advance(store)
    assert store.case_preparation_discovery_checkpoint(TARGET) == checkpoint
    assert store.case_preparation_stats()["eligible"] == 0


def test_known_incompatible_renderer_report(queue):
    store, report, _ = queue
    incompatible = dict(report, engine_version="unsupported-engine")
    with store._connection() as conn:
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET report_json=?", (encode(incompatible),))
    store.initialize_case_preparation_discovery(TARGET)
    assert not advance(store)["records"][0]["eligible"]


def test_missing_persisted_investigation_aborts(queue):
    store, _, _ = queue
    with store._connection() as conn:
        conn.execute(
            "INSERT INTO investigation_audit(investigation_id,correlation_id,event,occurred_at) "
            "VALUES('missing','broken','completed','time')",
        )
    checkpoint = store.initialize_case_preparation_discovery(TARGET)
    with pytest.raises(StateError, match="Missing persisted investigation"):
        advance(store)
    assert store.case_preparation_discovery_checkpoint(TARGET) == checkpoint
    assert store.case_preparation_stats()["eligible"] == 0


@pytest.mark.parametrize("state", ["queued", "leased", "retry_wait", "completed", "failed"])
def test_capacity_counts_states_and_replays_existing(queue, state):
    from test_preparation import lease_args

    store, report, payload = queue
    foreign = store.enqueue_case_preparation(
        report["investigation_id"], "https://other.test/default/securitySolution",
    )
    if state != "queued":
        job = store.claim_case_preparation()
        if state == "completed":
            store.complete_case_preparation(*lease_args(job), payload=payload)
        elif state != "leased":
            store.fail_case_preparation(
                *lease_args(job), failure="transient" if state == "retry_wait" else "permanent",
            )
    store.initialize_case_preparation_discovery(TARGET)
    page = advance(store, outstanding_limit=1)
    blocked = state in ("queued", "leased", "retry_wait")
    assert bool(page["records"]) is not blocked
    assert page["checkpoint"]["historical_cursor"] == (0 if blocked else 1)
    if blocked:
        # An independently enqueued identity can be resolved at/above the ceiling.
        local = store.enqueue_case_preparation(report["investigation_id"], TARGET)
        replay = advance(store, revision=1, outstanding_limit=1)
        assert replay["records"][0]["preparation_id"] == local["id"]
        assert store.show_case_preparation(foreign["id"])["state"] == state


@pytest.mark.parametrize("separate", [False, True])
def test_concurrent_discovery_global_capacity(queue, separate):
    from threading import Barrier

    store, _, _ = queue
    targets = [TARGET, "https://other.test/default/securitySolution"]
    for target in targets:
        store.initialize_case_preparation_discovery(target)
    barrier = Barrier(2)

    def admit(target):
        connection = Store(store.path) if separate else store
        barrier.wait()
        return connection.advance_case_preparation_discovery(
            target, lane="historical", expected_revision=0, outstanding_limit=1,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        pages = list(pool.map(admit, targets))
    assert sorted(len(page["records"]) for page in pages) == [0, 1]
    assert store.case_preparation_stats()["state_counts"]["queued"] == 1
    blocked = next(page for page in pages if not page["records"])
    assert blocked["checkpoint"]["historical_cursor"] == 0
    # Free the admitted slot, then resume exactly the blocked record.
    job = store.claim_case_preparation()
    store.fail_case_preparation(job["id"], job["lease_owner"], job["lease_generation"],
                                failure="permanent")
    page = store.advance_case_preparation_discovery(
        blocked["checkpoint"]["target"], lane="historical", expected_revision=1,
        outstanding_limit=1,
    )
    assert len(page["records"]) == 1


def test_capacity_retains_first_unadmitted_record(queue):
    from test_preparation import FIXTURES

    from soc_automation.evidence import FixtureEvidenceProvider
    from soc_automation.service import investigate

    store, report, _ = queue
    store.investigation_failure("between-eligible-records")
    investigate(store, [report["source_alert_ids"][0]],
                FixtureEvidenceProvider(FIXTURES / "evidence"))
    initial = store.initialize_case_preparation_discovery(TARGET)
    for invalid in (0, True, 2001):
        with pytest.raises(ValueError):
            advance(store, outstanding_limit=invalid)
        assert store.case_preparation_discovery_checkpoint(TARGET) == initial
    page = advance(store, outstanding_limit=1)
    assert [record["eligible"] for record in page["records"]] == [True, False]
    assert page["next_cursor"] == page["checkpoint"]["historical_cursor"] == 2
    blocked = advance(store, revision=1, outstanding_limit=1)
    assert blocked["records"] == []
    assert blocked["next_cursor"] == 2
    assert store.case_preparation_stats()["state_counts"]["queued"] == 1
