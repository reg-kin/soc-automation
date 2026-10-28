"""Read-only operator discovery and exact frozen review contracts."""

import copy
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from review_helpers import approve
from test_preparation import TARGET
from test_preparation import queue as preparation_queue

from soc_automation import preparation_coordinator
from soc_automation.cases import render
from soc_automation.cli import main
from soc_automation.state import StateError, Store


@pytest.fixture
def frozen(tmp_path):
    store, report, payload = preparation_queue.__wrapped__(tmp_path)
    store.path = store.path.rename(tmp_path / "soc_automation.db")
    result = preparation_coordinator.run_pass(store, TARGET)
    assert result.completed == 1
    publication = store.list_case_publications()["publications"][0]
    return store, report, payload, publication


def decision(store, publication_id, value):
    if value == "approved":
        approve(store, publication_id)
        return
    with store._connection() as conn:
        conn.execute(
            "INSERT INTO case_review_events(publication_id,request_id,decision,previous_event_id,"
            "payload_sha256,target,report_sha256,renderer_version,review_policy_version,actor_uid,"
            "actor_principal,authentication_method,decided_at) "
            "SELECT p.id,?, ?, (SELECT max(id) FROM case_review_events WHERE publication_id=p.id),"
            "p.payload_sha256,p.target,sha256_text(i.report_json),'soc-case/2','test/1',1000,"
            "'test:operator','os_peer_credentials','2026-01-01T00:00:00Z' "
            "FROM case_publications p JOIN investigations i ON i.id=p.investigation_id "
            "WHERE p.id=?",
            (value + publication_id, value, publication_id),
        )


def test_empty_listing(tmp_path):
    store = Store(tmp_path / "empty.db")
    store.initialize()
    assert store.list_case_publications() == {"publications": [], "next_cursor": None}


def test_heads_filters_and_metadata(frozen):
    store, report, payload, publication = frozen
    assert store.list_case_publications(review_status="approved")["publications"] == []
    assert store.list_case_publications(review_status="unreviewed")["publications"] == [publication]
    for status in ("declined", "approved", "revoked"):
        decision(store, publication["id"], status)
        rows = store.list_case_publications(review_status=status)["publications"]
        assert len(rows) == 1
        assert rows[0]["review_status"] == status
        assert set(rows[0]) == {"id", "investigation_id", "target", "state", "payload_sha256",
                                "created_at", "review_status", "is_current_head"}
    changed = copy.deepcopy(payload)
    changed["tags"] = ["replacement"]
    changed["title"] = "replacement"
    replacement = store.prepare_publication(
        report["investigation_id"], TARGET, changed, revise=True
    )
    assert [p["id"] for p in store.list_case_publications()["publications"]] == [replacement["id"]]
    assert not store.review_case_publication(publication["id"])["is_current_head"]
    assert store.list_case_publications(review_status="revoked")["publications"] == []
    assert store.list_case_publications(target=TARGET)["publications"]
    assert store.list_case_publications(target="https://other.test/default/securitySolution")[
        "publications"] == []


def test_keyset_pagination_and_insertion_ceiling(frozen):
    store, report, payload, publication = frozen
    for number in range(4):
        store.prepare_publication(report["investigation_id"],
                                  f"https://target{number}.test/default/securitySolution", payload)
    expected = store.list_case_publications()["publications"]
    page = store.list_case_publications(limit=2)
    assert page == store.list_case_publications(limit=2)
    store.prepare_publication(report["investigation_id"],
                              "https://later.test/default/securitySolution", payload)
    items = page["publications"]
    while page["next_cursor"]:
        page = store.list_case_publications(limit=1, cursor=page["next_cursor"])
        items += page["publications"]
    assert items == expected
    cursor = store.list_case_publications(limit=1)["next_cursor"]
    for kwargs in ({"review_status": "unreviewed"}, {"target": TARGET}):
        with pytest.raises(ValueError):
            store.list_case_publications(cursor=cursor, **kwargs)
    for cursor in ("garbage", "e30=", "MA==", "" , "a" * 4097):
        with pytest.raises(ValueError):
            store.list_case_publications(cursor=cursor)


def test_exact_snapshot_and_history(frozen):
    store, report, payload, publication = frozen
    for value in ("declined", "approved", "revoked"):
        decision(store, publication["id"], value)
    review = store.review_case_publication(publication["id"])
    with store._connection(readonly=True) as conn:
        raw_payload = conn.execute("SELECT payload_json FROM case_publications").fetchone()[0]
        raw_report = conn.execute("SELECT report_json FROM investigations").fetchone()[0]
    assert review["payload_json"] == raw_payload
    assert review["report_json"] == raw_report
    assert review["payload"] == payload
    assert review["report"] == report
    assert review["payload_sha256"] == hashlib.sha256(raw_payload.encode()).hexdigest()
    assert review["report_sha256"] == hashlib.sha256(raw_report.encode()).hexdigest()
    assert review["payload_sha256_verified"] and review["report_sha256_verified"]
    assert review["report_hash_sources"] == ["preparation", "review"]
    assert review["verification_method"] == "hash_binding"
    assert review["renderer_version"] == "soc-case/2"
    assert review["is_current_head"]
    assert review["review_status"] == "revoked"
    assert [r["decision"] for r in review["review_history"]] == ["declined", "approved", "revoked"]
    assert review["latest_review"] == review["review_history"][-1]
    assert [a["event"] for a in review["audit"]] == ["prepared"]


@pytest.mark.parametrize("artifact", ["payload", "report", "renderer", "review", "audit"])
def test_corruption_rejected(frozen, artifact):
    store, report, payload, publication = frozen
    approve(store, publication["id"])
    with store._connection() as conn:
        triggers = [r[0] for r in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger'"
        )]
        if artifact in {"payload", "renderer"}:
            conn.execute("DROP TRIGGER publication_frozen")
            conn.execute("DROP TRIGGER publication_transition")
            changed = dict(payload, title="tampered")
            if artifact == "renderer":
                changed["description"] = "Case rendering format: other/99\n"
            text = json.dumps(changed)
            conn.execute("UPDATE case_publications SET payload_json=?", (text,))
            if artifact == "renderer":
                conn.execute(
                    "UPDATE case_publications SET payload_sha256=sha256_text(payload_json)"
                )
        elif artifact == "report":
            conn.execute("DROP TRIGGER investigations_no_update")
            changed = dict(report, audit_correlation_id="tampered")
            conn.execute("UPDATE investigations SET report_json=?", (json.dumps(changed),))
        elif artifact == "review":
            conn.execute("DROP TRIGGER review_no_update")
            conn.execute("UPDATE case_review_events SET report_sha256=?", ("a" * 64,))
        else:
            conn.execute("DROP TRIGGER publication_audit_no_update")
            conn.execute("UPDATE case_publication_audit SET event='sending'")
        # Restore schema guards so rejection exercises content verification.
        for sql in triggers:
            name = sql.split()[2]
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (name,)).fetchone() is None:
                conn.execute(sql)
    with pytest.raises(StateError):
        store.review_case_publication(publication["id"])


def test_unbound_manual_report_and_review_provenance(frozen):
    store, report, payload, _ = frozen
    other = store.prepare_publication(report["investigation_id"],
                                      "https://legacy.test/default/securitySolution", payload)
    result = store.review_case_publication(other["id"])
    assert result["verification_method"] == "deterministic_evidence"
    assert result["report_sha256_verified"] is False
    assert result["report_hash_sources"] == []
    assert result["report_sha256"] == hashlib.sha256(result["report_json"].encode()).hexdigest()
    assert result["payload"] == payload
    approve(store, other["id"])
    bound = store.review_case_publication(other["id"])
    assert bound["report_hash_sources"] == ["review"]
    assert bound["verification_method"] == "hash_binding"
    assert bound["report_sha256_verified"] is True


@pytest.mark.parametrize("manual", [False, True])
def test_offline_readonly_no_mutation_and_cli(frozen, monkeypatch, capsys, manual):
    store, report, payload, publication = frozen
    if manual:
        publication = store.prepare_publication(
            report["investigation_id"], "https://manual.test/default/securitySolution", payload
        )
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    monkeypatch.setenv("SOC_KIBANA_URL", "https://EXAMPLE.test:443/")
    before = store.path.read_bytes()
    original = Store._connection
    connections = []

    @contextmanager
    def readonly(self, **kwargs):
        assert kwargs == {"readonly": True}
        connections.append(self)
        with original(self, **kwargs) as conn:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE forbidden(id)")
            yield conn

    with (patch.object(Store, "_connection", readonly),
          patch("soc_automation.cli.KibanaClient", side_effect=AssertionError),
          patch("soc_automation.cli.ElasticsearchProvider", side_effect=AssertionError),
          patch("socket.socket", side_effect=AssertionError),
          patch("soc_automation.cases.render", wraps=render) as renderer):
        assert main(["list-case-publications", "--target=configured", "--limit=1"]) == 0
        assert json.loads(capsys.readouterr().out)["publications"]
        assert main(["review-case-publication", "--publication-id", publication["id"]]) == 0
        raw = capsys.readouterr().out
        assert raw == json.dumps(json.loads(raw), sort_keys=True) + "\n"
    assert renderer.call_count == int(manual)
    assert len(connections) == 2
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("args", [
    ["review-case-publication"], ["review-case-publication", "--limit=1"],
    ["list-case-publications", "--publication-id=x"],
    ["list-case-publications", "--limit=0"], ["list-case-publications", "--limit=1001"],
    ["list-case-publications", "--review-status=unknown"],
    ["review-case-publication", "--publication-id=x", "--cursor=x"],
    ["healthcheck", "--target=configured"], ["prepare-case", "--review-status=approved"],
    ["list-case-publications", "--provider=elasticsearch"],
    ["review-case-publication", "--publication-id=x", "--authorize-case-creation"],
])
def test_cli_validation(args):
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2


def test_safe_failures_and_existing_show(frozen, monkeypatch, capsys):
    store, _, _, publication = frozen
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    assert main(["show-case-publication", "--publication-id", publication["id"]]) == 0
    assert "payload_json" in json.loads(capsys.readouterr().out)
    for args in (["review-case-publication", "--publication-id=missing"],
                 ["list-case-publications", "--cursor=secret"],
                 ["list-case-publications", "--target=https://user:secret@example.test"]):
        assert main(args) == 1
        assert capsys.readouterr().out == ""


@pytest.mark.parametrize("manual", [False, True])
def test_single_transaction_snapshot(frozen, manual):
    store, report, payload, publication = frozen
    if manual:
        publication = store.prepare_publication(
            report["investigation_id"], "https://manual.test/default/securitySolution", payload
        )
    # A concurrent review commit must not enter a snapshot already reading artifacts.
    with sqlite3.connect(store.path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    original = Store._validate_report_evidence

    snapshots = []

    def concurrent(self, conn, report):
        if not snapshots:
            approve(store, publication["id"])
        snapshots.append(conn)
        assert conn is snapshots[0]
        return original(self, conn, report)

    with patch.object(Store, "_validate_report_evidence", concurrent):
        review = store.review_case_publication(publication["id"])
    assert len(snapshots) == (2 if manual else 1)
    assert review["review_history"] == []
    assert review["report_sha256_verified"] is (not manual)
    assert store.review_case_publication(publication["id"])["review_status"] == "approved"


def test_sent_heads_excluded_but_reviewable(frozen):
    store, _, _, publication = frozen
    approve(store, publication["id"])
    assert store.claim_publication(publication["id"], publication["payload_sha256"])
    for state in ("sending", "uncertain", "published"):
        if state == "uncertain":
            store.publication_outcome(publication["id"])
        elif state == "published":
            store.publication_outcome(publication["id"], {"id": "remote", "version": "1"})
        assert store.list_case_publications()["publications"] == []
        review = store.review_case_publication(publication["id"])
        assert review["state"] == state
        assert review["audit"][-1]["event"] == state


@pytest.mark.parametrize("limit", [0, -1, 1001, True, "1"])
def test_store_bounds(frozen, limit):
    with pytest.raises(ValueError):
        frozen[0].list_case_publications(limit=limit)


def test_exact_noncanonical_payload_bytes(frozen):
    store, report, payload, _ = frozen
    # Legacy direct preparation can contain valid JSON with noncanonical whitespace.
    raw = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    target = "https://direct.test/default/securitySolution"
    with store._connection() as conn:
        conn.execute(
            "INSERT INTO case_publications VALUES('direct',?,?,?,?,NULL,'prepared',NULL,NULL,?)",
            (report["investigation_id"], target, raw, digest, "2026-01-01T00:00:00Z"),
        )
        conn.execute("INSERT INTO publication_heads VALUES(?,?,'direct')",
                     (report["investigation_id"], target))
    result = store.review_case_publication("direct")
    assert result["verification_method"] == "deterministic_evidence"
    assert result["report_sha256_verified"] is False
    assert result["payload_json"] == raw
    assert result["payload"] == payload
    assert result["payload_sha256"] == digest


def test_report_whitespace_corruption_is_not_normalized(frozen):
    store, report, _, publication = frozen
    with store._connection() as conn:
        guard = conn.execute("SELECT sql FROM sqlite_master WHERE name='investigations_no_update'"
                             ).fetchone()[0]
        conn.execute("DROP TRIGGER investigations_no_update")
        conn.execute("UPDATE investigations SET report_json=?", (json.dumps(report, indent=2),))
        conn.execute(guard)
    with pytest.raises(StateError):
        store.review_case_publication(publication["id"])


def test_missing_database_not_created(tmp_path, monkeypatch, capsys):
    path = tmp_path / "soc_automation.db"
    monkeypatch.setenv("SOC_DATABASE_PATH", str(path))
    assert main(["list-case-publications"]) == 1
    assert main(["review-case-publication", "--publication-id=missing"]) == 1
    assert capsys.readouterr().out == ""
    assert not path.exists()


@contextmanager
def content_mutation(store):
    """Permit fixture corruption, then restore every schema guard before review."""
    with store._connection() as conn:
        triggers = conn.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
        for name, _ in triggers:
            conn.execute(f'DROP TRIGGER "{name}"')
        yield conn
        for _, sql in triggers:
            conn.execute(sql)


@pytest.mark.parametrize("mutation", [
    "payload", "extra_payload_field", "findings", "missing_evidence",
    "renderer", "ineligible",
])
def test_manual_corruption_rejected(frozen, mutation):
    store, report, payload, _ = frozen
    publication = store.prepare_publication(
        report["investigation_id"], "https://manual.test/default/securitySolution", payload
    )
    with content_mutation(store) as conn:
        if mutation in {"payload", "extra_payload_field", "renderer"}:
            changed = copy.deepcopy(payload)
            if mutation == "renderer":
                changed["description"] = changed["description"].replace("soc-case/2", "other/99")
            elif mutation == "extra_payload_field":
                changed["unexpected"] = True
            else:
                changed["title"] = "tampered"
            raw = json.dumps(changed)
            conn.execute(
                "UPDATE case_publications SET payload_json=?,payload_sha256=? WHERE id=?",
                (raw, hashlib.sha256(raw.encode()).hexdigest(), publication["id"]),
            )
        elif mutation == "missing_evidence":
            conn.execute("DELETE FROM investigation_evidence")
        else:
            changed = copy.deepcopy(report)
            if mutation == "findings":
                changed["observed_facts"][0]["context"]["host.id"] = "invented"
            else:
                changed["status"] = "partial"
            conn.execute("UPDATE investigations SET report_json=?", (json.dumps(changed),))
    with pytest.raises(StateError):
        store.review_case_publication(publication["id"])


@pytest.mark.parametrize("binding", ["preparation", "review"])
def test_corrupt_binding_never_reconstructs(frozen, binding):
    store, _, _, publication = frozen
    if binding == "review":
        approve(store, publication["id"])
    with content_mutation(store) as conn:
        query = ("UPDATE case_preparation_jobs SET report_sha256=?" if binding == "preparation"
                 else "UPDATE case_review_events SET report_sha256=?")
        conn.execute(query, ("0" * 64,))
    with (patch.object(Store, "_preparation_payload", side_effect=AssertionError),
          pytest.raises(StateError)):
        store.review_case_publication(publication["id"])


def test_manual_rendering_failure_closed(frozen):
    store, report, payload, _ = frozen
    publication = store.prepare_publication(
        report["investigation_id"], "https://manual.test/default/securitySolution", payload
    )
    with (patch("soc_automation.cases.render", side_effect=ValueError("render failed")),
          pytest.raises(StateError)):
        store.review_case_publication(publication["id"])
