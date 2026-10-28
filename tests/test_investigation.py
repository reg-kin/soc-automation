"""Synthetic offline investigation contracts, with networking blocked by conftest."""

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from unittest.mock import Mock

import pytest

from soc_automation.cli import main
from soc_automation.evidence import FixtureEvidenceProvider, Reference, Retrieval
from soc_automation.ingestion import InputError, encode
from soc_automation.investigation import build
from soc_automation.service import ingest, investigate
from soc_automation.state import StateError, Store

FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    directory = tmp_path / "evidence"
    shutil.copytree(FIXTURES / "evidence", directory)
    provider = FixtureEvidenceProvider(directory)
    ids = [r["alert_id"] for r in ingest(store, (FIXTURES / "stages.json").read_bytes())]
    return store, provider, ids


def test_stages_repeat_restart_and_audit(setup):
    store, provider, ids = setup
    report = investigate(store, ids[::-1], provider)
    assert len(report["timeline"]) == 3
    assert report["timeline"][0]["context"]["event.action"] == "authentication"
    assert report["status"] == "completed"
    assert len(report["supported_inferences"]) == 2
    assert all(not r["causation_established"] for r in report["supported_inferences"])
    assert investigate(Store(store.path), ids + ids, provider) == report
    assert Store(store.path).show_investigation(report["investigation_id"]) == report
    with store._connection() as conn:
        assert conn.execute("SELECT count(*) FROM investigations").fetchone()[0] == 1
        assert [r[0] for r in conn.execute("SELECT event FROM investigation_audit")] == [
            "completed",
            "duplicate",
        ]
    assert store.show_alert(ids[0])["state"] == "investigating"


def test_partial_and_unlinked(setup):
    store, provider, _ = setup
    identifier = ingest(store, (FIXTURES / "partial.json").read_bytes())[0]["alert_id"]
    report = investigate(store, [identifier], provider)
    assert report["status"] == "partial"
    assert len(report["evidence_references"]) == 8
    assert len(report["retrieved_evidence"]) == 7
    assert len(report["timeline"]) == 3
    assert report["timeline"][0]["reference"]["id"] == "5"
    assert len(report["evidence_gaps"]) == 4
    assert all("5" not in [x["id"] for x in r["evidence"]] for r in report["supported_inferences"])


def test_conflict_preserves_previous(setup):
    store, provider, ids = setup
    original = investigate(store, ids, provider)
    target = provider.directory / provider.filename(Reference("synthetic-events", "0"))
    target.write_bytes((FIXTURES / "conflict.json").read_bytes())
    with pytest.raises(StateError):
        investigate(store, ids, provider)
    with pytest.raises(StateError):
        investigate(store, [ids[0]], provider)
    assert store.show_investigation(original["investigation_id"]) == original
    with store._connection() as conn:
        assert conn.execute("SELECT count(*) FROM investigations").fetchone()[0] == 1
        assert (
            conn.execute(
                "SELECT count(*) FROM investigation_audit WHERE event='failed'"
            ).fetchone()[0]
            == 2
        )


def test_provider(setup):
    _, provider, _ = setup
    assert provider.retrieve(Reference("synthetic-events", "0")).status == "found"
    assert provider.retrieve(Reference("synthetic-events", "missing")).status == "missing"
    assert provider.retrieve(Reference("synthetic-events", "wrong")).status == "failed"
    ref = Reference("synthetic-events", "bad")
    path = provider.directory / provider.filename(ref)
    for data in [b"{", b"x" * 262_145, b'{"a":1,"a":2}']:
        path.write_bytes(data)
        assert provider.retrieve(ref).status == "failed"
    path.unlink()
    path.symlink_to(provider.directory / provider.filename(Reference("synthetic-events", "0")))
    assert provider.retrieve(ref).status == "failed"
    for refs in [[], [ref] * 101]:
        with pytest.raises(InputError):
            provider.retrieve_many(refs)


@pytest.mark.parametrize(
    "index,identifier",
    [("../x", "a"), ("*", "a"), ("a", ".."), ("a", ""), (None, "x"), ("a", "x\n")],
)
def test_invalid_references(index, identifier):
    with pytest.raises(InputError):
        Reference(index, identifier)


def test_invalid_selection_and_provider(setup):
    store, provider, ids = setup
    for selection in [[], None, ["x"] * 101, [3], ["unknown"]]:
        with pytest.raises((InputError, StateError)):
            investigate(store, selection, provider)

    class WrongProvider:
        def retrieve_many(self, refs):
            return [Retrieval(Reference("wrong", "wrong"), "missing") for _ in refs]

    with pytest.raises(InputError):
        investigate(store, ids, WrongProvider())


def test_transaction_rollback(setup):
    store, provider, ids = setup
    with store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER reject_report BEFORE INSERT ON investigations "
            "BEGIN SELECT RAISE(ABORT,'synthetic failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        investigate(store, ids, provider)
    with store._connection() as conn:
        assert conn.execute("SELECT count(*) FROM investigation_evidence").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM investigations").fetchone()[0] == 0
        assert conn.execute("SELECT event FROM investigation_audit").fetchone()[0] == "failed"
    assert store.show_alert(ids[0])["state"] == "triaged"


def test_cli(setup, monkeypatch, capsys):
    store, provider, ids = setup
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    args = ["investigate", "--evidence-dir", str(provider.directory)]
    for identifier in ids:
        args.extend(["--alert-id", identifier])
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert main(["show-investigation", "--investigation-id", report["investigation_id"]]) == 0
    assert json.loads(capsys.readouterr().out) == report


def test_reference_limit_and_no_ancestors(setup):
    store, provider, _ = setup
    document = json.loads((FIXTURES / "stages.json").read_text())[0]
    document["_id"] = "empty"
    document["_source"].pop("kibana.alert.ancestors")
    identifier = ingest(store, json.dumps(document).encode())[0]["alert_id"]
    assert investigate(store, [identifier], provider)["status"] == "partial"
    document["_id"] = "large"
    document["_source"]["kibana.alert.ancestors"] = [{"index": "x", "id": "y"}] * 101
    identifier = ingest(store, json.dumps(document).encode())[0]["alert_id"]
    with pytest.raises(InputError):
        investigate(store, [identifier], provider)


def test_changed_availability_and_immutable_tables(setup):
    store, provider, ids = setup
    report = investigate(store, ids, provider)
    target = provider.directory / provider.filename(Reference("synthetic-events", "0"))
    target.unlink()
    with pytest.raises(StateError):
        investigate(store, ids, provider)
    assert store.show_investigation(report["investigation_id"]) == report
    for table in [
        "investigations",
        "investigation_alerts",
        "investigation_evidence",
        "investigation_references",
        "investigation_audit",
    ]:
        with pytest.raises(sqlite3.IntegrityError), store._connection() as conn:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 -- fixed local table allowlist


def test_migrate_version_two_preserves_evidence(tmp_path):
    from importlib.resources import files

    path = tmp_path / "soc_automation.db"
    with sqlite3.connect(path) as conn:
        for number in (1, 2):
            conn.executescript(
                files("soc_automation").joinpath(f"migrations/{number:03d}_initial.sql").read_text()
            )
        conn.execute("PRAGMA user_version=2")
        conn.execute(
            "INSERT INTO alerts VALUES('legacy','source','document','audit',"
            "'registered','time','time')"
        )
    store = Store(path)
    store.initialize()
    store.healthcheck()
    with store._connection() as conn:
        assert (
            conn.execute("SELECT state FROM alerts WHERE id='legacy'").fetchone()[0] == "registered"
        )
        assert conn.execute("SELECT count(*) FROM audit_records").fetchone()[0] == 1
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 9


@pytest.mark.parametrize("dotted", [False, True])
@pytest.mark.parametrize(
    "value", [0, -1, 1001, 2**80, " user-001 ", None, 1.0, 0.5, True, False, [], [1], {}, "", " "]
)
def test_user_id_context_compatibility(dotted, value):
    reference = Reference("synthetic-events", "numeric-user")
    source = {"@timestamp": "2026-01-01T00:00:00Z"}
    source.update({"user.id": value} if dotted else {"user": {"id": value}})
    document = {"_index": reference.index, "_id": reference.id, "_source": source}
    provider = Mock()
    provider.retrieve_many.return_value = [Retrieval(reference, "found", document)]
    alerts = [
        {
            "alert_id": "synthetic-alert",
            "normalized": {"ancestors": [{"index": reference.index, "id": reference.id}]},
        }
    ]
    report = build(alerts, provider)
    valid = value is None or type(value) is int or (isinstance(value, str) and bool(value.strip()))
    assert report["status"] == ("completed" if valid else "partial")
    evidence = report["retrieved_evidence"][0]
    assert evidence["document"] == document
    assert evidence["sha256"] == hashlib.sha256(encode(document).encode()).hexdigest()
    if valid:
        for event in report["timeline"] + report["observed_facts"]:
            assert event["context"]["user.id"] == value
            assert type(event["context"]["user.id"]) is type(value)
    else:
        assert report["timeline"] == report["observed_facts"] == []
        assert report["evidence_gaps"][0]["reason"] == "invalid_context_or_timestamp"


@pytest.mark.parametrize(
    "left,right,associated",
    [
        (1001, 1001, True),
        (1001, "1001", False),
        (0, 0, True),
        (0, "0", False),
        ("0", 0, False),
        (0, None, False),
        (None, None, False),
        (-1, -1, True),
        ("user-1", "user-1", True),
        (0, False, False),
        (False, 0, False),
        (0, 0.0, False),
        (True, True, False),
        ([], [], False),
        ("", "", False),
    ],
)
def test_numeric_user_id_correlation_semantics(left, right, associated):
    references = [Reference("synthetic-events", str(i)) for i in range(2)]
    provider = Mock()
    provider.retrieve_many.return_value = [
        Retrieval(
            ref,
            "found",
            {
                "_index": ref.index,
                "_id": ref.id,
                "_source": {"@timestamp": "2026-01-01T00:00:00Z", "user.id": value},
            },
        )
        for ref, value in zip(references, (left, right), strict=True)
    ]
    alerts = [
        {
            "alert_id": "synthetic-alert",
            "normalized": {"ancestors": [{"index": ref.index, "id": ref.id} for ref in references]},
        }
    ]
    report = build(alerts, provider)
    valid = all(
        value is None or type(value) is int or (isinstance(value, str) and bool(value.strip()))
        for value in (left, right)
    )
    assert report["status"] == ("completed" if valid else "partial")
    assert bool(report["supported_inferences"]) is associated
    if associated:
        assert report["supported_inferences"][0]["shared_fields"] == ["user.id"]


@pytest.mark.parametrize(
    "key", ["host.id", "session.id", "process.entity_id", "process.parent.entity_id"]
)
def test_other_context_identifiers_still_reject_integers(key):
    ref = Reference("synthetic-events", "other-id")
    provider = Mock()
    provider.retrieve_many.return_value = [
        Retrieval(
            ref,
            "found",
            {
                "_index": ref.index,
                "_id": ref.id,
                "_source": {"@timestamp": "2026-01-01T00:00:00Z", key: 1001},
            },
        )
    ]
    report = build(
        [
            {
                "alert_id": "synthetic-alert",
                "normalized": {"ancestors": [{"index": ref.index, "id": ref.id}]},
            }
        ],
        provider,
    )
    assert report["status"] == "partial"
    assert report["observed_facts"] == []
