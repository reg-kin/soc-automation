import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from soc_automation.cli import main
from soc_automation.ingestion import InputError, Limits, encode, normalize, parse
from soc_automation.service import ingest
from soc_automation.state import StateError, Store
from soc_automation.triage import Policy, decide

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name="standard"):
    return json.loads((FIXTURES / f"{name}.json").read_text())


@pytest.fixture
def store(tmp_path):
    result = Store(tmp_path / "soc_automation.db")
    result.initialize()
    return result


def send(store, item=None, **kwargs):
    return ingest(store, encode(fixture() if item is None else item).encode(), **kwargs)


def count(store, table):
    with sqlite3.connect(store.path) as connection:
        query = f"SELECT count(*) FROM {table}"  # noqa: S608 -- fixed test table names
        return connection.execute(query).fetchone()[0]


@pytest.mark.parametrize(
    "name", ["standard", "eql", "single_ancestor", "minimal", "approved_test", "high_incomplete"]
)
def test_preservation(store, name):
    item = fixture(name)
    result = send(store, item)[0]
    saved = store.show_alert(result["alert_id"], evidence=True)
    assert saved["original"] == item
    assert saved["normalized"]["source_index"] == item["_index"]
    assert saved["normalized"]["source_alert_id"] == item["_id"]
    assert saved["state"] == "triaged"
    assert saved["normalized"]["ancestors"] == item["_source"].get("kibana.alert.ancestors")
    assert saved["decision"]["validity"] == "VALID"
    assert len(store.audit_records(result["alert_id"])) == 2


def test_missing_and_high_evidence():
    minimal, _ = normalize(fixture("minimal"))
    assert minimal.ancestors is None
    assert minimal.severity is None
    assert all(v is None for v in minimal.entities.values())
    assert decide(minimal)["disposition"] == "MANUAL_REVIEW"
    high, _ = normalize(fixture("high_incomplete"))
    assert decide(high)["disposition"] == "URGENT_INVESTIGATION"
    assert decide(high)["activity"] == "UNKNOWN"


def test_trusted_test_policy():
    item = fixture("approved_test")
    item["_source"]["host"]["name"] = "test-host"
    item["_source"]["trusted_test"] = True
    alert, _ = normalize(item)
    assert decide(alert)["disposition"] == "INVESTIGATE"
    assert (
        decide(alert, Policy(approved_test_rule_ids=(alert.rule_id,)))["disposition"] == "TEST_ONLY"
    )


def test_priority_conflicts_and_override():
    item = fixture()
    item["_source"]["kibana.alert.severity"] = "low"
    item["_source"]["kibana.alert.risk_score"] = 95
    alert, _ = normalize(item)
    assert decide(alert)["priority"] == "P1"
    assert decide(alert, Policy(rule_overrides={alert.rule_id: "P4"}))["priority"] == "P4"
    item["_source"].pop("kibana.alert.risk_score")
    alert, _ = normalize(item)
    assert decide(alert, Policy(asset_priorities={"asset-001": "P2"}))["priority"] == "P2"


@pytest.mark.parametrize(
    "risk,priority", [(0, "P4"), (39.9, "P4"), (40, "P3"), (70, "P2"), (90, "P1"), (100, "P1")]
)
def test_risk_boundaries(risk, priority):
    item = fixture("minimal")
    item["_source"]["kibana.alert.risk_score"] = risk
    assert decide(normalize(item)[0])["priority"] == priority


def test_unwrapped_nested_and_identity(store):
    doc = {
        "@timestamp": "2026-10-01T12:00:00+00:00",
        "kibana": {"alert": {"severity": "high", "rule": {"name": "example", "rule_id": "r1"}}},
    }
    with pytest.raises(InputError):
        send(store, doc)
    result = send(store, doc, source_id="explicit-001")[0]
    assert store.show_alert(result["alert_id"], evidence=True)["normalized"]["rule_id"] == "r1"
    doc["kibana.alert.severity"] = "low"
    with pytest.raises(InputError):
        send(store, doc, source_id="explicit-001")


def test_duplicates_index_scope_and_changed_content(store):
    first = send(store)[0]
    assert send(store, policy=Policy(version="changed"))[0]["decision"] == first["decision"]
    item = fixture()
    item["_source"]["event"]["action"] = "different"
    with pytest.raises(StateError):
        send(store, item)
    assert count(store, "alerts") == 1
    item["_index"] = "another-index"
    assert send(store, item)[0]["alert_id"] != first["alert_id"]


def test_atomic_batch_and_search_response(store):
    batch = [fixture(), fixture("malformed")]
    with pytest.raises(InputError):
        send(store, batch)
    assert count(store, "alerts") == 0
    assert count(store, "ingestion_audit") == 1
    assert len(send(store, {"hits": {"hits": [fixture(), fixture("eql")]}})) == 2


def test_atomic_identity_conflict(store):
    send(store)
    changed = fixture()
    changed["_source"]["kibana.alert.severity"] = "critical"
    with pytest.raises(StateError):
        send(store, [fixture("eql"), changed])
    assert count(store, "alerts") == 1


def test_restart_process_and_concurrency(store):
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda _: send(Store(store.path))[0], range(16)))
    assert len({r["alert_id"] for r in rows}) == 1
    assert count(store, "ingested_alerts") == 1
    script = (
        "from soc_automation.state import Store; from pathlib import Path; import sys; "
        "s=Store(Path(sys.argv[1])); s.healthcheck(); "
        "print(s.show_alert(sys.argv[2])['state'])"
    )
    result = subprocess.run(  # noqa: S603 -- fixed Python program with separate arguments
        [sys.executable, "-c", script, str(store.path), rows[0]["alert_id"]],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "triaged"
    assert send(Store(store.path))[0]["duplicate"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("kibana.alert.severity", []),
        ("kibana.alert.risk_score", True),
        ("kibana.alert.risk_score", 101),
        ("kibana.alert.rule.name", 1),
        ("host", []),
        ("kibana.alert.ancestors", ["invalid"]),
        ("@timestamp", "2026-10-01"),
        ("process.entity_id", {}),
    ],
)
def test_bad_fields(store, key, value):
    item = fixture()
    item["_source"][key] = value
    with pytest.raises(InputError):
        send(store, item)
    assert count(store, "alerts") == 0


@pytest.mark.parametrize(
    "data", [b"null", b"[]", b"[1]", b"{", b'{"a":1,"a":2}', b'{"x":NaN}', b"\xff", b'"unexpected"']
)
def test_unexpected_input(store, data):
    with pytest.raises(InputError):
        ingest(store, data)
    assert count(store, "alerts") == 0


def test_limits(store):
    for limits in (Limits(input_bytes=1), Limits(alert_bytes=1)):
        with pytest.raises(InputError):
            send(store, limits=limits)
    with pytest.raises(InputError):
        send(store, [fixture(), fixture("eql")], limits=Limits(batch_size=1))
    with pytest.raises(InputError):
        parse(b"[" * 1000 + b"]" * 1000)
    with pytest.raises(InputError):
        send(store, limits=Limits(depth=1))


def test_database_failure_rolls_back(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_triage BEFORE INSERT ON ingestion_audit "
            "WHEN NEW.event='triaged' BEGIN SELECT RAISE(ABORT,'failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        send(store)
    for table in ("alerts", "audit_records", "ingested_alerts", "ingestion_audit"):
        assert count(store, table) == 0


def test_migration_from_m1(tmp_path):
    path = tmp_path / "soc_automation.db"
    sql = Path("src/soc_automation/migrations/001_initial.sql").read_text()
    with sqlite3.connect(path) as connection:
        connection.executescript(sql)
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "INSERT INTO alerts VALUES('old','elastic','old-id','corr','registered','now','now')"
        )
    store = Store(path)
    store.initialize()
    store.healthcheck()
    assert store.register_alert("elastic", "old-id")["id"] == "old"
    assert send(store)[0]["decision"]["priority"] == "P3"
    store.initialize()


def test_evidence_and_decisions_immutable(store):
    send(store)
    with sqlite3.connect(store.path) as connection:
        for sql in (
            "UPDATE ingested_alerts SET decision_json='{}'",
            "DELETE FROM ingested_alerts",
            "DELETE FROM ingestion_audit",
            "UPDATE ingestion_audit SET reason='x'",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(sql)


def test_cli_offline_and_redaction(store, monkeypatch, capsys):
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    assert (
        main(
            [
                "ingest",
                "--file",
                str(FIXTURES / "approved_test.json"),
                "--policy",
                str(FIXTURES / "test_policy.json"),
            ]
        )
        == 0
    )
    row = json.loads(capsys.readouterr().out)["alerts"][0]
    assert row["decision"]["disposition"] == "TEST_ONLY"
    for command in ("show-alert", "triage", "triage"):
        assert main([command, "--alert-id", row["alert_id"]]) == 0
        assert json.loads(capsys.readouterr().out)["decision"] == row["decision"]
    assert main(["ingest", "--file", str(FIXTURES / "malformed.json")]) == 1
    assert main(["show-alert", "--alert-id", "unknown"]) == 1
    item = fixture()
    item["_source"]["process"]["command_line"] = "secret-password"
    source = store.path.parent / "input.json"
    source.write_text(encode(item))
    assert main(["ingest", "--file", str(source)]) == 0
    output = capsys.readouterr()
    assert "secret-password" not in output.out + output.err
    assert "example-user" not in output.out


@pytest.mark.parametrize(
    "options",
    [
        {"default_priority": "bad"},
        {"risk_thresholds": [1, 2, 3]},
        {"severity_priorities": {}},
        {"approved_test_rule_ids": "test"},
    ],
)
def test_invalid_policy(options):
    with pytest.raises(ValueError):
        Policy(**options)


def test_critical_asset_and_custom_thresholds():
    alert, _ = normalize(fixture())
    assert decide(alert, Policy(asset_criticality={"asset-001": "critical"}))["priority"] == "P1"
    assert decide(alert, Policy(risk_thresholds=(40, 30, 20)))["priority"] == "P1"


def test_single_ancestor_object_and_unknown_rule_fields():
    item = fixture("single_ancestor")
    ancestor = item["_source"]["kibana.alert.ancestors"][0]
    item["_source"]["kibana.alert.ancestors"] = ancestor
    item["_source"]["kibana.alert.rule.parameters"] = {"language": "eql"}
    alert, original = normalize(item)
    assert alert.ancestors == [ancestor]
    assert json.loads(original) == item
    assert "kibana.alert.rule.parameters" in alert.context["rule"]
    assert decide(alert)["activity"] == "UNKNOWN"


def test_wrapper_explicit_identity_and_batch_ids_rejected(store):
    with pytest.raises(InputError):
        send(store, source_id="conflicting")
    with pytest.raises(InputError):
        send(store, [fixture(), fixture("eql")], source_id="one-id")
    with pytest.raises(InputError):
        send(store, fixture()["_source"], source_id="bad\nidentifier")


def test_v2_migration_failure_preserves_m1(tmp_path, monkeypatch):
    import soc_automation.state as state

    path = tmp_path / "soc_automation.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(Path("src/soc_automation/migrations/001_initial.sql").read_text())
        connection.execute("PRAGMA user_version=1")

    class BrokenMigration:
        def joinpath(self, name):
            assert name == "migrations/002_initial.sql"
            return self

        def read_text(self, encoding):
            return "CREATE TABLE partial(id INTEGER);\nINVALID SQL;\n"

    monkeypatch.setattr(state, "files", lambda _: BrokenMigration())
    with pytest.raises(sqlite3.OperationalError):
        Store(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
        assert (
            connection.execute("SELECT name FROM sqlite_master WHERE name='partial'").fetchone()
            is None
        )


def test_repeated_cli_ingestion(store, monkeypatch, capsys):
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    args = ["ingest", "--file", str(FIXTURES / "standard.json")]
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)["alerts"][0]
    assert main(args) == 0
    repeated = json.loads(capsys.readouterr().out)["alerts"][0]
    assert repeated["duplicate"]
    assert repeated["alert_id"] == first["alert_id"]
    assert repeated["decision"] == first["decision"]
    assert main(args + ["--max-input-bytes", "1"]) == 1


def test_triage_does_not_accept_ignored_policy():
    with pytest.raises(SystemExit) as error:
        main(["triage", "--alert-id", "unused", "--policy", "unused.json"])
    assert error.value.code == 2
