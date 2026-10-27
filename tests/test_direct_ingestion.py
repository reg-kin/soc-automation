"""Direct ingestion regressions with synthetic transport and isolated SQLite."""

import json
import sqlite3
from uuid import UUID

import pytest
from test_elasticsearch import KEY, response, source

from soc_automation.cli import main
from soc_automation.state import Store

pytest_plugins = ["test_elasticsearch"]


@pytest.fixture
def local(settings, transport, tmp_path, monkeypatch):
    for key, value in {
        "URL": settings.url,
        "API_KEY": KEY,
        "ALERT_INDICES": "synthetic-alerts",
        "SOURCE_INDICES": "synthetic-events",
        "BACKOFF": "0",
    }.items():
        monkeypatch.setenv("SOC_ELASTICSEARCH_" + key, value)
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    return store


def arguments(index="synthetic-alerts"):
    return ["ingest", "--provider", "elasticsearch", "--index", index, "--id", "0"]


def counts(store):
    with store._connection() as connection:
        return [
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
            for table in ("alerts", "ingested_alerts", "audit_records")
        ]


def test_success_duplicate_conflict_and_investigation(local, transport, capsys):
    item = source("synthetic-alerts")
    item["_source"]["kibana.alert.ancestors"] = [
        {"index": "synthetic-events", "id": "0", "type": "event", "depth": 0}
    ]
    response(transport, item)
    assert main(arguments()) == 0
    row = json.loads(capsys.readouterr().out)["alerts"][0]
    identifier = row["alert_id"]
    assert str(UUID(identifier)) == identifier
    assert row["duplicate"] is False
    saved = local.show_alert(identifier, evidence=True)
    assert saved["original"] == item
    assert saved["normalized"]["source_index"] == "synthetic-alerts"
    assert saved["normalized"]["source_alert_id"] == "0"
    before = counts(local)
    assert main(arguments()) == 0
    duplicate = json.loads(capsys.readouterr().out)["alerts"][0]
    assert duplicate == {**row, "duplicate": True}
    assert counts(local) == before
    item["_source"]["event.action"] = "changed"
    response(transport, item)
    assert main(arguments()) == 1
    assert capsys.readouterr().out == ""
    assert counts(local) == before
    response(transport, source())
    assert main(["investigate", "--provider", "elasticsearch", "--alert-id", identifier]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["source_alert_ids"] == [identifier]
    assert report["retrieved_evidence"][0]["status"] == "found"
    assert transport.return_value.request.call_args.args == ("GET", "/synthetic-events/_doc/0")


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--file", "unused", "--provider", "fixture"],
        ["--index", "synthetic-alerts", "--id", "0"],
        ["--provider", "elasticsearch"],
        ["--provider", "elasticsearch", "--index", "synthetic-alerts"],
        ["--provider", "elasticsearch", "--id", "0"],
        arguments()[1:] + ["--file", "unused"],
        arguments()[1:] + ["--source-id", "override"],
        ["--file", "unused", "--index", "synthetic-alerts"],
        ["--file", "unused", "--id", "0"],
    ],
)
def test_invalid_arguments(args, transport):
    with pytest.raises(SystemExit) as error:
        main(["ingest", *args])
    assert error.value.code == 2
    transport.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    ["forbidden", "malformed", "missing", "transport", "input_limit", "alert_limit", "persistence"],
)
def test_failures(local, transport, capsys, failure):
    item = source("synthetic-alerts")
    args = arguments("forbidden" if failure == "forbidden" else "synthetic-alerts")
    if failure == "malformed":
        item["_source"].pop("@timestamp")
    response(transport, item, status=404 if failure == "missing" else 200)
    if failure == "transport":
        transport.return_value.connect.side_effect = ConnectionError("synthetic failure")
    if failure in {"input_limit", "alert_limit"}:
        args += ["--max-input-bytes" if failure == "input_limit" else "--max-alert-bytes", "1"]
    if failure == "persistence":
        with sqlite3.connect(local.path) as connection:
            connection.execute(
                "CREATE TRIGGER reject_triage BEFORE INSERT ON ingestion_audit "
                "WHEN NEW.event='triaged' BEGIN SELECT RAISE(ABORT,'failure'); END"
            )
    assert main(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert KEY not in output.err
    assert counts(local) == [0, 0, 0]
    if failure == "forbidden":
        transport.assert_not_called()
    if failure == "transport":
        assert transport.return_value.connect.call_count == 3
