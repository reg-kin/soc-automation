"""Operational CLI contracts for the bounded offline preparation pass."""

import json
import os
import sqlite3
from dataclasses import asdict
from unittest.mock import patch

import pytest
from test_preparation import TARGET
from test_preparation import queue as preparation_queue

from soc_automation import preparation_coordinator
from soc_automation.cli import main
from soc_automation.state import Store

COMMAND = "run-case-preparation"
DEFAULTS = dict(discovery_limit=100, processing_limit=50, recovery_limit=100, lease_seconds=60)


@pytest.fixture
def configured(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("SOC_"):
            monkeypatch.delenv(key)
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    monkeypatch.setenv("SOC_KIBANA_URL", "https://EXAMPLE.test:443/")
    monkeypatch.setenv("SOC_DATABASE_TIMEOUT_SECONDS", "2")
    return store


@pytest.fixture
def populated(configured, tmp_path):
    directory = tmp_path / "seed"
    directory.mkdir()
    seed, report, payload = preparation_queue.__wrapped__(directory)
    configured.path.write_bytes(seed.path.read_bytes())
    return configured, report, payload


def output(capsys):
    raw = capsys.readouterr().out
    assert len(raw.splitlines()) == 1
    result = json.loads(raw)
    assert set(result) == set(asdict(preparation_coordinator.PassResult()))
    assert raw == json.dumps(result, sort_keys=True) + "\n"
    return result


@pytest.mark.parametrize("custom", [False, True])
def test_invocation_and_empty_pass(configured, capsys, custom):
    limits = dict(discovery_limit=4, processing_limit=3, recovery_limit=2, lease_seconds=7)
    expected = limits if custom else DEFAULTS
    args = [COMMAND]
    if custom:
        for key, value in limits.items():
            args.extend(["--" + key.replace("_", "-"), str(value)])
    with patch.object(preparation_coordinator, "run_pass",
                      wraps=preparation_coordinator.run_pass) as run:
        assert main(args) == 0
    call = run.call_args
    assert call.args[0].path == configured.path
    assert call.args[0].timeout == 2
    assert call.args[1] == TARGET
    assert call.kwargs == expected
    assert output(capsys) == asdict(preparation_coordinator.PassResult())


def test_completed_offline_without_approval_or_publication(populated, capsys):
    store, _, _ = populated
    with (patch("soc_automation.cli.KibanaClient", side_effect=AssertionError),
          patch("soc_automation.cli.ElasticsearchProvider", side_effect=AssertionError),
          patch("socket.socket", side_effect=AssertionError),
          patch.object(Store, "claim_publication", side_effect=AssertionError),
          patch.object(Store, "publication_outcome", side_effect=AssertionError)):
        assert main([COMMAND]) == 0
    result = output(capsys)
    assert result["completed"] == result["claimed"] == 1
    assert result["stopped"] is None
    job = store.show_case_preparation(result["outcomes"][0]["job_id"])
    publication = store.show_case_publication(job["publication_id"])
    assert publication["state"] == "prepared"
    assert publication["approval_sha256"] is None
    assert result["outcomes"] == [{"job_id": job["id"], "status": "completed"}]
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 1


def test_budget_exhaustion_is_success(populated, capsys):
    store, report, _ = populated
    for index in range(2):
        store.enqueue_case_preparation(report["investigation_id"],
                                       f"https://foreign{index}.test/default/securitySolution")
    assert main([COMMAND, "--processing-limit=1", "--discovery-limit=2"]) == 0
    result = output(capsys)
    assert result["discovery_budget_exhausted"]
    assert result["completed"] == 0
    assert result["stopped"] is None


@pytest.mark.parametrize("reason", ["unexpected", "contention", "lease_lost", "ownership_unknown"])
def test_stopped_pass(populated, capsys, reason):
    error = RuntimeError("secret exception content")
    if reason == "contention":
        error = sqlite3.OperationalError("secret exception content")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
    if reason in {"unexpected", "contention"}:
        boundary = patch.object(Store, "recover_case_preparations", side_effect=error)
    else:
        boundary = patch("soc_automation.preparation_coordinator._ownership",
                         return_value=False if reason == "lease_lost" else None)
    with boundary, patch("soc_automation.preparation_coordinator._payload", side_effect=error):
        assert main([COMMAND]) == 1
    result = output(capsys)
    assert result["stopped"] == reason
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("option,values", [
    ("discovery-limit", ["0", "1", "1001"]),
    ("processing-limit", ["0", "-1", "1001"]),
    ("recovery-limit", ["0", "1001"]),
    ("lease-seconds", ["0", "86401"]),
])
def test_invalid_bounds_before_writes(configured, capsys, option, values):
    with patch.object(Store, "recover_case_preparations", side_effect=AssertionError):
        for value in values:
            assert main([COMMAND, f"--{option}={value}"]) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("key,value", [
    ("SOC_KIBANA_URL", None), ("SOC_KIBANA_URL", "http://secret.test"),
    ("SOC_KIBANA_SPACE", "other"), ("SOC_DATABASE_PATH", None),
    ("SOC_DATABASE_TIMEOUT_SECONDS", "0"), ("SOC_CASE_TARGET", TARGET),
])
def test_configuration_failure(configured, monkeypatch, capsys, key, value):
    if value is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, value)
    assert main([COMMAND]) == 1
    assert capsys.readouterr().out == ""


def test_missing_database(configured, capsys):
    configured.path.unlink()
    assert main([COMMAND]) == 1
    assert output(capsys)["stopped"] == "unexpected"
    assert not configured.path.exists()


@pytest.mark.parametrize("option", [
    "--once", "--max-jobs=1", "--job-id=x", "--limit=1", "--max-attempts=1",
    "--retry-seconds=1", "--index=x", "--id=x", "--provider=fixture", "--file=x",
    "--source-id=x", "--alert-id=x", "--evidence-dir=x", "--investigation-id=x",
    "--publication-id=x", "--new-revision", "--approve-payload-sha256=x",
    "--authorize-case-creation", "--policy=x", "--max-input-bytes=1",
    "--max-alert-bytes=1", "--max-batch-size=1", "--discovery-l=2",
    "--processing-limit=abc", "--lease-seconds=1.5",
])
def test_unrelated_or_malformed_options(option):
    with pytest.raises(SystemExit) as error:
        main([COMMAND, option])
    assert error.value.code == 2


@pytest.mark.parametrize("command", ["healthcheck", "prepare-case", "run-investigation-worker"])
@pytest.mark.parametrize("option", ["discovery-limit", "processing-limit", "recovery-limit",
                                    "lease-seconds"])
def test_preparation_options_rejected_elsewhere(command, option):
    with pytest.raises(SystemExit) as error:
        main([command, f"--{option}=2"])
    assert error.value.code == 2


def test_processing_budget_with_outstanding_work(populated, capsys):
    from test_preparation import FIXTURES

    from soc_automation.evidence import FixtureEvidenceProvider
    from soc_automation.service import investigate

    store, report, _ = populated
    store.enqueue_case_preparation(report["investigation_id"], TARGET)
    other = investigate(store, [report["source_alert_ids"][0]],
                        FixtureEvidenceProvider(FIXTURES / "evidence"))
    store.enqueue_case_preparation(other["investigation_id"], TARGET)
    assert main([COMMAND, "--processing-limit=1", "--discovery-limit=2"]) == 0
    result = output(capsys)
    assert result["completed"] == 1
    assert result["processing_budget_exhausted"]
    assert result["stopped"] is None


def test_completion_failure_rolls_back(populated, capsys):
    store, _, _ = populated
    with store._connection() as conn:
        conn.execute("CREATE TRIGGER reject_cli_completion "
                     "BEFORE INSERT ON case_preparation_audit "
                     "WHEN NEW.event='completed' "
                     "BEGIN SELECT RAISE(ABORT,'secret exception content'); END")
    assert main([COMMAND]) == 1
    result = output(capsys)
    assert result["stopped"] == "unexpected"
    assert result["completed"] == 0
    assert "secret" not in json.dumps(result)
    with store._connection(readonly=True) as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 0
