import io
import json
import logging
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from soc_automation.cli import main
from soc_automation.config import ConfigurationError, Settings
from soc_automation.logging import configure_logging
from soc_automation.state import StateError, Store


@pytest.fixture
def store(tmp_path):
    result = Store(tmp_path / "soc_automation.db")
    result.initialize()
    return result


def test_config(tmp_path):
    path = str(tmp_path / "soc_automation.db")
    settings = Settings.from_env({"SOC_DATABASE_PATH": path})
    assert settings.database_path == Path(path)
    assert settings.database_timeout_seconds == 5


def test_missing_database_path_exact_error():
    with pytest.raises(
        ConfigurationError, match="^SOC_DATABASE_PATH must be an absolute file path$"
    ):
        Settings.from_env({})


@pytest.mark.parametrize("mode", ["empty", "database_only", "partial_es", "unknown_es"])
def test_check_config_offline_contract(mode, monkeypatch, tmp_path, capsys):
    for key in list(os.environ):
        if key.startswith("SOC_"):
            monkeypatch.delenv(key)
    path = tmp_path / "soc_automation.db"
    if mode != "empty":
        monkeypatch.setenv("SOC_DATABASE_PATH", str(path))
    if mode == "partial_es":
        monkeypatch.setenv("SOC_ELASTICSEARCH_URL", "https://elastic.invalid")
    if mode == "unknown_es":
        monkeypatch.setenv("SOC_ELASTICSEARCH_UNKNOWN", "invalid")

    def forbidden(*args, **kwargs):
        raise AssertionError("check-config must not open a database or create a provider")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr("soc_automation.cli.ElasticsearchProvider", forbidden)
    success = mode == "database_only"
    assert main(["check-config"]) == (0 if success else 1)
    output = capsys.readouterr()
    assert output.out == ""
    record = json.loads(output.err)
    assert record["event"] == ("config_valid" if success else "command_failed")
    assert record["level"] == ("INFO" if success else "ERROR")
    assert set(record) == {"timestamp", "level", "event"}
    assert not path.exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"SOC_DATABASE_PATH": "relative/soc_automation.db"},
        {"SOC_DATABASE_PATH": "/invalid/wrong.db"},
        {"SOC_LOG_LEVEL": "debug"},
        {"SOC_DATABASE_TIMEOUT_SECONDS": "0"},
        {"SOC_DATABASE_TIMEOUT_SECONDS": "61"},
        {"SOC_DATABASE_TIMEOUT_SECONDS": "1.5"},
        {"SOC_TOKEN": "secret"},
    ],
)
def test_invalid_config(overrides):
    env = {"SOC_DATABASE_PATH": "/invalid/soc_automation.db"} if overrides else {}
    env.update(overrides)
    with pytest.raises(ConfigurationError):
        Settings.from_env(env)


def test_repeat_initialization_and_restart(store):
    alert = store.register_alert("elastic", "123", "correlation-1")
    store.initialize()
    restarted = Store(store.path)
    restarted.healthcheck()
    assert restarted.register_alert("elastic", "123", "other") == alert
    records = restarted.audit_records(alert["id"])
    assert len(records) == 1
    assert records[0]["correlation_id"] == "correlation-1"
    assert records[0]["occurred_at"].endswith("+00:00")


def test_concurrent_registration(store):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: Store(store.path).register_alert("elastic", "123"), range(16))
        )
    assert len({row["id"] for row in results}) == 1
    assert len(store.audit_records(results[0]["id"])) == 1
    assert store.register_alert("another-source", "123")["id"] != results[0]["id"]


def test_lifecycle(store):
    alert = store.register_alert("elastic", "123")
    for state in ("triaged", "investigating", "completed"):
        updated = store.transition(alert["id"], state)
        assert updated["state"] == state
        assert updated["updated_at"] >= alert["created_at"]
    with pytest.raises(StateError):
        store.transition(alert["id"], "investigating")
    assert [row["new_state"] for row in store.audit_records(alert["id"])] == [
        "registered",
        "triaged",
        "investigating",
        "completed",
    ]


@pytest.mark.parametrize("state", ["completed", "registered", "unknown", "investigating"])
def test_invalid_transition_is_atomic(store, state):
    alert = store.register_alert("elastic", "123")
    with pytest.raises(StateError):
        store.transition(alert["id"], state)
    assert len(store.audit_records(alert["id"])) == 1
    assert store.register_alert("elastic", "123")["state"] == "registered"


@pytest.mark.parametrize("initial_steps", [[], ["triaged"], ["triaged", "investigating"]])
def test_fail_closed_terminal_state(store, initial_steps):
    alert = store.register_alert("elastic", "123")
    for state in initial_steps:
        store.transition(alert["id"], state)
    store.transition(alert["id"], "failed")
    with pytest.raises(StateError):
        store.transition(alert["id"], "triaged")


def test_unknown_alert(store):
    with pytest.raises(StateError):
        store.transition("missing", "triaged")


def test_database_enforces_rules(store):
    alert = store.register_alert("elastic", "123")
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE alerts SET state='completed' WHERE id=?", (alert["id"],))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM audit_records")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE audit_records SET correlation_id='changed'")


def test_audit_failure_rolls_back_alert(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_records "
            "BEGIN SELECT RAISE(ABORT, 'test failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.register_alert("elastic", "123")
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def test_newer_schema_rejected(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(StateError):
        store.initialize()
    with pytest.raises(StateError):
        store.healthcheck()


def test_missing_database_not_created(tmp_path):
    path = tmp_path / "soc_automation.db"
    with pytest.raises(sqlite3.OperationalError):
        Store(path).healthcheck()
    assert not path.exists()


@pytest.mark.parametrize("command", ["init-db", "healthcheck"])
def test_database_commands_reject_partial_es_config(command, monkeypatch, tmp_path, capsys):
    for key in list(os.environ):
        if key.startswith("SOC_"):
            monkeypatch.delenv(key)
    path = tmp_path / "soc_automation.db"
    monkeypatch.setenv("SOC_DATABASE_PATH", str(path))
    monkeypatch.setenv("SOC_ELASTICSEARCH_URL", "https://elastic.invalid")

    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid configuration must fail before opening a database")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    assert main([command]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["event"] == "command_failed"
    assert not path.exists()


def test_logs_never_emit_untrusted_content():
    output = io.StringIO()
    logger = configure_logging("DEBUG", output)
    logger.info("Authorization: Bearer credential", extra={"password": "credential"})
    logger.info("config_valid", "credential")
    try:
        raise ValueError("credential")
    except ValueError:
        logger.exception("credential")
    logger.handle(
        logging.LogRecord(
            "credential", logging.INFO, "credential", 1, {"token": "credential"}, (), None
        )
    )
    assert "credential" not in output.getvalue()
    records = [json.loads(line) for line in output.getvalue().splitlines()]
    assert records[0]["event"] == "redacted"
    assert records[1]["event"] == "config_valid"
    assert all(set(record) == {"timestamp", "level", "event"} for record in records)


def test_cli(monkeypatch, tmp_path, capsys):
    for key in list(os.environ):
        if key.startswith("SOC_"):
            monkeypatch.delenv(key)
    assert main(["check-config"]) == 1
    path = tmp_path / "soc_automation.db"
    monkeypatch.setenv("SOC_DATABASE_PATH", str(path))
    assert main(["check-config"]) == 0
    assert not path.exists()
    assert main(["healthcheck"]) == 1
    assert main(["init-db"]) == 0
    assert main(["init-db"]) == 0
    assert main(["healthcheck"]) == 0
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.value.code == 0
    assert "check-config" in capsys.readouterr().out


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    import soc_automation.state as state

    class BrokenMigration:
        def joinpath(self, name):
            return self

        def read_text(self, encoding):
            return "CREATE TABLE partial (id INTEGER);\nINVALID SQL;\n"

    monkeypatch.setattr(state, "files", lambda _: BrokenMigration())
    store = Store(tmp_path / "soc_automation.db")
    with pytest.raises(sqlite3.OperationalError):
        store.initialize()
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT name FROM sqlite_master").fetchall() == []


def test_missing_schema_objects_rejected(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER audit_transition")
    with pytest.raises(StateError):
        store.healthcheck()
    with pytest.raises(StateError):
        store.register_alert("elastic", "123")


@pytest.mark.parametrize("identifier", ["", "  ", "bad\nidentifier", "x" * 513])
def test_invalid_identifiers_rejected(store, identifier):
    with pytest.raises(ValueError):
        store.register_alert("elastic", identifier)
