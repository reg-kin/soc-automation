"""Stage C contracts; every HTTP request uses a mock, sockets are forbidden."""

import base64
import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from review_helpers import LegacyClaimStore as Store

from soc_automation.cases import render
from soc_automation.config import ConfigurationError, KibanaSettings, Settings
from soc_automation.evidence import FixtureEvidenceProvider
from soc_automation.kibana import KibanaClient, KibanaError
from soc_automation.service import ingest, investigate, prepare_case, publish_case, reconcile_case
from soc_automation.state import StateError

FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.fixture
def prepared(tmp_path):
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    ids = [r["alert_id"] for r in ingest(store, (FIXTURES / "stages.json").read_bytes())]
    report = investigate(store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
    settings = KibanaSettings("https://kibana.example.test", base64.b64encode(b"id:key").decode())
    row = prepare_case(store, report["investigation_id"], settings)
    payload = json.loads(row["payload_json"])
    client = SimpleNamespace(
        settings=settings,
        create=Mock(
            return_value={
                **payload,
                "id": "case-123",
                "version": "v1",
            }
        ),
        find=Mock(),
        get=Mock(),
    )
    from review_helpers import approve

    approve(store, row["id"])
    return store, report, row, client


def publish(prepared, **kwargs):
    store, _, row, client = prepared
    return publish_case(
        store, row["id"], client, approval_hash=row["payload_sha256"], authorized=True, **kwargs
    )


def test_render_and_idempotence(prepared):
    store, report, row, client = prepared
    assert prepare_case(store, report["investigation_id"], client.settings) == row
    payload = json.loads(row["payload_json"])
    assert payload["owner"] == "securitySolution"
    assert payload["settings"] == {"syncAlerts": False}
    assert "_source" not in payload["description"]
    assert "association_only" in payload["description"]
    assert publish(prepared)["state"] == "published"
    assert publish(prepared)["state"] == "published"
    client.create.assert_called_once()
    assert [a["event"] for a in store.show_case_publication(row["id"])["audit"]] == [
        "prepared",
        "sending",
        "published",
    ]


@pytest.mark.parametrize("mutation", ["status", "hash", "identity", "fact", "cause", "gap"])
def test_evidence_validation(prepared, mutation):
    store, report, _, _ = prepared
    alerts = [store.show_alert(i, evidence=True) for i in report["source_alert_ids"]]
    report = copy.deepcopy(report)
    if mutation == "status":
        report["status"] = "partial"
    elif mutation == "hash":
        report["retrieved_evidence"][0]["sha256"] = "0" * 64
    elif mutation == "identity":
        report["retrieved_evidence"][0]["document"]["_id"] = "wrong"
    elif mutation == "fact":
        report["observed_facts"][0]["context"]["host.id"] = "invented"
    elif mutation == "cause":
        report["supported_inferences"][0]["causation_established"] = True
    else:
        report["evidence_gaps"] = ["missing"]
    with pytest.raises(ValueError):
        render(report, alerts)


@pytest.mark.parametrize("authorized,approval", [(False, None), (True, "0" * 64), (True, None)])
def test_authorization(prepared, authorized, approval):
    store, _, row, client = prepared
    with pytest.raises(StateError):
        publish_case(store, row["id"], client, authorized=authorized, approval_hash=approval)
    client.create.assert_not_called()
    assert store.show_case_publication(row["id"])["state"] == "prepared"


def test_concurrent_claim(prepared):
    def attempt(_):
        try:
            return publish(prepared)["state"]
        except StateError:
            return "claimed"

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert "published" in results
    prepared[3].create.assert_called_once()


@pytest.mark.parametrize("count", [0, 1, 2])
def test_uncertain_reconciliation(prepared, count):
    store, _, row, client = prepared
    receipt = client.create.return_value

    def timeout(payload):
        # A separate writer succeeds during the HTTP operation: no transaction held.
        store.healthcheck()
        raise TimeoutError

    client.create.side_effect = timeout
    with pytest.raises(StateError):
        publish(prepared)
    with pytest.raises(StateError):
        publish(prepared)
    client.create.assert_called_once()
    client.find.return_value = {"total": count, "cases": [{"id": "case-123"}] * count}
    client.get.return_value = receipt
    if count == 1:
        assert reconcile_case(store, row["id"], client)["state"] == "published"
    else:
        with pytest.raises(StateError):
            reconcile_case(store, row["id"], client)
        assert store.show_case_publication(row["id"])["state"] == "uncertain"


def test_receipt_mismatch_and_crash(prepared):
    store, _, row, client = prepared
    assert store.claim_publication(row["id"], row["payload_sha256"])
    with pytest.raises(StateError):
        publish(prepared)
    client.find.return_value = {"total": 1, "cases": [{"id": "case-123"}]}
    client.get.return_value = {**client.create.return_value, "owner": "cases"}
    with pytest.raises(StateError):
        reconcile_case(store, row["id"], client)
    client.create.assert_not_called()


def test_sql_guards_and_receipt_rollback(prepared):
    store, _, row, _ = prepared
    assert store.claim_publication(row["id"], row["payload_sha256"])
    with store._connection() as conn:
        conn.execute(
            "CREATE TRIGGER reject_receipt BEFORE INSERT ON case_publication_audit "
            "WHEN NEW.event='published' BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.publication_outcome(row["id"], {"id": "case-123", "version": "v1"})
    assert store.show_case_publication(row["id"])["state"] == "sending"
    for sql in [
        "DELETE FROM case_publications",
        "DELETE FROM case_publication_audit",
        "UPDATE case_publications SET state='prepared'",
        "UPDATE case_publications SET payload_json='{}'",
    ]:
        with pytest.raises(sqlite3.IntegrityError), store._connection() as conn:
            conn.execute(sql)


@pytest.mark.parametrize("status", [200, 302, 401, 403, 500])
def test_transport(prepared, status):
    settings = prepared[3].settings
    with patch("soc_automation.kibana.http.client.HTTPSConnection") as transport:
        connection = transport.return_value
        response = connection.getresponse.return_value
        response.status = status
        response.getheader.return_value = "identity"
        response.read.return_value = b'{"id":"case-123"}'
        client = KibanaClient(settings)
        assert client.context.check_hostname
        assert client.context.verify_mode == 2
        if status == 200:
            assert client.create({"title": "test"})["id"] == "case-123"
            client.find("soc-publication-" + "a" * 64)
            client.get("case-123")
        else:
            with pytest.raises(KibanaError):
                client.create({"title": "test"})
            assert connection.request.call_count == 1
        headers = connection.request.call_args.kwargs["headers"]
        assert headers["Authorization"] == "ApiKey " + settings.api_key
        assert headers["kbn-xsrf"]
        for identifier in ["../x", "x?y", "https://evil", "x\n"]:
            with pytest.raises(KibanaError):
                client.get(identifier)


@pytest.mark.parametrize(
    "change",
    [
        {"url": "http://bad"},
        {"url": "https://a/path"},
        {"api_key": "secret\n"},
        {"space": "other"},
        {"read_timeout": 0},
        {"max_response_bytes": 0},
    ],
)
def test_configuration(prepared, change):
    values = {"url": prepared[3].settings.url, "api_key": prepared[3].settings.api_key}
    with pytest.raises(ConfigurationError):
        KibanaSettings(**(values | change))
    assert values["api_key"] not in repr(prepared[3].settings)
    with pytest.raises(ConfigurationError):
        Settings.from_env({"SOC_DATABASE_PATH": str(prepared[0].path), "SOC_KIBANA_BAD": "x"})


def test_limits_and_alert_integrity(prepared):
    store, report, _, _ = prepared
    alerts = [store.show_alert(i, evidence=True) for i in report["source_alert_ids"]]
    alerts[0]["original_ref"] = "0" * 64
    with pytest.raises(ValueError):
        render(report, alerts)
    alerts = [store.show_alert(i, evidence=True) for i in report["source_alert_ids"]]
    report = copy.deepcopy(report)
    report["audit_correlation_id"] = "x" * 30000
    with pytest.raises(ValueError):
        render(report, alerts)


def test_transport_failures(prepared):
    with patch("soc_automation.kibana.http.client.HTTPSConnection") as transport:
        client = KibanaClient(prepared[3].settings)
        conn = transport.return_value
        conn.connect.side_effect = TimeoutError
        with pytest.raises(KibanaError):
            client.create({"title": "test"})
        assert conn.connect.call_count == 1
        conn.connect.side_effect = None
        response = conn.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "identity"
        for data in [b"x" * (client.settings.max_response_bytes + 1), b"{", b'{"a":1,"a":2}']:
            response.read.return_value = data
            with pytest.raises(KibanaError):
                client.create({"title": "test"})
        response.getheader.return_value = "gzip"
        with pytest.raises(KibanaError):
            client.get("case-123")


def test_cli_workflow(prepared, monkeypatch, capsys):
    from soc_automation.cli import main

    store, report, row, client = prepared
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    monkeypatch.setenv("SOC_KIBANA_URL", client.settings.url)
    monkeypatch.setenv("SOC_KIBANA_API_KEY", client.settings.api_key)
    assert main(["prepare-case", "--investigation-id", report["investigation_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["payload_sha256"] == row["payload_sha256"]
    assert main(["show-case-publication", "--publication-id", row["id"]]) == 0
    capsys.readouterr()
    with patch("soc_automation.cli.KibanaClient", return_value=client):
        args = [
            "publish-case",
            "--publication-id",
            row["id"],
            "--approve-payload-sha256",
            row["payload_sha256"],
        ]
        assert main(args) == 1
        client.create.assert_not_called()
        # Missing protected active policy fails closed.
        assert main([*args, "--authorize-case-creation"]) == 1
        client.create.assert_not_called()
        capsys.readouterr()
        assert main(["reconcile-case", "--publication-id", row["id"]]) == 1


def test_migration_rollback(tmp_path):
    from importlib.resources import files

    path = tmp_path / "soc_automation.db"
    with sqlite3.connect(path) as conn:
        for number in (1, 2, 3):
            conn.executescript(
                files("soc_automation").joinpath(f"migrations/{number:03d}_initial.sql").read_text()
            )
        conn.execute("PRAGMA user_version=3")
        # Force failure after the new tables have been created.
        conn.execute(
            "CREATE TRIGGER publication_transition BEFORE UPDATE ON alerts "
            "BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.OperationalError):
        Store(path).initialize()
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            conn.execute("SELECT name FROM sqlite_master WHERE name='case_publications'").fetchone()
            is None
        )
        conn.execute("DROP TRIGGER publication_transition")
    Store(path).initialize()
    Store(path).healthcheck()


@pytest.mark.parametrize(
    "priority,severity", [("P1", "critical"), ("P2", "high"), ("P3", "medium"), ("P4", "low")]
)
def test_stored_priority_mapping(prepared, priority, severity):
    store, report, _, _ = prepared
    alerts = [store.show_alert(i, evidence=True) for i in report["source_alert_ids"]]
    for alert in alerts:
        alert["decision"]["priority"] = priority
    assert render(report, alerts)["severity"] == severity


def test_target_normalization(prepared):
    key = prepared[3].settings.api_key
    assert (
        KibanaSettings("https://KIBANA.example.test:443/", key).target
        == prepared[3].settings.target
    )


@pytest.mark.parametrize("space", [None, "default"])
def test_prepare_cli_without_credentials(prepared, monkeypatch, capsys, space):
    from soc_automation.cli import main

    store, report, row, _ = prepared
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    monkeypatch.setenv("SOC_KIBANA_URL", "https://KIBANA.example.test:443/")
    monkeypatch.delenv("SOC_KIBANA_API_KEY", raising=False)
    monkeypatch.delenv("SOC_KIBANA_SPACE", raising=False)
    if space is not None:
        monkeypatch.setenv("SOC_KIBANA_SPACE", space)
    with (
        patch("soc_automation.cli.KibanaClient") as client,
        patch("socket.socket") as socket,
        patch("http.client.HTTPSConnection") as transport,
    ):
        assert main(["prepare-case", "--investigation-id", report["investigation_id"]]) == 0
        assert json.loads(capsys.readouterr().out) == row
        client.assert_not_called()
        socket.assert_not_called()
        transport.assert_not_called()


@pytest.mark.parametrize("command", ["publish-case", "reconcile-case"])
@pytest.mark.parametrize("key", [None, "", "invalid"])
def test_publication_cli_requires_credentials(prepared, monkeypatch, command, key):
    from soc_automation.cli import main

    store, _, row, client = prepared
    monkeypatch.setenv("SOC_DATABASE_PATH", str(store.path))
    monkeypatch.setenv("SOC_KIBANA_URL", client.settings.url)
    monkeypatch.delenv("SOC_KIBANA_API_KEY", raising=False)
    if key is not None:
        monkeypatch.setenv("SOC_KIBANA_API_KEY", key)
    with patch("soc_automation.cli.KibanaClient") as constructor:
        assert main([command, "--publication-id", row["id"]]) == 1
        constructor.assert_not_called()


@pytest.mark.parametrize(
    "override",
    [
        {"SOC_KIBANA_SPACE_ID": "default"},
        {"SOC_KIBANA_SPACE": ""},
        {"SOC_KIBANA_SPACE": "other"},
        {"SOC_KIBANA_SPACE": "../default"},
        *(
            {"SOC_KIBANA_URL": url}
            for url in [
                "http://example.test",
                "https://user:pass@example.test",
                "https://example.test/path",
                "https://example.test?x=1",
                "https://example.test#x",
                "https://example.test:0",
                "https://example.test:bad",
                "https://example.test/../",
                "https://example.test\\x",
                "https://example.test\n",
                "https://",
                "",
            ]
        ),
    ],
)
def test_target_configuration_rejects_unsafe_values(tmp_path, override):
    from soc_automation.config import KibanaTargetSettings

    env = {
        "SOC_DATABASE_PATH": str(tmp_path / "soc_automation.db"),
        "SOC_KIBANA_URL": "https://example.test",
        **override,
    }
    with pytest.raises(ConfigurationError):
        Settings.from_env(env)
    with pytest.raises(ConfigurationError):
        KibanaTargetSettings.from_env(env)


@pytest.mark.parametrize(
    "url", ["https://EXAMPLE.test:443/", "https://example.test:5601", "https://[::1]:443/"]
)
def test_target_identity_matches_authenticated_settings(url):
    from soc_automation.config import KibanaTargetSettings

    env = {"SOC_KIBANA_URL": url}
    target = KibanaTargetSettings.from_env(env)
    authenticated = KibanaSettings.from_env(
        {
            **env,
            "SOC_KIBANA_API_KEY": base64.b64encode(b"id:key").decode(),
        }
    )
    assert target.space == "default"
    assert target.target == authenticated.target


def test_readable_versioned_report(prepared):
    from soc_automation.cases import RENDERER_VERSION

    store, report, row, _ = prepared
    alerts = [store.show_alert(i, evidence=True) for i in report["source_alert_ids"]]
    payload = render(report, alerts)
    assert payload == render(copy.deepcopy(report), copy.deepcopy(alerts))
    description = payload["description"]
    assert RENDERER_VERSION in description
    for section in (
        "Investigation summary",
        "Observed event chronology",
        "Evidence-backed findings",
        "Supported inferences",
        "Evidence limitations",
        "Unresolved questions",
        "Evidence provenance",
    ):
        assert "## " + section in description
    assert "```json" not in description
    assert len(description) <= 30000
    assert "authentication" in payload["title"]
    assert "synthetic evidence" in description
    for item in report["retrieved_evidence"]:
        assert item["sha256"] in description
        assert item["reference"]["id"] in description
    assert json.loads(row["payload_json"]) == payload


def test_revisions_preserve_frozen_rows_and_block_superseded(prepared):
    from soc_automation.cases import digest

    store, report, old, client = prepared
    before = store.show_case_publication(old["id"])
    payload = json.loads(old["payload_json"])
    payload["description"] += "\nNew renderer version fixture"
    payload["tags"] = ["soc-publication-" + digest(payload)]
    with pytest.raises(StateError):
        store.prepare_publication(report["investigation_id"], client.settings.target, payload)
    new = store.prepare_publication(
        report["investigation_id"], client.settings.target, payload, revise=True
    )
    assert new["id"] != old["id"]
    assert new["payload_sha256"] != old["payload_sha256"]
    assert store.show_case_publication(old["id"]) == before
    assert not store.claim_publication(old["id"], old["payload_sha256"])
    with pytest.raises(sqlite3.IntegrityError), store._connection() as conn:
        conn.execute("UPDATE publication_heads SET publication_id=?", (old["id"],))
    with pytest.raises(sqlite3.IntegrityError), store._connection() as conn:
        conn.execute(
            "UPDATE case_publications SET state='sending',approval_sha256=payload_sha256 "
            "WHERE id=?",
            (old["id"],),
        )
    from review_helpers import approve

    approve(store, new["id"])
    assert store.claim_publication(new["id"], new["payload_sha256"])
    payload["description"] += "\nThird version"
    payload["tags"] = ["soc-publication-" + digest(payload)]
    with pytest.raises(StateError, match="after send"):
        store.prepare_publication(
            report["investigation_id"], client.settings.target, payload, revise=True
        )
    client.create.assert_not_called()


def test_v4_migration_preserves_publication_and_audit(tmp_path, monkeypatch):
    import soc_automation.state as state
    from soc_automation.cases import digest
    from soc_automation.ingestion import encode

    store = Store(tmp_path / "legacy.db")
    with monkeypatch.context() as patcher:
        patcher.setattr(state, "SCHEMA_VERSION", 4)
        with patch.object(Store, "_validate"):
            store.initialize()
        patcher.setattr(Store, "_validate", staticmethod(lambda connection: None))
        ids = [r["alert_id"] for r in ingest(store, (FIXTURES / "stages.json").read_bytes())]
        report = investigate(store, ids, FixtureEvidenceProvider(FIXTURES / "evidence"))
        payload = {"tags": ["soc-publication-legacy"], "description": "frozen legacy payload"}
        with store._connection() as conn:
            conn.execute(
                "INSERT INTO case_publications VALUES(?,?,?,?,?,NULL,'prepared',NULL,NULL,?)",
                (
                    "legacy",
                    report["investigation_id"],
                    "target",
                    encode(payload),
                    digest(payload),
                    "time",
                ),
            )
        before = store.show_case_publication("legacy")
    store.initialize()
    assert store.show_case_publication("legacy") == before
    with store._connection() as conn:
        assert not conn.execute("PRAGMA foreign_key_check").fetchall()
        assert (
            conn.execute("SELECT publication_id FROM publication_heads").fetchone()[0] == "legacy"
        )


def test_concurrent_revision_preparation_is_idempotent(prepared):
    from soc_automation.cases import digest

    store, report, old, client = prepared
    payload = json.loads(old["payload_json"])
    payload["description"] += "\nConcurrent revision fixture"
    payload["tags"] = ["soc-publication-" + digest(payload)]

    def prepare(_):
        return store.prepare_publication(
            report["investigation_id"], client.settings.target, payload, revise=True
        )["id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(prepare, range(4)))
    assert len(set(ids)) == 1
    with store._connection() as conn:
        assert conn.execute("SELECT count(*) FROM case_publications").fetchone()[0] == 2


@pytest.mark.parametrize("outcome", ["sending", "uncertain", "published"])
def test_revision_refused_after_remote_claim(prepared, outcome):
    from soc_automation.cases import digest

    store, report, row, client = prepared
    assert store.claim_publication(row["id"], row["payload_sha256"])
    if outcome == "uncertain":
        store.publication_outcome(row["id"])
    elif outcome == "published":
        store.publication_outcome(row["id"], {"id": "case-1", "version": "v1"})
    payload = json.loads(row["payload_json"])
    payload["description"] += "\nDisallowed revision"
    payload["tags"] = ["soc-publication-" + digest(payload)]
    with pytest.raises(StateError, match="after send"):
        store.prepare_publication(
            report["investigation_id"], client.settings.target, payload, revise=True
        )
    client.create.assert_not_called()


def test_reconcile_prepared_is_local_rejection(prepared):
    store, _, row, client = prepared
    before = store.show_case_publication(row["id"])
    with patch.object(client, "find") as find, patch.object(client, "get") as get:
        with pytest.raises(StateError, match="Publication has not been sent"):
            reconcile_case(store, row["id"], client)
        find.assert_not_called()
        get.assert_not_called()
    assert store.show_case_publication(row["id"]) == before
