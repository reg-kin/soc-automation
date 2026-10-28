"""Entirely synthetic HTTP tests; global socket/DNS prohibition remains active."""

import base64
import http.client
import json
import socket
import ssl
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soc_automation.cli import main
from soc_automation.config import ConfigurationError, ElasticsearchSettings, Settings
from soc_automation.elasticsearch import ElasticsearchError, ElasticsearchProvider
from soc_automation.evidence import Reference
from soc_automation.ingestion import InputError, encode
from soc_automation.service import ingest, investigate
from soc_automation.state import StateError, Store

KEY = base64.b64encode(b"synthetic-id:synthetic-secret").decode()
FIXTURES = Path(__file__).parent / "fixtures" / "investigation"


@pytest.fixture
def settings():
    return ElasticsearchSettings(
        "https://elastic.invalid:9200",
        KEY,
        ("synthetic-alerts",),
        ("synthetic-events", "other-events-*"),
        backoff=0,
    )


@pytest.fixture
def transport(monkeypatch):
    factory = MagicMock()
    monkeypatch.setattr(http.client, "HTTPSConnection", factory)
    return factory


def response(transport, item=None, status=200, data=None):
    reply = MagicMock()
    reply.status = status
    reply.getheader.return_value = "identity"
    reply.read.return_value = data if data is not None else encode(item).encode()
    transport.return_value.getresponse.return_value = reply
    return reply


def source(index="synthetic-events", identifier="0"):
    return {
        "_index": index,
        "_id": identifier,
        "_source": {
            "@timestamp": "2026-01-01T00:00:00Z",
            "event.action": "synthetic",
            "untouched": {"array": [1, None, "original"]},
        },
    }


def test_get_auth_tls_identity(settings, transport):
    item = source()
    reply = response(transport, item)
    provider = ElasticsearchProvider(settings)
    assert provider.retrieve(Reference("synthetic-events", "0")).document == item
    args, kwargs = transport.return_value.request.call_args
    assert args == ("GET", "/synthetic-events/_doc/0")
    assert kwargs["headers"]["Authorization"] == "ApiKey " + KEY
    context = transport.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert transport.call_args.kwargs["timeout"] == 5
    transport.return_value.sock.settimeout.assert_called_once_with(10)
    reply.read.assert_called_once_with(settings.max_response_bytes + 1)
    transport.return_value.close.assert_called_once()
    assert KEY not in repr(settings)


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "http://elastic.invalid"},
        {"url": "ftp://elastic.invalid"},
        {"url": "https://user:pass@elastic.invalid"},
        {"url": "https://elastic.invalid/?x=y"},
        {"url": "https://elastic.invalid/path"},
        {"url": "https://elastic.invalid:bad"},
        {"url": "https://"},
        {"api_key": ""},
        {"api_key": "bad"},
        {"api_key": base64.b64encode(b"no-colon").decode()},
        {"alert_indices": ("*",)},
        {"source_indices": ()},
        {"source_indices": ("a,b",)},
        {"retries": 4},
        {"max_documents": 101},
        {"read_timeout": 0},
        {"max_document_bytes": 262145},
        {"ca_path": Path("/nonexistent/synthetic-ca.pem")},
    ],
)
def test_bad_config(settings, changes):
    with pytest.raises(ConfigurationError) as error:
        replace(settings, **changes)
    assert KEY not in str(error.value)


def test_env_and_ca(settings, tmp_path):
    env = {
        "SOC_DATABASE_PATH": str(tmp_path / "soc_automation.db"),
        "SOC_ELASTICSEARCH_URL": settings.url,
        "SOC_ELASTICSEARCH_API_KEY": KEY,
        "SOC_ELASTICSEARCH_ALERT_INDICES": "synthetic-alerts",
        "SOC_ELASTICSEARCH_SOURCE_INDICES": "synthetic-events,other-events-*",
    }
    assert ElasticsearchSettings.from_env(env).source_indices == settings.source_indices
    Settings.from_env(env)
    for name, value in [("API_KEY", ""), ("READ_TIMEOUT", "nan"), ("UNKNOWN", "x")]:
        with pytest.raises(ConfigurationError):
            Settings.from_env({**env, "SOC_ELASTICSEARCH_" + name: value})
    ca = tmp_path / "bad.pem"
    ca.write_text("not a certificate")
    for path in [ca, tmp_path, Path("relative.pem")]:
        with pytest.raises(ConfigurationError):
            replace(settings, ca_path=path)
    with patch("ssl.create_default_context") as context:
        replace(settings, ca_path=ca)
        context.assert_called_once_with(cafile=str(ca))


@pytest.mark.parametrize(
    "status,reason,calls",
    [
        (401, "authentication_failed", 1),
        (403, "authorization_failed", 1),
        (404, "document_missing", 1),
        (429, "rate_limited", 3),
        (500, "server_error", 3),
        (502, "server_error", 3),
        (503, "server_error", 3),
        (504, "server_error", 3),
        (302, "http_error", 1),
    ],
)
def test_http_errors(settings, transport, status, reason, calls):
    response(transport, status=status, data=KEY.encode())
    with patch("soc_automation.elasticsearch.time.sleep") as sleep:
        result = ElasticsearchProvider(settings).retrieve(Reference("synthetic-events", "0"))
    assert result.reason == reason
    assert result.status == ("missing" if status == 404 else "failed")
    assert transport.return_value.request.call_count == calls
    assert transport.return_value.close.call_count == calls
    assert sleep.call_count == calls - 1
    assert KEY not in repr(result)


@pytest.mark.parametrize(
    "exception,reason,retries",
    [
        (TimeoutError, "read_timeout", 3),
        (socket.timeout, "read_timeout", 3),
        (ssl.SSLCertVerificationError, "tls_verification_failed", 1),
        (ConnectionError, "transport_failure", 3),
        (http.client.IncompleteRead, "transport_failure", 3),
    ],
)
def test_transport_errors(settings, transport, exception, reason, retries):
    if exception is http.client.IncompleteRead:
        error = exception(b"synthetic")
    else:
        error = exception(KEY)
    transport.return_value.getresponse.side_effect = error
    result = ElasticsearchProvider(settings).retrieve(Reference("synthetic-events", "0"))
    assert result.status == "failed" and result.reason == reason
    assert transport.return_value.close.call_count == retries
    assert KEY not in repr(result)


def test_connect_timeout_backoff(settings, transport):
    transport.return_value.connect.side_effect = TimeoutError(KEY)
    with patch("soc_automation.elasticsearch.time.sleep") as sleep:
        result = ElasticsearchProvider(replace(settings, backoff=1)).retrieve(
            Reference("synthetic-events", "0")
        )
    assert result.reason == "connection_timeout"
    assert [call.args[0] for call in sleep.call_args_list] == [1, 2]


@pytest.mark.parametrize("mutation", ["index", "id", "source", "found"])
def test_invalid_identity(settings, transport, mutation):
    item = source()
    if mutation == "source":
        item.pop("_source")
    elif mutation == "found":
        item["found"] = False
    else:
        item["_" + mutation] = "wrong"
    response(transport, item)
    assert (
        ElasticsearchProvider(settings).retrieve(Reference("synthetic-events", "0")).status
        == "failed"
    )


@pytest.mark.parametrize("data", [b"{", b"null", b"[]", b'{"x":1,"x":2}', b"{}", b"\xff"])
def test_malformed(settings, transport, data):
    response(transport, data=data)
    assert (
        ElasticsearchProvider(settings).retrieve(Reference("synthetic-events", "0")).reason
        == "invalid_response"
    )


def test_sizes_and_encoding(settings, transport):
    ref = Reference("synthetic-events", "0")
    response(transport, data=b"x" * 101)
    assert (
        ElasticsearchProvider(replace(settings, max_response_bytes=100)).retrieve(ref).reason
        == "response_size_exceeded"
    )
    response(transport, source())
    assert (
        ElasticsearchProvider(replace(settings, max_document_bytes=10)).retrieve(ref).reason
        == "document_size_exceeded"
    )
    reply = response(transport, source())
    reply.getheader.return_value = "gzip"
    assert ElasticsearchProvider(settings).retrieve(ref).reason == "unexpected_encoding"


def test_batch_bounds_duplicates_and_allowlist(settings, transport):
    response(transport, source())
    provider = ElasticsearchProvider(settings)
    ref = Reference("synthetic-events", "0")
    assert len(provider.retrieve_many([ref, ref])) == 2
    assert transport.return_value.request.call_count == 1
    for batch in [[], [ref] * 101]:
        with pytest.raises(InputError):
            provider.retrieve_many(batch)
    assert provider.retrieve(Reference("forbidden", "0")).reason == "index_not_permitted"
    assert transport.return_value.request.call_count == 1
    response(transport, source("other-events-1"))
    assert provider.retrieve(Reference("other-events-1", "0")).status == "found"


def test_alert_ingestion_and_partial_investigation(settings, transport, tmp_path):
    alerts = json.loads((FIXTURES / "stages.json").read_text())
    settings = replace(settings, alert_indices=(alerts[0]["_index"],))
    provider = ElasticsearchProvider(settings)
    store = Store(tmp_path / "soc_automation.db")
    store.initialize()
    ids = []
    for alert in alerts:
        response(transport, alert)
        hit = provider.fetch_alert(Reference(alert["_index"], alert["_id"]))
        assert hit == alert
        ids.append(ingest(store, encode(hit).encode())[0]["alert_id"])
    original_get = provider.retrieve

    def partial(ref):
        if ref.id == "0":
            response(transport, source(identifier=ref.id))
        elif ref.id == "1":
            response(transport, status=404)
        else:
            response(transport, status=503)
        return original_get(ref)

    provider.retrieve = partial
    report = investigate(store, ids, provider)
    assert report["status"] == "partial"
    assert [row["status"] for row in report["retrieved_evidence"]] == ["found", "missing", "failed"]
    assert len(report["source_alert_ids"]) == 3
    response(transport, status=401)
    with pytest.raises(ElasticsearchError, match="authentication_failed"):
        provider.fetch_alert(Reference(alerts[0]["_index"], alerts[0]["_id"]))


def test_cli_fetch_and_investigate(settings, transport, monkeypatch, tmp_path, capsys):
    alerts = json.loads((FIXTURES / "stages.json").read_text())
    database = tmp_path / "soc_automation.db"
    for key, value in {
        "URL": settings.url,
        "API_KEY": KEY,
        "ALERT_INDICES": alerts[0]["_index"],
        "SOURCE_INDICES": "synthetic-events",
        "BACKOFF": "0",
    }.items():
        monkeypatch.setenv("SOC_ELASTICSEARCH_" + key, value)
    monkeypatch.setenv("SOC_DATABASE_PATH", str(database))
    response(transport, alerts[0])
    assert main(["fetch-alert", "--index", alerts[0]["_index"], "--id", alerts[0]["_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["persisted"] is False
    assert not database.exists()
    store = Store(database)
    store.initialize()
    # Fetch validates only: even the remote document ID cannot select a local alert.
    with pytest.raises(StateError, match="^Unknown ingested alert$"):
        investigate(store, [alerts[0]["_id"]], provider=ElasticsearchProvider(settings))
    transport.reset_mock()
    assert main(["--provider", "elasticsearch", "--alert-id", alerts[0]["_id"], "investigate"]) == 1
    transport.assert_not_called()
    assert capsys.readouterr().out == ""
    with store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM investigations").fetchone()[0] == 0
    identifier = ingest(store, encode(alerts[0]).encode())[0]["alert_id"]
    response(transport, source())
    assert main(["--provider", "elasticsearch", "--alert-id", identifier, "investigate"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "completed"
    response(transport, status=403, data=KEY.encode())
    assert main(["fetch-alert", "--index", alerts[0]["_index"], "--id", alerts[0]["_id"]]) == 1
    output = capsys.readouterr()
    assert KEY not in output.out + output.err


def test_installed_cli_mocked(tmp_path):
    script = """
import http.client, json, socket
from unittest.mock import MagicMock
from soc_automation.cli import main
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network"))
factory = MagicMock()
http.client.HTTPSConnection = factory
response = factory.return_value.getresponse.return_value
response.status = 200
response.getheader.return_value = "identity"
response.read.return_value = json.dumps({"_index":"synthetic-alerts", "_id":"a",
 "_source":{"@timestamp":"2026-01-01T00:00:00Z"}}).encode()
import runpy, sys
sys.argv = ["soc-automation", "fetch-alert", "--index", "synthetic-alerts", "--id", "a"]
runpy.run_path(sys.prefix + "/bin/soc-automation", run_name="__main__")
"""
    import os
    import sys

    env = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}
    env.update(
        SOC_DATABASE_PATH=str(tmp_path / "soc_automation.db"),
        SOC_ELASTICSEARCH_URL="https://elastic.invalid",
        SOC_ELASTICSEARCH_API_KEY=KEY,
        SOC_ELASTICSEARCH_ALERT_INDICES="synthetic-alerts",
        SOC_ELASTICSEARCH_SOURCE_INDICES="synthetic-events",
    )
    result = subprocess.run(  # noqa: S603 -- fixed installed CLI smoke script
        [sys.executable, "-c", script], env=env, capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout)["persisted"] is False
    assert not (tmp_path / "soc_automation.db").exists()


@pytest.mark.parametrize("dotted", [False, True])
def test_fetch_alert_numeric_user_id(settings, transport, dotted):
    item = source("synthetic-alerts", "numeric-user")
    item["_source"].update({"user.id": 1001} if dotted else {"user": {"id": 1001}})
    response(transport, item)
    fetched = ElasticsearchProvider(settings).fetch_alert(Reference(item["_index"], item["_id"]))
    assert fetched == item
    value = fetched["_source"]["user.id"] if dotted else fetched["_source"]["user"]["id"]
    assert type(value) is int
