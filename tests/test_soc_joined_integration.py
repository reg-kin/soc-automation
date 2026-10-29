"""Joined offline investigation, authenticated review, and trusted publication journey.

Only HTTPS transport and the test account's policy ownership are substituted.
Internet sockets remain forbidden by conftest; all state lives in a private,
protected temporary directory and is removed after socket workers stop.
"""

import hashlib
import json
import os
import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_automation import cli
from soc_automation.approval import ReviewPolicy, _policy_content
from soc_automation.approval_policy import PolicySource
from soc_automation.approval_socket import ApprovalSocketService, SocketSettings
from soc_automation.cases import digest, render
from soc_automation.evidence import FixtureEvidenceProvider
from soc_automation.ingestion import encode
from soc_automation.preparation_coordinator import run_pass
from soc_automation.service import ingest, investigate
from soc_automation.state import Store

pytestmark = pytest.mark.unix_socket
FIXTURES = Path(__file__).parent / 'fixtures' / 'investigation'
TARGET = 'https://example.test/default/securitySolution'


@pytest.fixture
def joined(monkeypatch, capsys):
    # /tmp is intentionally unacceptable to the production protected-path loader.
    with tempfile.TemporaryDirectory(prefix='.soc-joined-', dir=Path.home()) as directory:
        root = Path(directory)
        uid = os.getuid()
        policy = ReviewPolicy('joined/1', ((uid, 'operator:joined'),), frozenset({TARGET}))
        policy_path = root / 'policy.json'
        policy_path.write_text(_policy_content(policy))
        policy_path.chmod(0o600)
        store = Store(root / 'soc_automation.db')
        store.initialize()
        assert store.install_review_policy(policy, expected_generation=None) == 1
        ids = [item['alert_id'] for item in ingest(store, (FIXTURES / 'stages.json').read_bytes())]
        report = investigate(store, ids, FixtureEvidenceProvider(FIXTURES / 'evidence'))
        assert report['status'] == 'completed'
        assert report['source_alert_ids'] == sorted(ids)
        assert report['retrieved_evidence'] and not report['evidence_gaps']
        assert Store(store.path).show_investigation(report['investigation_id']) == report
        with store._connection(readonly=True) as conn:
            evidence = conn.execute(
                'SELECT original_json,sha256 FROM investigation_evidence'
            ).fetchall()
        assert len(evidence) == len(report['retrieved_evidence'])
        for row in evidence:
            assert hashlib.sha256(row['original_json'].encode()).hexdigest() == row['sha256']

        result = run_pass(store, TARGET)
        assert result.completed == 1 and result.stopped is None
        job = store.show_case_preparation(result.outcomes[0]['job_id'], snapshot=True)
        assert job['state'] == 'completed'
        pub = job['publication_id']
        monkeypatch.setenv('SOC_DATABASE_PATH', str(store.path))
        monkeypatch.setenv('SOC_KIBANA_URL', 'https://example.test')
        monkeypatch.setenv('SOC_KIBANA_API_KEY', 'c3ludGhldGljOm9ubHk=')
        monkeypatch.setattr(cli, 'APPROVAL_POLICY', policy_path)
        # Same trusted test composition as test_trusted_publisher: retain path,
        # permissions, ancestor, content and authoritative generation checks.
        monkeypatch.setattr(cli, 'PolicySource', lambda path: PolicySource(path, owner_uid=uid))
        assert cli.main(['review-case-publication', '--publication-id', pub]) == 0
        review = json.loads(capsys.readouterr().out)
        expected = render(
            report, [store.show_alert(i, evidence=True) for i in report['source_alert_ids']]
        )
        assert review['payload'] == expected
        assert review['payload_sha256_verified'] and review['report_sha256_verified']
        assert review['report_hash_sources'] == ['preparation']
        assert review['payload_sha256'] == digest(expected)
        assert review['report_sha256'] == job['report_sha256']

        requests = []

        class Transport:
            def __init__(self, host, port, **kwargs):
                assert host == 'example.test' and port is None
                self.sock = SimpleNamespace(settimeout=lambda _: None)

            def connect(self):
                pass

            def request(self, method, path, body, headers):
                assert (method, path) == ('POST', '/api/cases')
                assert headers['kbn-xsrf'] == 'soc-automation'
                requests.append((method, path, body))
                receipt = dict(json.loads(body), id='joined-case-1', version='v1')
                self.body = encode(receipt).encode()

            def getresponse(self):
                return SimpleNamespace(status=201, getheader=lambda _, default: default,
                                       read=lambda limit: self.body[:limit])

            def close(self):
                pass

        monkeypatch.setattr('soc_automation.kibana.http.client.HTTPSConnection', Transport)
        settings = SocketSettings(root / 'operator.sock', uid, os.getgid(), administrator_uid=uid,
                                  special_uids=frozenset({uid}))
        source = PolicySource(policy_path, owner_uid=uid)
        service = ApprovalSocketService(settings, source, store).start()
        thread = threading.Thread(target=service.serve_forever)
        thread.start()
        try:
            yield SimpleNamespace(store=store, policy=policy, policy_path=policy_path,
                                  settings=settings, pub=pub, review=review, requests=requests)
        finally:
            service.close()
            thread.join(3)
            assert not thread.is_alive()
            assert not service.workers
            assert not settings.path.exists()


def decide(j, operation='approve', previous=None):
    review = j.review
    args = [('approve-case-publication' if operation == 'approve' else 'revoke-case-approval'),
            '--socket-path', str(j.settings.path), '--target', TARGET,
            '--publication-id', j.pub, '--request-id', 'joined-' + operation,
            '--expected-state', 'prepared', '--expected-previous-event-id',
            'null' if previous is None else str(previous), '--confirm']
    for key in ('payload_sha256', 'report_sha256', 'renderer_version'):
        args += ['--expected-' + key.replace('_', '-'), review[key]]
    args += ['--expected-review-policy-version', j.policy.version]
    if operation == 'revoke':
        args += ['--reason-code', 'operator_revoked']
    return cli.main(args)


def publish(j, payload_hash=None):
    return cli.main(['publish-case', '--publication-id', j.pub, '--authorize-case-creation',
                     '--approve-payload-sha256', payload_hash or j.review['payload_sha256']])


def corrupt(store, table, statement):
    # Simulate offline disk damage, restoring schema so production integrity
    # verification (rather than missing-trigger validation) detects corruption.
    with store._connection() as conn:
        triggers = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                                'AND tbl_name=?', (table,)).fetchall()
        for row in triggers:
            conn.execute('DROP TRIGGER "' + row['name'] + '"')
        conn.execute(statement)
        for row in triggers:
            conn.execute(row['sql'])


def test_joined_publication_one_shot(joined, capsys):
    j = joined
    assert decide(j) == 0
    event_id = json.loads(capsys.readouterr().out)['event_id']
    assert publish(j) == 0
    capsys.readouterr()
    saved = Store(j.store.path).review_case_publication(j.pub)
    assert saved['state'] == 'published'
    assert saved['approval_sha256'] == saved['payload_sha256'] == j.review['payload_sha256']
    assert (saved['remote_case_id'], saved['remote_version']) == ('joined-case-1', 'v1')
    assert [item['event'] for item in saved['audit']] == ['prepared', 'sending', 'published']
    event, = saved['review_history']
    assert event['id'] == event_id
    assert event['actor_uid'] == os.getuid()
    assert event['actor_principal'] == 'operator:joined'
    assert event['authentication_method'] == 'os_peer_credentials'
    assert event['decision'] == 'approved'
    assert event['target'] == TARGET
    assert event['review_policy_version'] == j.policy.version
    assert event['payload_sha256'] == saved['payload_sha256']
    assert event['report_sha256'] == saved['report_sha256']
    assert publish(j) == 0
    assert j.requests == [('POST', '/api/cases', encode(j.review['payload']).encode())]
    assert Store(j.store.path).review_case_publication(j.pub) == saved


@pytest.mark.parametrize(('failure', 'expected_error'), [
    ('no_approval', 'Current approval under active policy required'),
    ('revoked', 'Current approval under active policy required'),
    ('hash', 'Reviewed approval hash required'),
    ('generation', 'Missing or superseded authority'),
    ('provenance', 'Approval requires verified completed preparation provenance'),
    ('evidence', 'Stored evidence mismatch'),
    ('target', 'Publication target or payload mismatch'),
])
def test_joined_rejections_never_send(joined, capsys, monkeypatch, failure, expected_error):
    j = joined
    if failure != 'no_approval':
        assert decide(j) == 0
        event = json.loads(capsys.readouterr().out)['event_id']
    if failure == 'revoked':
        assert decide(j, 'revoke', event) == 0
    elif failure == 'generation':
        # Real generation API rotates authority; the trusted policy file is stale.
        assert j.store.install_review_policy(replace(j.policy, version='joined/2'),
                                             expected_generation=1) == 2
    elif failure == 'provenance':
        corrupt(j.store, 'case_preparation_jobs',
                "UPDATE case_preparation_jobs SET publication_id=NULL,state='failed',"
                "failure_code='permanent'")
    elif failure == 'evidence':
        corrupt(j.store, 'investigation_evidence',
                "UPDATE investigation_evidence SET original_json='{}'")
    elif failure == 'target':
        monkeypatch.setenv('SOC_KIBANA_URL', 'https://other.test')
    # The CLI emits only command_failed. Observe the handled application error
    # at that boundary, without changing rejection behavior or inspecting traces.
    errors = []
    configure_logging = cli.configure_logging

    def observed_logging(level):
        logger = configure_logging(level)

        def log(*args, **kwargs):
            errors.append(sys.exc_info()[1])
            return logger.log(*args, **kwargs)

        return SimpleNamespace(info=logger.info, log=log)

    monkeypatch.setattr(cli, 'configure_logging', observed_logging)
    for attempt in range(2):
        assert publish(j, '0' * 64 if failure == 'hash' else None) == 1
        assert len(errors) == attempt + 1
        error = errors[-1]
        if failure == 'generation':
            # Authority validation preserves the specific reason as its cause.
            assert str(error) == 'Policy authority unavailable'
            error = error.__cause__
        assert str(error) == expected_error
    assert j.requests == []
    saved = Store(j.store.path).show_case_publication(j.pub)
    assert saved['state'] == 'prepared'
    assert saved['approval_sha256'] is None
    assert saved['remote_case_id'] is None
    assert [item['event'] for item in saved['audit']] == ['prepared']
