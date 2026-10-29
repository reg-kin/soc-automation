"""Trusted CLI composition with disposable state and fake Cases transports only."""

import os
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_approval import context as approval_context  # noqa: F401
from test_approval import record

from soc_automation import cli
from soc_automation.approval import _policy_content
from soc_automation.approval_policy import PolicySource
from soc_automation.state import Store


@pytest.fixture
def publisher(approval_context, monkeypatch):  # noqa: F811
    context = approval_context
    store, policy, _, pub, _, payload = context
    renamed = store.path.with_name('soc_automation.db')
    store.path.rename(renamed)
    store.path = renamed
    with tempfile.TemporaryDirectory(prefix='.soc-publisher-test-', dir=Path.home()) as directory:
        path = Path(directory) / 'policy.json'
        path.write_text(_policy_content(policy))
        path.chmod(0o600)
        monkeypatch.setattr(cli, 'APPROVAL_POLICY', path)
        # Only the trusted test composition changes owner/path; real loader checks run.
        monkeypatch.setattr(cli, 'PolicySource',
                            lambda supplied: PolicySource(supplied, owner_uid=os.getuid()))
        monkeypatch.setenv('SOC_DATABASE_PATH', str(store.path))
        monkeypatch.setenv('SOC_DATABASE_TIMEOUT_SECONDS', '7')
        monkeypatch.setenv('SOC_KIBANA_URL', 'https://example.test')
        monkeypatch.setenv('SOC_KIBANA_API_KEY', 'aWQ6a2V5')
        client = SimpleNamespace(settings=SimpleNamespace(target=next(iter(policy.targets))),
                                 create=Mock(return_value=dict(payload, id='case-1', version='v1')),
                                 find=Mock(), get=Mock())
        monkeypatch.setattr(cli, 'KibanaClient', lambda _: client)
        args = ['publish-case', '--publication-id', pub, '--authorize-case-creation',
                '--approve-payload-sha256', store.show_case_publication(pub)['payload_sha256']]
        yield context, path, client, args


def test_valid_policy_and_one_shot(publisher, monkeypatch):
    context, _, client, args = publisher
    record(context)
    actual_publish = cli.publish_case

    def guarded(store, *args, **kwargs):
        assert type(store) is Store
        assert store.path == context[0].path
        assert store.timeout == 7
        assert store._publication_policy == context[1]
        return actual_publish(store, *args, **kwargs)

    monkeypatch.setattr(cli, 'publish_case', guarded)
    assert cli.main(args) == 0
    assert cli.main(args) == 0
    client.create.assert_called_once_with(context[-1])


@pytest.mark.parametrize('failure', [
    'missing', 'permissions', 'owner', 'invalid', 'mismatch', 'uninstalled', 'rotation',
    'unapproved', 'declined', 'revoked', 'provenance', 'stale', 'authorization', 'hash',
])
def test_rejection_never_creates_case(publisher, monkeypatch, failure):
    context, path, client, args = publisher
    store, policy, _, pub, report, payload = context
    if failure not in {'unapproved', 'declined'}:
        event = record(context)
    if failure == 'missing':
        path.unlink()
    elif failure == 'permissions':
        path.chmod(0o622)
    elif failure == 'owner':
        monkeypatch.setattr(cli, 'PolicySource',
                            lambda supplied: PolicySource(supplied, owner_uid=os.getuid() + 1))
    elif failure == 'invalid':
        path.write_text('{"version": "invalid"}')
    elif failure == 'mismatch':
        path.write_text(_policy_content(replace(policy, version='review/2')))
    elif failure == 'uninstalled':
        empty_dir = store.path.parent / 'empty'
        empty_dir.mkdir()
        empty = Store(empty_dir / 'soc_automation.db')
        empty.initialize()
        monkeypatch.setenv('SOC_DATABASE_PATH', str(empty.path))
    elif failure == 'rotation':
        original = cli.publish_case

        def rotate(*args, **kwargs):
            store.install_review_policy(replace(policy, version='review/2'), expected_generation=1)
            return original(*args, **kwargs)

        monkeypatch.setattr(cli, 'publish_case', rotate)
    elif failure == 'declined':
        record(context, decision='declined', reason_code='operator_declined')
    elif failure == 'revoked':
        record(context, decision='revoked', reason_code='operator_revoked',
               expected_previous_event_id=event['id'])
    elif failure == 'provenance':
        # Simulate a historical approval lacking completed preparation evidence.
        with store._connection() as conn:
            triggers = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                                    "AND tbl_name='case_preparation_jobs'").fetchall()
            for row in triggers:
                conn.execute('DROP TRIGGER "' + row[0] + '"')
            conn.execute("UPDATE case_preparation_jobs SET publication_id=NULL,"
                         "state='failed',failure_code='permanent'")
            for row in triggers:
                conn.execute(row[1])
    elif failure == 'stale':
        store.prepare_publication(report['investigation_id'], next(iter(policy.targets)),
                                  dict(payload, title='Revised', tags=['revised-marker']),
                                  revise=True)
    elif failure == 'authorization':
        args.remove('--authorize-case-creation')
    elif failure == 'hash':
        args[-1] = '0' * 64
    assert cli.main(args) == 1
    client.create.assert_not_called()
    assert store.show_case_publication(pub)['state'] == 'prepared'


def test_uncertain_no_retry_and_reconciliation(publisher):
    context, path, client, args = publisher
    record(context)
    receipt = client.create.return_value
    client.create.side_effect = TimeoutError
    assert cli.main(args) == 1
    assert cli.main(args) == 1
    client.create.assert_called_once()
    # Reconciliation keeps its existing composition and needs no policy file.
    path.unlink()
    client.find.return_value = {'total': 1, 'cases': [{'id': receipt['id']}]}
    client.get.return_value = receipt
    assert cli.main(['reconcile-case', '--publication-id', context[3]]) == 0
    assert context[0].show_case_publication(context[3])['state'] == 'published'
    client.create.assert_called_once()


@pytest.mark.parametrize('option', ['--policy', '--principal', '--identity', '--policy-content'])
def test_caller_cannot_supply_trust(publisher, option):
    _, _, client, args = publisher
    with pytest.raises(SystemExit):
        cli.main([*args, option, 'untrusted'])
    client.create.assert_not_called()
