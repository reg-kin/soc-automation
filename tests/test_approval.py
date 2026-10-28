"""Production internal decision path, synthetic SQLite only; no legacy claim adapter."""

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from test_preparation import TARGET
from test_preparation import queue as preparation_queue

from soc_automation.approval import ReviewPolicy, TrustedIdentity
from soc_automation.cases import RENDERER_VERSION
from soc_automation.service import publish_case
from soc_automation.state import StateError, Store


@pytest.fixture
def context(tmp_path):
    legacy, report, payload = preparation_queue.__wrapped__(tmp_path)
    policy = ReviewPolicy('review/1', ((1000, 'soc:reviewer'),), frozenset({TARGET}))
    legacy.install_review_policy(policy, expected_generation=None)
    store = Store(legacy.path, publication_policy=policy)
    job = store.enqueue_case_preparation(report['investigation_id'], TARGET)
    leased = store.claim_case_preparation()
    done = store.complete_case_preparation(job['id'], leased['lease_owner'],
                                           leased['lease_generation'], payload=payload)
    identity = TrustedIdentity.from_verified_peer_credentials(uid=1000, principal='soc:reviewer')
    return store, policy, identity, done['publication_id'], report, payload


def request(context, **changes):
    store, policy, identity, pub, _, _ = context
    review = store.review_case_publication(pub)
    values = dict(identity=identity, policy=policy, request_id=str(uuid4()), publication_id=pub,
                  decision='approved', expected_previous_event_id=None,
                  expected_payload_sha256=review['payload_sha256'],
                  expected_report_sha256=review['report_sha256'], expected_target=TARGET,
                  expected_renderer_version=RENDERER_VERSION,
                  expected_review_policy_version=policy.version, confirmed=True)
    values.update(changes)
    return values


def record(context, **changes):
    return context[0].record_case_decision(**request(context, **changes))


def count(store):
    with store._connection(readonly=True) as conn:
        return conn.execute('SELECT count(*) FROM case_review_events').fetchone()[0]


@pytest.mark.parametrize('sequence', [
    ['approved'], ['declined'], ['declined', 'declined'], ['declined', 'approved'],
    ['approved', 'revoked'], ['approved', 'revoked', 'approved'],
])
def test_transitions(context, sequence):
    prior = None
    for decision in sequence:
        event = record(context, decision=decision, expected_previous_event_id=prior,
                       reason_code={'approved': None, 'declined': 'operator_declined',
                                    'revoked': 'operator_revoked'}[decision])
        assert event['previous_event_id'] == prior
        assert event['actor_uid'] == 1000
        assert event['authentication_method'] == 'os_peer_credentials'
        assert event['decided_at'].endswith('+00:00')
        prior = event['id']
    assert count(context[0]) == len(sequence)


@pytest.mark.parametrize('first,next_decision', [(None, 'revoked'), ('approved', 'approved'),
                                               ('approved', 'declined'), ('declined', 'revoked')])
def test_invalid_transitions(context, first, next_decision):
    event = record(context, decision=first, reason_code='operator_declined' if first == 'declined'
                   else None) if first else None
    with pytest.raises(StateError, match='transition'):
        record(context, decision=next_decision,
               expected_previous_event_id=event['id'] if event else None,
               reason_code='operator_revoked' if next_decision == 'revoked'
               else 'operator_declined' if next_decision == 'declined' else None)
    assert count(context[0]) == bool(first)


@pytest.mark.parametrize('changes', [
    {'confirmed': False}, {'confirmed': 1}, {'decision': 'approve'},
    {'decision': 'declined'}, {'reason_code': 'operator_declined'},
    {'decision': 'declined', 'reason_code': 'operator_revoked'}, {'reason_code': 'unknown'},
    {'expected_previous_event_id': True}, {'expected_previous_event_id': 0},
    {'expected_payload_sha256': 'A' * 64}, {'expected_report_sha256': ''},
    {'expected_target': 'https://bad.test'}, {'request_id': ''},
])
def test_invalid_request_no_writes(context, changes):
    store = context[0]
    before = snapshot(store)
    with pytest.raises((ValueError, StateError)):
        record(context, **changes)
    assert snapshot(store) == before


def test_omitted_predecessor(context):
    values = request(context)
    del values['expected_previous_event_id']
    with pytest.raises(TypeError):
        context[0].record_case_decision(**values)


@pytest.mark.parametrize('changes,match', [
    ({'expected_previous_event_id': 12}, 'predecessor'),
    ({'expected_payload_sha256': 'a' * 64}, 'binding'),
    ({'expected_report_sha256': 'a' * 64}, 'binding'),
    ({'expected_target': 'https://other.test/default/securitySolution'}, 'unauthorized'),
    ({'expected_renderer_version': 'soc-case/1'}, 'binding'),
    ({'expected_review_policy_version': 'review/0'}, 'version'),
])
def test_stale_and_unauthorized(context, changes, match):
    with pytest.raises(StateError, match=match):
        record(context, **changes)
    assert count(context[0]) == 0


@pytest.mark.parametrize('uid,principal', [(1001, 'soc:reviewer'), (1000, 'soc:impostor')])
def test_unauthorized_identity(context, uid, principal):
    identity = TrustedIdentity.from_verified_peer_credentials(uid=uid, principal=principal)
    with pytest.raises(StateError, match='unauthorized'):
        record(context, identity=identity)


def test_replay_conflict_and_revocation(context):
    store = context[0]
    values = request(context)
    event = store.record_case_decision(**values)
    assert store.record_case_decision(**values) == event
    record(context, decision='revoked', expected_previous_event_id=event['id'],
           reason_code='operator_revoked')
    assert store.record_case_decision(**values) == event
    assert store.review_case_publication(context[3])['review_status'] == 'revoked'
    for key, value in {
        'publication_id': 'another', 'decision': 'declined', 'expected_previous_event_id': 1,
        'expected_payload_sha256': 'a' * 64, 'expected_report_sha256': 'a' * 64,
        'expected_renderer_version': 'soc-case/1', 'expected_review_policy_version': 'review/0',
        'reason_code': 'policy',
    }.items():
        with pytest.raises(StateError, match='conflict'):
            store.record_case_decision(**dict(values, **{key: value}))
    unauthorized = TrustedIdentity.from_verified_peer_credentials(uid=999, principal='bad')
    with pytest.raises(StateError, match='unauthorized'):
        store.record_case_decision(**dict(values, identity=unauthorized))
    assert count(store) == 2


def test_manual_publication_and_historical_replay(context):
    store, _, _, pub, _, payload = context
    values = request(context)
    event = store.record_case_decision(**values)
    client = SimpleNamespace(settings=SimpleNamespace(target=TARGET),
                             create=Mock(return_value=dict(payload, id='case-1', version='v1')))
    result = publish_case(store, pub, client, approval_hash=values['expected_payload_sha256'],
                          authorized=True)
    assert result['state'] == 'published'
    client.create.assert_called_once_with(payload)
    assert store.record_case_decision(**values) == event
    assert not store.claim_publication(pub, values['expected_payload_sha256'])
    assert count(store) == 1


def test_policy_rotation_and_missing_policy(context):
    store, policy, _, pub, _, _ = context
    event = record(context)
    for active in (None, replace(policy, version='review/2'),
                   replace(policy, principals=((1001, 'other'),)),
                   replace(policy, targets=frozenset({'https://other.test/default/securitySolution'})),
                   replace(policy, decisions=frozenset({'declined', 'revoked'}))):
        rotated = Store(store.path, publication_policy=active)
        before = snapshot(store)
        with pytest.raises(StateError):
            rotated.claim_publication(pub, event['payload_sha256'])
        assert snapshot(store) == before
    assert store.claim_publication(pub, event['payload_sha256'])


def test_rotation_allows_revoking_prior_approval(context):
    store, policy, identity, pub, report, payload = context
    event = record(context)
    active = replace(policy, version='review/2', decisions=frozenset({'declined', 'revoked'}))
    store.install_review_policy(active, expected_generation=1)
    rotated = Store(store.path, publication_policy=active)
    new_context = rotated, active, identity, pub, report, payload
    assert record(new_context, decision='revoked', expected_previous_event_id=event['id'],
                  reason_code='policy')['decision'] == 'revoked'


def test_deterministic_decline_does_not_bootstrap(context):
    store, policy, identity, _, report, payload = context
    target = 'https://deterministic.test/default/securitySolution'
    policy = replace(policy, version='review/2', targets=frozenset({target}))
    store.install_review_policy(policy, expected_generation=1)
    store = Store(store.path, publication_policy=policy)
    pub = store.prepare_publication(report['investigation_id'], target, payload)
    new_context = store, policy, identity, pub['id'], report, payload
    values = request(new_context, expected_target=target)
    with pytest.raises(StateError, match='provenance'):
        store.record_case_decision(**values)
    event = store.record_case_decision(**dict(values, decision='declined',
                                            reason_code='operator_declined'))
    assert store.review_case_publication(pub['id'])['report_hash_sources'] == ['review']
    with pytest.raises(StateError, match='provenance'):
        store.record_case_decision(**dict(values, request_id='approve-after-decline',
                                          expected_previous_event_id=event['id']))
    assert count(store) == 1


def test_superseded_publication(context):
    store, _, _, pub, report, payload = context
    values = request(context)
    revised = dict(payload, title='new revision', tags=['new-marker'])
    store.prepare_publication(report['investigation_id'], TARGET, revised, revise=True)
    with pytest.raises(StateError, match='head'):
        store.record_case_decision(**values)
    assert count(store) == 0
    assert not store.claim_publication(pub, values['expected_payload_sha256'])


def snapshot(store):
    with store._connection(readonly=True) as conn:
        return list(conn.iterdump())


def test_one_connection_only_and_only_event_write(context, monkeypatch):
    store = context[0]
    values = request(context)
    original = store._connection
    calls = []

    def connection(**kwargs):
        calls.append(kwargs)
        assert len(calls) == 1
        return original(**kwargs)

    before = snapshot(store)
    with monkeypatch.context() as patcher:
        patcher.setattr(store, '_connection', connection)
        store.record_case_decision(**values)
    after = snapshot(store)
    assert [line for line in after if line not in before] == [
        line for line in after if line.startswith('INSERT INTO "case_review_events"')]
    assert all(line in after for line in before)


def test_concurrent_decisions(context):
    store = context[0]
    values = [request(context), request(context)]

    def run(value):
        try:
            return store.record_case_decision(**value)
        except StateError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, values))
    assert sum(r is not None for r in results) == 1
    assert count(store) == 1


def test_concurrent_replays(context):
    store = context[0]
    values = request(context)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: store.record_case_decision(**values), range(2)))
    assert results[0] == results[1]
    assert count(store) == 1


def test_rollback_after_insert(context, monkeypatch):
    import soc_automation.state as state

    store = context[0]
    values = request(context)
    before = snapshot(store)
    monkeypatch.setattr(state, '_timestamp', lambda: '1900-01-01T00:00:00Z')
    # Insert succeeds; commit hook failure must roll back the whole transaction.
    original = store._connection
    from contextlib import contextmanager

    @contextmanager
    def failing_connection(**kwargs):
        with original(**kwargs) as conn:
            yield conn
            raise RuntimeError('injected failure')

    with monkeypatch.context() as patcher:
        patcher.setattr(store, '_connection', failing_connection)
        with pytest.raises(RuntimeError, match='injected'):
            store.record_case_decision(**values)
    assert snapshot(store) == before


@pytest.mark.parametrize('table,trigger,column,value', [
    ('case_publications', 'publication_identity', 'payload_sha256', 'a' * 64),
    ('investigations', 'investigations_no_update', 'report_json', '{}'),
    ('investigation_evidence', 'evidence_no_update', 'original_json', '{}'),
])
def test_tampered_artifacts(context, table, trigger, column, value):
    store = context[0]
    values = request(context)
    with store._connection() as conn:
        # Discover the immutable trigger names rather than assume their spelling.
        triggers = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                                "AND tbl_name=?", (table,)).fetchall()
        for row in triggers:
            conn.execute('DROP TRIGGER "' + row[0] + '"')
        conn.execute(f'UPDATE {table} SET {column}=?', (value,))  # noqa: S608
        for row in triggers:
            conn.execute(row[1])
    # Schema is intact: the shared artifact verifier must reject the changed bytes.
    with pytest.raises(StateError):
        store.record_case_decision(**values)
    assert count(store) == 0


@pytest.mark.parametrize('changes', [
    {'version': ''}, {'principals': ((True, 'user'),)}, {'principals': ((-1, 'user'),)},
    {'principals': ((1, 'a'), (1, 'b'))}, {'principals': [(1, 'a')]},
    {'targets': frozenset({'http://bad'})}, {'targets': set()},
    {'decisions': frozenset({'approve'})}, {'renderer_version': 'soc-case/99'},
    {'approval_provenance': 'review'}, {'decline_provenance': 'anything'},
    {'reason_requirements': ()}, {'decisions': frozenset({'approved'})},
])
def test_strict_policy(context, changes):
    with pytest.raises((ValueError, TypeError)):
        replace(context[1], **changes)


def test_identity_and_policy_boundaries(context):
    store, policy, identity, _, _, _ = context
    with pytest.raises((FrozenInstanceError, AttributeError)):
        identity.uid = 0
    with pytest.raises(FrozenInstanceError):
        policy.version = 'new'
    with pytest.raises(TypeError):
        TrustedIdentity(uid=1000, principal='soc:reviewer', authentication_method='oidc')
    with pytest.raises(ValueError):
        TrustedIdentity.from_verified_peer_credentials(uid=True, principal='soc:reviewer')
    with pytest.raises(ValueError):
        record(context, identity=SimpleNamespace(uid=1000, principal='soc:reviewer'))
    with pytest.raises(StateError, match='active policy'):
        record(context, policy=copy.copy(policy))
    with pytest.raises(ValueError):
        Store(store.path, publication_policy='review/1')


@pytest.mark.parametrize('reason', [None, 'operator_declined', 'unknown'])
def test_revocation_reason(context, reason):
    event = record(context)
    with pytest.raises(ValueError):
        record(context, decision='revoked', expected_previous_event_id=event['id'],
               reason_code=reason)
    assert count(context[0]) == 1


def test_replay_material_actor_and_target_conflicts(context):
    original, policy, identity, pub, report, payload = context
    other = 'https://other.test/default/securitySolution'
    policy = replace(policy, version='review/2',
                     principals=policy.principals + ((1001, 'soc:other'),),
                     targets=policy.targets | {other})
    original.install_review_policy(policy, expected_generation=1)
    store = Store(original.path, publication_policy=policy)
    values = request((store, policy, identity, pub, report, payload))
    event = store.record_case_decision(**values)
    for change in (
        {'identity': TrustedIdentity.from_verified_peer_credentials(
            uid=1001, principal='soc:other')},
        {'expected_target': other},
    ):
        with pytest.raises(StateError, match='conflict'):
            store.record_case_decision(**dict(values, **change))
    assert store.record_case_decision(**values) == event
    assert count(store) == 1


def test_replay_under_rotated_policy_is_historical(context):
    store, policy, identity, pub, _, _ = context
    values = request(context)
    event = store.record_case_decision(**values)
    active = replace(policy, version='review/2')
    store.install_review_policy(active, expected_generation=1)
    rotated = Store(store.path, publication_policy=active)
    assert rotated.record_case_decision(**dict(values, identity=identity, policy=active)) == event
    with pytest.raises(StateError, match='active policy'):
        rotated.claim_publication(pub, event['payload_sha256'])


def test_claim_rechecks_reason_policy(context):
    store, policy, _, pub, _, _ = context
    event = record(context)
    # Even a trusted composition error reusing a version cannot bypass current reason rules.
    active = replace(policy, reason_requirements=(
        ('approved', frozenset({'policy'})),
        ('declined', frozenset({'policy'})), ('revoked', frozenset({'policy'}))))
    with pytest.raises(StateError, match='active policy'):
        Store(store.path, publication_policy=active).claim_publication(pub, event['payload_sha256'])


def test_claim_rechecks_preparation_provenance(context):
    from review_helpers import approve

    original, policy, _, _, report, payload = context
    target = 'https://deterministic.test/default/securitySolution'
    policy = replace(policy, version='test-policy/1',
                     principals=((1000, 'synthetic:test-operator'),), targets=frozenset({target}))
    original.install_review_policy(policy, expected_generation=1)
    store = Store(original.path, publication_policy=policy)
    pub = store.prepare_publication(report['investigation_id'], target, payload)
    # A raw schema-valid approval is insufficient for the production application gate.
    approve(store, pub['id'])
    with pytest.raises(StateError, match='provenance'):
        store.claim_publication(pub['id'], pub['payload_sha256'])
    assert store.show_case_publication(pub['id'])['state'] == 'prepared'


def test_retained_store_rejected_after_rotation(context):
    store, policy, identity, pub, report, payload = context
    event = record(context)
    active = replace(policy, version='review/2')
    assert store.install_review_policy(active, expected_generation=1) == 2
    with pytest.raises(StateError, match='superseded'):
        record(context, decision='revoked', expected_previous_event_id=event['id'],
               reason_code='policy')
    with pytest.raises(StateError, match='superseded'):
        store.claim_publication(pub, event['payload_sha256'])
    current = Store(store.path, publication_policy=active)
    new = current, active, identity, pub, report, payload
    revoked = record(new, decision='revoked', expected_previous_event_id=event['id'],
                     reason_code='policy')
    approved = record(new, expected_previous_event_id=revoked['id'])
    assert current.claim_publication(pub, approved['payload_sha256'])


def test_policy_installation_cas_and_version_reuse(context):
    store, policy, *_ = context
    changed = replace(policy, principals=((2000, 'soc:other'),))
    with pytest.raises(StateError, match='reused'):
        store.install_review_policy(changed, expected_generation=1)
    with pytest.raises(StateError, match='conflict'):
        store.install_review_policy(replace(policy, version='review/2'), expected_generation=None)
    assert record(context)['decision'] == 'approved'
    with store._connection() as conn:
        for sql in ('DELETE FROM review_policy_generations',
                    "UPDATE review_policy_generations SET version='changed'"):
            with pytest.raises(Exception, match='immutable policy generation'):
                conn.execute(sql)


@pytest.mark.parametrize('recursive_triggers', [False, True])
@pytest.mark.parametrize('generation,version,content,valid_hash', [
    (3, 'review/1', '{}', True),  # Replace a historical version at the next generation.
    (3, 'review/2', '{}', True),  # Replace the active version at the next generation.
    (1, 'review/3', '{}', True),  # Replace an existing generation with a fresh version.
    (2, 'review/3', '{}', True),
    (1, 'review/2', '{}', True),  # Conflict with two different existing rows.
    (3, 'review/1', '{}', False),  # Version reuse also cannot bypass hash validation.
    (4, 'review/1', '{}', True),  # Version reuse also cannot bypass sequencing.
])
def test_policy_generation_replace_rejected(
        context, recursive_triggers, generation, version, content, valid_hash):
    store, policy, *_ = context
    assert store.install_review_policy(replace(policy, version='review/2'),
                                       expected_generation=1) == 2
    with store._connection() as conn:
        conn.execute(f'PRAGMA recursive_triggers={int(recursive_triggers)}')
        assert conn.execute('PRAGMA recursive_triggers').fetchone()[0] == recursive_triggers
        before = [tuple(row) for row in conn.execute(
            'SELECT * FROM review_policy_generations ORDER BY generation')]
        digest = conn.execute('SELECT sha256_text(?)', (content,)).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match='invalid policy generation'):
            conn.execute(
                'INSERT OR REPLACE INTO review_policy_generations '
                '(generation,version,content,content_sha256,installed_at) VALUES(?,?,?,?,?)',
                (generation, version, content, digest if valid_hash else '0' * 64, 'changed'))
        assert [tuple(row) for row in conn.execute(
            'SELECT * FROM review_policy_generations ORDER BY generation')] == before
    with store._connection(readonly=True) as conn:
        assert [tuple(row) for row in conn.execute(
            'SELECT * FROM review_policy_generations ORDER BY generation')] == before


@pytest.mark.parametrize('damage', ['empty', 'hash', 'missing_table'])
def test_authoritative_policy_damage_fails_closed(context, damage):
    store, _, _, pub, _, _ = context
    event = record(context)
    with store._connection() as conn:
        if damage == 'empty':
            conn.execute('DROP TRIGGER policy_generation_no_delete')
            conn.execute('DELETE FROM review_policy_generations')
            conn.execute("CREATE TRIGGER policy_generation_no_delete BEFORE DELETE ON "
                         "review_policy_generations BEGIN SELECT RAISE(ABORT,'immutable'); END")
        elif damage == 'hash':
            conn.execute('DROP TRIGGER policy_generation_no_update')
            conn.execute("UPDATE review_policy_generations SET content='{}'")
            conn.execute("CREATE TRIGGER policy_generation_no_update BEFORE UPDATE ON "
                         "review_policy_generations BEGIN SELECT RAISE(ABORT,'immutable'); END")
        else:
            conn.execute('DROP TABLE review_policy_generations')
    with pytest.raises(StateError):
        record(context, decision='revoked', expected_previous_event_id=event['id'],
               reason_code='policy')
    with pytest.raises(StateError):
        store.claim_publication(pub, event['payload_sha256'])


@pytest.mark.parametrize('operation', ['approval', 'claim'])
def test_rotation_serializes_with_admitted_operation(context, monkeypatch, operation):
    from threading import Event

    store, policy, _, pub, _, _ = context
    values = request(context)
    if operation == 'claim':
        store.record_case_decision(**values)
    entered, release, rotating = Event(), Event(), Event()
    original = store._require_active_policy

    def pause(conn):
        result = original(conn)
        entered.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(store, '_require_active_policy', pause)

    def rotate():
        rotating.set()
        return Store(store.path).install_review_policy(
            replace(policy, version='review/2'), expected_generation=1)

    with ThreadPoolExecutor(max_workers=2) as pool:
        if operation == 'approval':
            admitted = pool.submit(store.record_case_decision, **values)
        else:
            admitted = pool.submit(store.claim_publication, pub, values['expected_payload_sha256'])
        assert entered.wait(5)
        rotation = pool.submit(rotate)
        assert rotating.wait(5)
        assert not rotation.done()
        release.set()
        assert admitted.result()
        assert rotation.result() == 2
    with pytest.raises(StateError, match='superseded'):
        store.record_case_decision(**values)


def test_schema9_upgrade_preserves_artifacts_and_installs_no_policy(context):
    store, policy, _, pub, _, _ = context
    before = [line for line in snapshot(store)
              if not line.startswith('INSERT INTO "review_policy_generations"')]
    # Reconstruct schema 9: the only schema 10 addition is the empty policy ledger.
    with store._connection() as conn:
        conn.execute('DROP TABLE review_policy_generations')
        conn.execute('PRAGMA user_version=9')
    with pytest.raises(StateError, match='initialized'):
        record(context)
    store.initialize()
    store.initialize()
    assert snapshot(store) == before
    with pytest.raises(StateError, match='active policy'):
        record(context)
    assert store.install_review_policy(policy, expected_generation=None) == 1
    assert record(context)['publication_id'] == pub


def test_concurrent_rotation_has_single_winner(context):
    store, policy, *_ = context

    def rotate(version):
        try:
            return Store(store.path).install_review_policy(
                replace(policy, version=version), expected_generation=1)
        except StateError:
            return 'conflict'

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(rotate, ['review/2', 'review/3']))
    assert sorted(results, key=str) == [2, 'conflict']


@pytest.mark.parametrize('stage', ['python', 'sqlite', 'lock', 'precommit', 'entry'])
def test_decision_deadline_rollback(context, monkeypatch, stage):
    from soc_automation import deadline

    store = context[0]
    values = request(context)
    before = snapshot(store)
    clock = [10.0]
    monkeypatch.setattr(deadline.time, 'monotonic', lambda: clock[0])
    if stage == 'entry':
        clock[0] = 20.0
    elif stage == 'python':
        original = store._validate_report_evidence

        def verify(*args, **kwargs):
            clock[0] = 20.0
            return original(*args, **kwargs)

        monkeypatch.setattr(store, '_validate_report_evidence', verify)
    elif stage == 'sqlite':
        original = store._verify_case_publication

        def verify(conn, publication_id):
            clock[0] = 20.0
            conn.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL '
                         'SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n').fetchone()
            return original(conn, publication_id)

        monkeypatch.setattr(store, '_verify_case_publication', verify)
    elif stage == 'precommit':
        from contextlib import contextmanager

        original_connection = store._connection

        @contextmanager
        def expire_before_commit(**kwargs):
            with original_connection(**kwargs) as conn:
                yield conn
                assert conn.execute('SELECT count(*) FROM case_review_events').fetchone()[0] == 1
                clock[0] = 20.0

        monkeypatch.setattr(store, '_connection', expire_before_commit)
    else:
        blocker = sqlite3.connect(store.path, isolation_level=None)
        blocker.execute('BEGIN IMMEDIATE')
        monkeypatch.setattr(deadline.time, 'sleep', lambda _: clock.__setitem__(0, 20.0))
    try:
        with pytest.raises(TimeoutError):
            store.record_case_decision(**values, deadline=15.0)
    finally:
        if stage == 'lock':
            blocker.rollback()
            blocker.close()
    if stage == 'precommit':
        monkeypatch.setattr(store, '_connection', original_connection)
    assert snapshot(store) == before
    assert count(store) == 0
    assert deadline.current_deadline.get() is None


def test_decision_deadline_success_and_lost_response_replay(context):
    import time

    store = context[0]
    values = request(context)
    event = store.record_case_decision(**values, deadline=time.monotonic() + 30)
    before = snapshot(store)
    assert store.record_case_decision(**values, deadline=time.monotonic() + 30) == event
    assert snapshot(store) == before


def test_exact_binding_with_two_authorized_targets(context):
    store, policy, *_ = context
    other = 'https://other.test/default/securitySolution'
    policy = replace(policy, version='review/2', targets=frozenset({TARGET, other}))
    store.install_review_policy(policy, expected_generation=1)
    store._publication_policy = policy
    values = request(context, policy=policy, expected_review_policy_version=policy.version,
                     expected_target=other)
    before = snapshot(store)
    with pytest.raises(StateError, match='binding'):
        store.record_case_decision(**values)
    assert snapshot(store) == before


@pytest.mark.parametrize('loss', ['uid', 'operation', 'target'])
def test_exact_replay_requires_current_authorization(context, loss):
    store, policy, *_ = context
    values = request(context)
    store.record_case_decision(**values)
    changes = dict(version='review/2')
    if loss == 'uid':
        changes['principals'] = ((1001, 'other'),)
    elif loss == 'operation':
        changes['decisions'] = frozenset({'declined', 'revoked'})
    else:
        changes['targets'] = frozenset({'https://other.test/default/securitySolution'})
    policy = replace(policy, **changes)
    store.install_review_policy(policy, expected_generation=1)
    store._publication_policy = policy
    before = snapshot(store)
    with pytest.raises(StateError, match='unauthorized'):
        store.record_case_decision(**dict(values, policy=policy))
    assert snapshot(store) == before
