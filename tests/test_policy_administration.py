"""Disposable authority inspection and bounded candidate validation."""

import hashlib
import json
import sqlite3
from dataclasses import FrozenInstanceError, replace

import pytest

from soc_automation.approval import ReviewPolicy, _policy_content
from soc_automation.approval_policy import (
    POLICY_LIMIT,
    inspect_policy_ledger,
    policy_from_content,
    verify_authority,
)
from soc_automation.state import StateError, Store


@pytest.fixture
def ledger(tmp_path):
    store = Store(tmp_path / 'authority.db')
    store.initialize()
    policy = ReviewPolicy('review/1', ((1000, 'operator:test'),),
                          frozenset({'https://example.test/default/securitySolution'}))
    return store, policy


def test_empty_inspection(ledger):
    store, policy = ledger
    result = inspect_policy_ledger(store)
    assert result.generations == ()
    assert result.active is None
    with pytest.raises(StateError):
        verify_authority(store, policy)


def test_populated_inspection_without_live_file_and_no_mutation(ledger):
    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    second = replace(policy, version='review/2')
    store.install_review_policy(second, expected_generation=1)
    before = store.path.read_bytes()
    result = inspect_policy_ledger(store)
    assert [row.version for row in result.generations] == ['review/1', 'review/2']
    assert result.active.generation == 2
    assert result.active.content == _policy_content(second)
    assert result.active.content_sha256 == hashlib.sha256(
        result.active.content.encode()).hexdigest()
    assert result.active.installed_at
    assert store.path.read_bytes() == before
    verify_authority(store, second)
    with pytest.raises(StateError):
        verify_authority(store, policy)


@pytest.mark.parametrize('damage', ['semantics', 'digest', 'gap', 'version', 'noncanonical'])
def test_corrupt_history(ledger, damage):
    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    store.install_review_policy(replace(policy, version='review/2'), expected_generation=1)
    with store._connection() as conn:
        sql = conn.execute("SELECT sql FROM sqlite_master WHERE "
                           "name='policy_generation_no_update'").fetchone()[0]
        conn.execute('DROP TRIGGER policy_generation_no_update')
        if damage == 'digest':
            conn.execute('UPDATE review_policy_generations SET content_sha256=? '
                         'WHERE generation=1', ('0' * 64,))
        elif damage == 'gap':
            conn.execute('UPDATE review_policy_generations SET generation=3 WHERE generation=1')
        else:
            value = json.loads(_policy_content(policy))
            if damage == 'semantics':
                value['approval_provenance'] = 'untrusted'
            elif damage == 'version':
                value['version'] = 'review/2'
            content = json.dumps(value, sort_keys=True,
                                 separators=(',', ':') if damage != 'noncanonical' else None)
            conn.execute('UPDATE review_policy_generations SET content=?,content_sha256=? '
                         'WHERE generation=1',
                         (content, hashlib.sha256(content.encode()).hexdigest()))
        conn.execute(sql)
    with pytest.raises(StateError, match='Policy authority unavailable'):
        inspect_policy_ledger(store)


def test_version_reuse(ledger):
    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    with pytest.raises(StateError, match='cannot be reused'):
        store.install_review_policy(policy, expected_generation=1)


@pytest.mark.parametrize('version', [0, 9, 11])
def test_unsupported_schema(ledger, version):
    store, _ = ledger
    with store._connection() as conn:
        conn.execute(f'PRAGMA user_version={version}')
    with pytest.raises(StateError):
        inspect_policy_ledger(store)


def test_no_creation(tmp_path):
    path = tmp_path / 'missing.db'
    with pytest.raises(StateError):
        inspect_policy_ledger(Store(path))
    assert list(tmp_path.iterdir()) == []


def test_raw_limit(ledger):
    _, policy = ledger
    content = _policy_content(policy)
    assert policy_from_content(content + ' ' * (POLICY_LIMIT - len(content))) == policy
    with pytest.raises(ValueError, match='raw input'):
        policy_from_content(content + ' ' * (POLICY_LIMIT + 1 - len(content)))


def test_canonical_limit_and_store_guard(ledger, monkeypatch):
    store, policy = ledger
    prefix, suffix = 'https://', '/default/securitySolution'
    base = replace(policy, targets=frozenset({prefix + 'a' + suffix}))
    padding = POLICY_LIMIT - len(_policy_content(base).encode())
    exact = replace(policy, targets=frozenset({prefix + 'a' * (padding + 1) + suffix}))
    assert len(_policy_content(exact).encode()) == POLICY_LIMIT
    assert policy_from_content(_policy_content(exact)) == exact
    store.install_review_policy(exact, expected_generation=None)
    oversized = replace(exact, version='review/22')
    original = store._connection
    calls = []

    def connection(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(store, '_connection', connection)
    with pytest.raises(ValueError, match='Canonical policy too large'):
        store.install_review_policy(oversized, expected_generation=1)
    assert calls == []
    assert inspect_policy_ledger(store).active.generation == 1


def directory_bytes(path):
    return {item.name: item.read_bytes() for item in path.iterdir()}


@pytest.mark.parametrize('mode', ['delete', 'wal_absent', 'wal_present'])
def test_inspection_filesystem_contract(ledger, mode):
    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    writer = None
    if mode != 'delete':
        writer = sqlite3.connect(store.path)
        assert writer.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
        if mode == 'wal_absent':
            writer.close()
            writer = None
            assert not store.path.with_name(store.path.name + '-wal').exists()
        else:
            writer.execute('SELECT * FROM review_policy_generations').fetchall()
            # Commit a generation that is only present in WAL; never accept stale main state.
            store.install_review_policy(replace(policy, version='review/2'), expected_generation=1)
            assert store.path.with_name(store.path.name + '-wal').stat().st_size > 0
    try:
        before = directory_bytes(store.path.parent)
        if mode == 'delete':
            assert inspect_policy_ledger(store).active.generation == 1
        else:
            with pytest.raises(StateError, match='unsupported or busy database state'):
                inspect_policy_ledger(store)
        assert directory_bytes(store.path.parent) == before
    finally:
        if writer is not None:
            writer.close()


def test_snapshot_immutable_and_not_authority(ledger):
    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    snapshot = inspect_policy_ledger(store)
    with pytest.raises(FrozenInstanceError):
        snapshot.generations = ()
    with pytest.raises(FrozenInstanceError):
        snapshot.active.version = 'forged'
    with pytest.raises(TypeError):
        snapshot.generations[0] = snapshot.active
    with pytest.raises(StateError, match='Policy authority unavailable'):
        verify_authority(store, snapshot)
    with pytest.raises(ValueError, match='Validated publication policy required'):
        Store(store.path, publication_policy=snapshot)
    with pytest.raises(ValueError, match='Validated policy required'):
        store.install_review_policy(snapshot, expected_generation=1)


def test_inspection_writer_lock_and_original_deadline(ledger):
    import time

    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    with store._connection() as writer:
        writer.execute('UPDATE review_policy_generations SET generation=generation WHERE 0')
        # Repeating must still fail: inspection must not release the parent's locks.
        for _ in range(2):
            with pytest.raises(StateError, match='unsupported or busy database state'):
                inspect_policy_ledger(store)
    writer = sqlite3.connect(store.path)
    try:
        before = directory_bytes(store.path.parent)
        writer.execute('BEGIN EXCLUSIVE')
        deadline = time.monotonic() + 0.02
        with pytest.raises(TimeoutError):
            inspect_policy_ledger(store, deadline=deadline)
        assert time.monotonic() >= deadline
        assert directory_bytes(store.path.parent) == before
    finally:
        writer.close()


def test_validation_final_deadline(ledger, monkeypatch):
    import time

    import soc_automation.approval_policy as module

    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    original = module.policy_from_content
    clock = [time.monotonic()]
    bound = clock[0] + 10

    def validate(content):
        result = original(content)
        clock[0] = bound
        return result

    monkeypatch.setattr(module, 'policy_from_content', validate)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    with pytest.raises(TimeoutError):
        inspect_policy_ledger(store, deadline=bound)


@pytest.mark.parametrize('expired', [True, False, 'unrelated_expired'])
def test_sqlite_interrupt_classification(ledger, monkeypatch, expired):
    import time

    store, _ = ledger
    clock = [time.monotonic()]
    bound = clock[0] + 10

    def validate(conn):
        if expired is True:
            clock[0] = bound
        else:
            if expired == 'unrelated_expired':
                clock[0] = bound
            conn.set_progress_handler(lambda: 1, 1)
        conn.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL '
                     'SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n').fetchone()

    monkeypatch.setattr(store, '_validate', validate)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    with pytest.raises(TimeoutError if expired is True else StateError):
        inspect_policy_ledger(store, deadline=bound)


@pytest.mark.parametrize('extra', [0, 1])
def test_snapshot_size_boundary(ledger, monkeypatch, extra):
    import soc_automation.approval_policy as module

    store, _ = ledger
    size = store.path.stat().st_size
    monkeypatch.setattr(module, 'SNAPSHOT_LIMIT', size - extra)
    before = directory_bytes(store.path.parent)
    if extra:
        with pytest.raises(StateError, match='snapshot size limit'):
            module._locked_inspection_bytes(store.path, deadline=None)
    else:
        assert module._locked_inspection_bytes(store.path, deadline=None) == store.path.read_bytes()
    assert directory_bytes(store.path.parent) == before
    with sqlite3.connect(store.path, timeout=0) as writer:
        writer.execute('BEGIN EXCLUSIVE')


@pytest.mark.parametrize('payload', [b'', b'garbage', (100).to_bytes(8, 'big') + b'x',
                                     (0).to_bytes(8, 'big') + b'extra',
                                     (2**63).to_bytes(8, 'big')])
def test_malformed_ipc(ledger, payload):
    from soc_automation.approval_policy import _inspection_output

    store, _ = ledger
    before = directory_bytes(store.path.parent)
    program = f'import sys; sys.stdout.buffer.write({payload!r})'
    with pytest.raises(StateError):
        _inspection_output(program, store.path, None)
    assert directory_bytes(store.path.parent) == before


def test_ipc_independent_bound(ledger, monkeypatch):
    import soc_automation.approval_policy as module

    store, _ = ledger
    monkeypatch.setattr(module, 'IPC_LIMIT', 16)
    with pytest.raises(StateError, match='size limit'):
        module._inspection_output(
            'import sys; sys.stdout.buffer.write(bytes(100000))', store.path, None)


def test_helper_timeout_reaped(ledger, monkeypatch):
    import time

    import soc_automation.approval_policy as module

    store, _ = ledger
    children = []
    original = module.subprocess.Popen

    def spawn(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(module.subprocess, 'Popen', spawn)
    with pytest.raises(TimeoutError):
        module._inspection_output('import time; time.sleep(60)', store.path,
                                  time.monotonic() + 0.05)
    assert len(children) == 1
    assert children[0].returncode is not None
    assert children[0].stdout.closed


def test_source_lock_blocks_real_sqlite_writer(ledger):
    import subprocess
    import sys

    store, _ = ledger
    # Pause the actual copy immediately after lock acquisition, in a separate process.
    program = '''
import os, sys
from pathlib import Path
import soc_automation.approval_policy as m
original = os.pread
def pause(fd, length, offset):
    if length == 100:
        print('locked', flush=True)
        sys.stdin.readline()
    return original(fd, length, offset)
os.pread = pause
m._locked_inspection_bytes(Path(sys.argv[1]), deadline=None)
'''
    child = subprocess.Popen(  # noqa: S603 - fixed test program
        [sys.executable, '-c', program, str(store.path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'locked'
        with sqlite3.connect(store.path, timeout=0) as writer:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                writer.execute('BEGIN IMMEDIATE')
        child.stdin.write('\n')
        child.stdin.flush()
        assert child.wait(timeout=5) == 0
        with sqlite3.connect(store.path, timeout=0) as writer:
            writer.execute('BEGIN IMMEDIATE')
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdin.close()
        child.stdout.close()


def test_hot_journal_unchanged(ledger):
    import subprocess
    import sys

    store, _ = ledger
    program = '''
import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute('PRAGMA cache_size=1')
c.execute('BEGIN IMMEDIATE')
c.execute('CREATE TABLE crash_data(value BLOB)')
for _ in range(100):
    c.execute('INSERT INTO crash_data VALUES(zeroblob(4096))')
os._exit(0)
'''
    subprocess.run(  # noqa: S603 - fixed test program
        [sys.executable, '-c', program, str(store.path)], check=True)
    journal = store.path.with_name(store.path.name + '-journal')
    assert journal.read_bytes()[:8] == bytes.fromhex('d9d505f920a163d7')
    before = directory_bytes(store.path.parent)
    with pytest.raises(StateError):
        inspect_policy_ledger(store)
    assert directory_bytes(store.path.parent) == before


def test_actual_snapshot_limit_end_to_end(ledger):
    from soc_automation.approval_policy import SNAPSHOT_LIMIT

    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    # SQLite permits unused trailing pages; retain the entire main file in IPC.
    with store.path.open('r+b') as source:
        source.truncate(SNAPSHOT_LIMIT)
    before = hashlib.sha256(store.path.read_bytes()).digest()
    assert inspect_policy_ledger(store).active.version == policy.version
    assert hashlib.sha256(store.path.read_bytes()).digest() == before
    with store.path.open('r+b') as source:
        source.truncate(SNAPSHOT_LIMIT + 1)
    before = hashlib.sha256(store.path.read_bytes()).digest()
    with pytest.raises(StateError, match='snapshot size limit'):
        inspect_policy_ledger(store)
    assert hashlib.sha256(store.path.read_bytes()).digest() == before
    assert {p.name for p in store.path.parent.iterdir()} == {store.path.name}
    with sqlite3.connect(store.path, timeout=0) as writer:
        writer.execute('BEGIN EXCLUSIVE')


@pytest.mark.parametrize('change', ['grow', 'shrink'])
def test_copy_detects_size_change(ledger, monkeypatch, change):
    import os

    import soc_automation.approval_policy as module

    store, _ = ledger
    original = os.pread
    size = store.path.stat().st_size

    def changing_read(fd, length, offset):
        data = original(fd, length, offset)
        if length == 100:
            # Simulate the explicitly unsupported direct writer during maintenance.
            with store.path.open('r+b') as writer:
                writer.truncate(size + (1 if change == 'grow' else -1))
        return data

    monkeypatch.setattr(os, 'pread', changing_read)
    with pytest.raises(StateError, match='snapshot changed'):
        module._locked_inspection_bytes(store.path, deadline=None)
    with sqlite3.connect(store.path, timeout=0) as writer:
        writer.execute('BEGIN EXCLUSIVE')


@pytest.mark.parametrize('failure', [
    'deadline_interrupt', 'unrelated_interrupt', 'unrelated_expired_interrupt',
    'non_interrupt', 'arbitrary_state',
])
def test_active_history_sql_wrapper_classification(ledger, monkeypatch, failure):
    import time

    import soc_automation.approval_policy as module
    from soc_automation.deadline import current_deadline

    store, policy = ledger
    store.install_review_policy(policy, expected_generation=None)
    clock = [time.monotonic()]
    bound = clock[0] + 10
    connect = sqlite3.connect
    reached = []
    original_error = []

    class Connection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql == 'SELECT * FROM review_policy_generations ORDER BY generation':
                reached.append(current_deadline.get())
                assert current_deadline.get() == bound
                if failure in ('deadline_interrupt', 'unrelated_expired_interrupt'):
                    clock[0] = bound
                try:
                    if failure == 'arbitrary_state':
                        raise StateError('Unrelated state failure')
                    if failure == 'non_interrupt':
                        return super().execute('SELECT * FROM missing_history_table')
                    if failure != 'deadline_interrupt':
                        self.set_progress_handler(lambda: 1, 1)
                    return super().execute(
                        'WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL '
                        'SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n')
                except (sqlite3.Error, StateError) as exc:
                    original_error.append(exc)
                    raise
            return super().execute(sql, parameters)

    def inspection_connect(*args, **kwargs):
        return connect(*args, **kwargs, factory=Connection)

    monkeypatch.setattr(module.sqlite3, 'connect', inspection_connect)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    previous_deadline = current_deadline.get()
    result = None
    with pytest.raises(TimeoutError if failure == 'deadline_interrupt' else StateError) as caught:
        result = inspect_policy_ledger(store, deadline=bound)
    assert result is None  # No partial ledger escapes on failure.
    assert reached == [bound]  # No retry or replacement deadline.
    assert current_deadline.get() == previous_deadline
    chain = []
    cause = caught.value
    while cause is not None:
        chain.append(cause)
        cause = cause.__cause__
    assert chain[-1] is original_error[0]
    if failure != 'arbitrary_state':
        assert any(isinstance(exc, StateError) and str(exc) ==
                   'Authoritative active policy state corrupt or unavailable' for exc in chain)
        code = original_error[0].sqlite_errorcode & 0xff
        assert code == (sqlite3.SQLITE_ERROR if failure == 'non_interrupt'
                        else sqlite3.SQLITE_INTERRUPT)
