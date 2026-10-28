"""Offline real Linux transport and protected administrative policy tests."""

import hashlib
import json
import os
import socket
import sqlite3
import stat
import struct
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from test_preparation import queue as preparation_queue

from soc_automation.approval import ReviewPolicy, _policy_content
from soc_automation.approval_policy import POLICY_LIMIT, PolicySource, verify_authority
from soc_automation.approval_socket import (
    REQUEST_LIMIT,
    AdmissionError,
    ApprovalSocketService,
    SocketSettings,
    authorize_peer,
    peer_credentials,
)
from soc_automation.state import StateError, Store

pytestmark = pytest.mark.unix_socket
TARGET = 'https://example.test/default/securitySolution'


@pytest.fixture
def setup():
    # /tmp deliberately fails the real loader's ancestor checks. No security bypass:
    # use a private temporary directory beneath the test account's protected home.
    with tempfile.TemporaryDirectory(prefix='.soc-socket-test-', dir=Path.home()) as directory:
        root = Path(directory)
        uid, gid = os.getuid(), os.getgid()
        policy = ReviewPolicy('review/1', ((uid, 'operator:test'),), frozenset({TARGET}))
        path = root / 'policy.json'
        path.write_text(_policy_content(policy))
        path.chmod(0o600)
        source = PolicySource(path, owner_uid=uid)
        store = Store(root / 'soc_automation.db', timeout=0.1)
        store.initialize()
        store.install_review_policy(policy, expected_generation=None)
        settings = SocketSettings(root / 'operator.sock', uid, gid, administrator_uid=uid,
                                  special_uids=frozenset({uid}), connection_seconds=0.2,
                                  max_clients=8)
        yield root, policy, source, store, settings


@pytest.fixture
def running(setup):
    _, _, source, store, settings = setup
    service = ApprovalSocketService(settings, source, store).start()
    thread = threading.Thread(target=service.serve_forever)
    thread.start()
    try:
        yield service
    finally:
        service.close()
        thread.join(2)
        assert not thread.is_alive()


def connect(service):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    client.connect(str(service.settings.path))
    return client


def receive(client):
    def exact(size):
        data = b''
        while len(data) < size:
            part = client.recv(size - len(data))
            assert part
            data += part
        return data
    return json.loads(exact(struct.unpack('!I', exact(4))[0]))


def exchange(service, data=None, *, raw=None):
    if data is None:
        data = {'version': 1, 'operation': 'health', 'target': TARGET}
    encoded = json.dumps(data).encode()
    with connect(service) as client:
        client.sendall(raw if raw is not None else struct.pack('!I', len(encoded)) + encoded)
        client.shutdown(socket.SHUT_WR)
        return receive(client)


def test_real_peer_credentials_and_health_no_side_effects(setup, running, monkeypatch):
    _, _, _, store, _ = setup
    with store._connection(readonly=True) as conn:
        before = list(conn.iterdump())
    monkeypatch.setenv('USER', 'root')
    monkeypatch.setenv('LOGNAME', 'spoof')
    monkeypatch.setenv('SUDO_USER', 'spoof')
    with connect(running) as client:
        assert peer_credentials(client) == (os.getpid(), os.getuid(), os.getgid())
    assert exchange(running) == {'version': 1, 'ok': True, 'operation': 'health'}
    with store._connection(readonly=True) as conn:
        assert list(conn.iterdump()) == before
    assert running.settings.path.stat().st_mode & 0o777 == 0o660
    for action in ('approve', 'decline', 'revoke', 'publish', 'reconcile', 'install', 'rotate'):
        assert exchange(running, {'version': 1, 'operation': action, 'target': TARGET})[
            'error'] == 'invalid_request'


def test_uid_authorization(setup):
    _, policy, _, _, settings = setup
    uid = settings.service_uid
    identity = authorize_peer((123, uid, 123), policy, settings, operation='health', target=TARGET)
    assert (identity.uid, identity.principal) == (uid, 'operator:test')
    for credentials, candidate, config, target in [
        ((123, uid + 1, 123), policy, settings, TARGET),
        ((123, uid, 123), policy, replace(settings, special_uids=frozenset()), TARGET),
        ((123, 0, 123), replace(policy, principals=((0, 'root:test'),)), settings, TARGET),
        ((123, uid, 123), policy, settings, 'https://other.test/default/securitySolution'),
    ]:
        with pytest.raises(AdmissionError, match='unauthorized'):
            authorize_peer(credentials, candidate, config, operation='health', target=target)


@pytest.mark.parametrize('changes,error', [
    ({'version': 2}, 'unsupported_version'), ({'version': True}, 'invalid_request'),
    ({'uid': 0}, 'invalid_request'), ({'principal': 'root'}, 'invalid_request'),
    ({'identity': {}}, 'invalid_request'), ({'actor': 'root'}, 'invalid_request'),
    ({'policy_path': '/etc/policy'}, 'invalid_request'),
    ({'target': []}, 'invalid_request'), ({'operation': None}, 'invalid_request'),
    ({'target': 'https://other.test/default/securitySolution'}, 'unauthorized'),
])
def test_request_validation(running, changes, error):
    request = dict(version=1, operation='health', target=TARGET)
    request.update(changes)
    assert exchange(running, request)['error'] == error


@pytest.mark.parametrize('raw,error', [
    (struct.pack('!I', REQUEST_LIMIT + 1), 'request_too_large'),
    (b'\x00\x00', 'truncated_request'),
    (struct.pack('!I', 50) + b'{}', 'truncated_request'),
    (struct.pack('!I', 2) + b'{}extra', 'invalid_request'),
    (struct.pack('!I', 1) + b'{', 'invalid_request'),
    (struct.pack('!I', 25) + b'{"version":1,"version":1}', 'invalid_request'),
])
def test_framing(running, raw, error):
    assert exchange(running, raw=raw)['error'] == error


@pytest.mark.parametrize('data', [
    b'{"version":1,"version":1}', b'{"version":NaN}', b'{"version":Infinity}',
    b'{"version":1e999}', b'[]', b'\xff', b'[' * 2000,
])
def test_strict_json(running, data):
    assert exchange(running, raw=struct.pack('!I', len(data)) + data)['error'] == 'invalid_request'


def test_timeout_and_concurrency(running):
    running.slots = threading.BoundedSemaphore(1)
    entered = threading.Event()
    original = running._read

    def signal(*args):
        entered.set()
        return original(*args)

    running._read = signal
    with connect(running) as first:
        assert entered.wait(1)
        with connect(running) as second:
            assert receive(second)['error'] == 'busy'
        assert receive(first)['error'] == 'timeout'
    assert exchange(running)['ok']


def test_network_fixture_still_blocks_ip_and_dns():
    for family in (socket.AF_INET, socket.AF_INET6):
        with pytest.raises(AssertionError):
            socket.socket(family)
    with pytest.raises(AssertionError):
        socket.getaddrinfo('example.test', 443)
    with pytest.raises(AssertionError):
        socket.create_connection(('example.test', 443))


def test_missing_and_unsafe_policy(setup):
    root, _, source, store, _ = setup
    source.path.unlink()
    with pytest.raises(OSError):
        source.load(store)
    source.path.symlink_to(root / 'absent')
    with pytest.raises(OSError):
        source.load(store)


@pytest.mark.parametrize('mode', [0o666, 0o620, 0o601, 0o1600, 0o4600])
def test_policy_permissions(setup, mode):
    _, _, source, store, _ = setup
    source.path.chmod(mode)
    with pytest.raises(ValueError):
        source.load(store)


def test_policy_ownership(setup):
    _, _, source, store, _ = setup
    with pytest.raises(ValueError):
        replace(source, owner_uid=source.owner_uid + 1).load(store)


@pytest.mark.parametrize('attack', ['writable', 'symlink', 'fifo', 'directory', 'hardlink'])
def test_path_attacks(setup, attack):
    root, _, source, store, _ = setup
    if attack == 'writable':
        root.chmod(0o770)
    elif attack == 'symlink':
        link = root / 'link'
        link.symlink_to(root, target_is_directory=True)
        source = replace(source, path=link / source.path.name)
    elif attack == 'hardlink':
        os.link(source.path, root / 'alias')
    else:
        source.path.unlink()
        if attack == 'fifo':
            os.mkfifo(source.path, 0o600)
        else:
            source.path.mkdir()
    with pytest.raises((ValueError, OSError)):
        source.load(store)


@pytest.mark.parametrize('change', [
    'oversize', 'duplicate', 'nan', 'infinity', 'float_overflow', 'unknown', 'bool_uid',
    'bad_target', 'bad_decision', 'bad_renderer', 'bad_type', 'missing_field',
])
def test_policy_json(setup, change):
    _, policy, source, store, _ = setup
    value = json.loads(_policy_content(policy))
    raw = None
    if change == 'oversize':
        raw = ' ' * (POLICY_LIMIT + 1)
    elif change == 'duplicate':
        raw = '{"version":"review/1",' + _policy_content(policy)[1:]
    elif change in ('nan', 'infinity', 'float_overflow'):
        raw = '{"version":' + {'nan': 'NaN', 'infinity': 'Infinity',
                               'float_overflow': '1e999'}[change] + '}'
    elif change == 'unknown':
        value['unknown'] = True
    elif change == 'bool_uid':
        value['principals'][0][0] = True
    elif change == 'bad_target':
        value['targets'] = ['http://unsafe']
    elif change == 'bad_decision':
        value['decisions'] = ['publish']
    elif change == 'bad_renderer':
        value['renderer_version'] = 'soc-case/1'
    elif change == 'bad_type':
        value['targets'] = TARGET
    elif change == 'missing_field':
        del value['targets']
    source.path.write_text(raw if raw is not None else json.dumps(value))
    with pytest.raises(ValueError):
        source.load(store)


def test_policy_authority_rotation(setup, running):
    _, policy, source, store, _ = setup
    assert source.load(store) == policy
    store.install_review_policy(replace(policy, version='review/2'), expected_generation=1)
    with pytest.raises(StateError):
        source.load(store)
    assert exchange(running)['error'] == 'policy_unavailable'


@pytest.mark.parametrize('damage', ['empty', 'missing', 'hash', 'semantic', 'schema'])
def test_corrupt_authority(setup, damage):
    _, policy, source, store, _ = setup
    with store._connection() as conn:
        if damage == 'empty':
            conn.execute('DROP TRIGGER policy_generation_no_delete')
            conn.execute('DELETE FROM review_policy_generations')
        elif damage == 'missing':
            conn.execute('DROP TABLE review_policy_generations')
        elif damage == 'schema':
            conn.execute('PRAGMA user_version=9')
        else:
            conn.execute('DROP TRIGGER policy_generation_no_update')
            if damage == 'hash':
                conn.execute("UPDATE review_policy_generations SET content_sha256=?", ('0' * 64,))
            else:
                content = '{"version":"review/1"}'
                conn.execute('UPDATE review_policy_generations SET content=?,content_sha256=?',
                             (content, hashlib.sha256(content.encode()).hexdigest()))
    with pytest.raises(StateError):
        source.load(store)
    with pytest.raises(StateError):
        verify_authority(store, policy)


def test_socket_collision_and_concurrent_listener(setup, running):
    _, _, source, store, settings = setup
    with pytest.raises((ValueError, OSError)):
        ApprovalSocketService(settings, source, store).start()
    assert exchange(running)['ok']


@pytest.mark.parametrize('kind', ['file', 'symlink', 'socket'])
def test_existing_path_never_unlinked(setup, kind):
    root, _, source, store, settings = setup
    other = None
    if kind == 'file':
        settings.path.write_text('preserve')
    elif kind == 'symlink':
        settings.path.symlink_to(root / 'absent')
    else:
        other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        other.bind(str(settings.path))
    inode = settings.path.lstat().st_ino
    try:
        with pytest.raises(ValueError):
            ApprovalSocketService(settings, source, store).start()
        assert settings.path.lstat().st_ino == inode
    finally:
        if other:
            other.close()


@pytest.mark.parametrize('kind', ['socket', 'file', 'symlink'])
def test_shutdown_preserves_replacement(setup, kind):
    _, _, source, store, settings = setup
    service = ApprovalSocketService(settings, source, store).start()
    settings.path.unlink()
    replacement = None
    if kind == 'socket':
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(settings.path))
    elif kind == 'file':
        settings.path.write_text('replacement')
    else:
        settings.path.symlink_to(source.path)
    inode = settings.path.lstat().st_ino
    service.close()
    assert settings.path.lstat().st_ino == inode
    if replacement is not None:
        replacement.close()


def test_safe_shutdown_and_restart(setup):
    _, _, source, store, settings = setup
    service = ApprovalSocketService(settings, source, store).start()
    service.close()
    service.close()
    assert not settings.path.exists()
    assert settings.path.with_name(settings.path.name + '.lock').exists()
    second = ApprovalSocketService(settings, source, store).start()
    second.close()


@pytest.mark.parametrize('mode', [0o777, 0o770, 0o705])
def test_unsafe_socket_directory(setup, mode):
    root, _, source, store, settings = setup
    socket_dir = root / 'socket-dir'
    socket_dir.mkdir(mode=mode)
    socket_dir.chmod(mode)
    with pytest.raises(ValueError):
        ApprovalSocketService(replace(settings, path=socket_dir / 'operator.sock'),
                              source, store).start()


def test_actual_uid_denied_by_default(setup):
    _, _, source, store, settings = setup
    service = ApprovalSocketService(replace(settings, special_uids=frozenset()),
                                    source, store).start()
    thread = threading.Thread(target=service.serve_forever)
    thread.start()
    try:
        assert exchange(service)['error'] == 'unauthorized'
    finally:
        service.close()
        thread.join(2)


def test_actual_unknown_uid_denied(setup):
    _, policy, source, store, settings = setup
    policy = replace(policy, version='review/2', principals=((settings.service_uid + 1, 'other'),))
    store.install_review_policy(policy, expected_generation=1)
    source.path.write_text(_policy_content(policy))
    service = ApprovalSocketService(settings, source, store).start()
    thread = threading.Thread(target=service.serve_forever)
    thread.start()
    try:
        assert exchange(service)['error'] == 'unauthorized'
    finally:
        service.close()
        thread.join(2)


def test_explicit_root_exception_still_requires_mapping(setup):
    _, policy, _, _, settings = setup
    settings = replace(settings, special_uids=frozenset({0}))
    with pytest.raises(AdmissionError):
        authorize_peer((1, 0, 0), policy, settings, operation='health', target=TARGET)
    policy = replace(policy, principals=((0, 'admin:root'),))
    assert authorize_peer((1, 0, 0), policy, settings, operation='health',
                          target=TARGET).principal == 'admin:root'


def test_environment_cannot_select_policy(setup, monkeypatch):
    root, policy, source, store, _ = setup
    hostile = str(root / 'hostile-policy.json')
    monkeypatch.setenv('SOC_APPROVAL_POLICY_PATH', hostile)
    monkeypatch.setenv('SOC_POLICY_PATH', hostile)
    assert source.load(store) == policy


@pytest.mark.parametrize('damage', ['digest', 'semantics', 'gap'])
def test_historical_authority_is_verified(setup, damage):
    _, policy, source, store, _ = setup
    active = replace(policy, version='review/2')
    store.install_review_policy(active, expected_generation=1)
    source.path.write_text(_policy_content(active))
    with store._connection() as conn:
        trigger = conn.execute("SELECT sql FROM sqlite_master WHERE "
                               "name='policy_generation_no_update'").fetchone()[0]
        conn.execute('DROP TRIGGER policy_generation_no_update')
        if damage == 'digest':
            conn.execute("UPDATE review_policy_generations SET content_sha256=? WHERE generation=1",
                         ('0' * 64,))
        elif damage == 'gap':
            conn.execute('UPDATE review_policy_generations SET generation=3 WHERE generation=1')
        else:
            value = json.loads(_policy_content(policy))
            value['unknown'] = True
            content = json.dumps(value)
            conn.execute('UPDATE review_policy_generations SET content=?,content_sha256=? '
                         'WHERE generation=1',
                         (content, hashlib.sha256(content.encode()).hexdigest()))
        conn.execute(trigger)
    with pytest.raises(StateError):
        source.load(store)


def test_socket_unlink_cannot_bypass_listener_lock(setup, running):
    _, _, source, store, settings = setup
    settings.path.unlink()
    with pytest.raises(BlockingIOError):
        ApprovalSocketService(settings, source, store).start()


@pytest.mark.parametrize('kind', ['symlink', 'permissions', 'directory'])
def test_unsafe_listener_lock(setup, kind):
    root, _, source, store, settings = setup
    path = root / (settings.path.name + '.lock')
    if kind == 'symlink':
        path.symlink_to(source.path)
    elif kind == 'directory':
        path.mkdir()
    else:
        path.write_text('')
        path.chmod(0o666)
    inode = path.lstat().st_ino
    with pytest.raises((ValueError, OSError)):
        ApprovalSocketService(settings, source, store).start()
    assert path.lstat().st_ino == inode
    assert not settings.path.exists()


def test_socket_directory_wrong_owner(setup):
    _, _, source, store, settings = setup
    with pytest.raises(ValueError):
        ApprovalSocketService(replace(settings, service_uid=settings.service_uid + 1,
                                      special_uids=frozenset()), source, store).start()


def test_shutdown_waits_for_active_client(running):
    entered = threading.Event()
    original = running._read

    def signal(*args):
        entered.set()
        return original(*args)

    running._read = signal
    with connect(running) as client:
        client.sendall(b'\x00')
        assert entered.wait(1)
        running.close()
        assert receive(client)['error'] == 'timeout'
    assert not running.settings.path.exists()


def test_no_transaction_while_client_is_waiting(setup, running):
    _, policy, _, store, _ = setup
    entered = threading.Event()
    original = running._read

    def signal(*args):
        entered.set()
        return original(*args)

    running._read = signal
    with connect(running) as client:
        assert entered.wait(1)
        # An idle connection has neither a write lock nor an active read snapshot.
        assert store.install_review_policy(replace(policy, version='review/2'),
                                           expected_generation=1) == 2
        assert receive(client)['error'] == 'timeout'



def test_wrong_file_owner_rejected_after_safe_parent_walk(setup, monkeypatch):
    _, _, source, store, _ = setup
    original = os.fstat

    def wrong_owner(fd):
        info = original(fd)
        if stat.S_ISREG(info.st_mode):
            values = list(info)
            values[4] = source.owner_uid + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(os, 'fstat', wrong_owner)
    with pytest.raises(ValueError, match='Unsafe protected path'):
        source.load(store)


@pytest.mark.parametrize('failure', [RuntimeError, MemoryError])
def test_worker_start_failure_cleans_up_and_recovers(setup, monkeypatch, failure):
    _, _, source, store, settings = setup
    service = ApprovalSocketService(settings, source, store).start()
    attempted = []

    def fail_start(worker):
        attempted.append(worker)
        raise failure('injected worker startup failure')

    with connect(service) as client:
        with monkeypatch.context() as patch:
            patch.setattr(threading.Thread, 'start', fail_start)
            with pytest.raises(failure, match='injected worker startup failure'):
                service.serve_forever()
        assert client.recv(1) == b''
    assert len(attempted) == 1
    assert attempted[0].ident is None
    assert not service.workers
    assert service.stopping.is_set()
    assert service.listener.fileno() == -1
    assert service.directory is None
    assert service.lock is None
    assert not settings.path.exists()
    for _ in range(settings.max_clients):
        assert service.slots.acquire(blocking=False)
    assert not service.slots.acquire(blocking=False)
    for _ in range(settings.max_clients):
        service.slots.release()
    service.close()
    recovered = ApprovalSocketService(settings, source, store).start()
    thread = threading.Thread(target=recovered.serve_forever)
    thread.start()
    try:
        assert exchange(recovered)['ok']
    finally:
        recovered.close()
        thread.join(2)
    assert not thread.is_alive()


@pytest.mark.parametrize('family', [socket.AF_INET, socket.AF_INET6])
def test_network_guard_rejects_disguised_ip_descriptor(family):
    import _socket

    # Create an unconnected test-owned descriptor; no bind/connect or network I/O.
    original = _socket.socket(family, socket.SOCK_STREAM)
    try:
        fd = original.fileno()
        before = os.fstat(fd)
        with pytest.raises(AssertionError, match='Network access is forbidden'):
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd)
        assert os.fstat(fd) == before
        assert original.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == family
    finally:
        original.close()


def test_network_guard_allows_unix_descriptor():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as original:
        # Only the duplicate is transferred; cleanup never owns an inherited fd.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM,
                           fileno=os.dup(original.fileno())) as wrapped:
            assert wrapped.family == socket.AF_UNIX
            assert wrapped.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
        assert original.fileno() >= 0


def test_example_policy_has_no_active_grant():
    from soc_automation.approval_policy import policy_from_content

    example = Path(__file__).resolve().parents[1] / 'deploy/approval-policy.example.json'
    with pytest.raises(ValueError, match='Invalid UID'):
        policy_from_content(example.read_text())


@pytest.fixture
def decisions(setup, request):
    root, policy, source, _, settings = setup
    store, report, payload = preparation_queue.__wrapped__(root)
    store.install_review_policy(policy, expected_generation=None)
    if getattr(request, 'param', True):
        job = store.enqueue_case_preparation(report['investigation_id'], TARGET)
        lease = store.claim_case_preparation()
        done = store.complete_case_preparation(job['id'], lease['lease_owner'],
                                               lease['lease_generation'], payload=payload)
    else:
        publication = store.prepare_publication(report['investigation_id'], TARGET, payload)
        done = {'publication_id': publication['id']}
    service = ApprovalSocketService(settings, source, store).start()
    thread = threading.Thread(target=service.serve_forever)
    thread.start()
    review = store.review_case_publication(done['publication_id'])
    request = dict(version=1, operation='approve', target=TARGET, request_id='intent-1',
                   publication_id=done['publication_id'], expected_state='prepared',
                   expected_previous_event_id=None,
                   expected_payload_sha256=review['payload_sha256'],
                   expected_report_sha256=review['report_sha256'],
                   expected_renderer_version=review['renderer_version'],
                   expected_review_policy_version=policy.version, confirmed=True, reason_code=None)
    try:
        yield service, store, request, report, payload
    finally:
        service.close()
        thread.join(2)
        assert not thread.is_alive()


def event_count(store):
    with store._connection(readonly=True) as conn:
        return conn.execute('SELECT count(*) FROM case_review_events').fetchone()[0]


def test_authenticated_decisions_and_historical_replays(decisions):
    service, store, request, _, _ = decisions
    with store._connection(readonly=True) as conn:
        before = list(conn.iterdump())
    approved = exchange(service, request)
    assert approved == dict(version=1, ok=True, event_id=1, outcome='approved', historical=True)
    assert exchange(service, request) == approved
    revoke = dict(request, operation='revoke', request_id='intent-2',
                  expected_previous_event_id=1, reason_code='operator_revoked')
    assert exchange(service, revoke)['outcome'] == 'revoked'
    assert exchange(service, request) == approved
    decline = dict(request, operation='decline', request_id='intent-3',
                   expected_previous_event_id=2, reason_code='operator_declined')
    assert exchange(service, decline)['outcome'] == 'declined'
    assert event_count(store) == 3
    with store._connection(readonly=True) as conn:
        after = list(conn.iterdump())
    assert all(line in after for line in before)
    assert all(line.startswith('INSERT INTO "case_review_events"')
               for line in after if line not in before)
    with store._connection(readonly=True) as conn:
        assert conn.execute('SELECT state FROM case_publications').fetchone()[0] == 'prepared'
        assert conn.execute('SELECT count(*) FROM case_publication_audit').fetchone()[0] == 1


@pytest.mark.parametrize('change,error', [
    ({'request_id': None}, 'invalid_request'), ({'request_id': ''}, 'invalid_request'),
    ({'request_id': 'x' * 257}, 'invalid_request'), ({'request_id': '\n'}, 'invalid_request'),
    ({'expected_state': None}, 'invalid_request'),
    ({'expected_state': 'sending'}, 'stale_publication_state'),
    ({'expected_payload_sha256': 'a' * 64}, 'stale_publication_state'),
    ({'expected_report_sha256': 'a' * 64}, 'stale_publication_state'),
    ({'expected_previous_event_id': 42}, 'invalid_review_transition'),
    ({'expected_previous_event_id': True}, 'invalid_request'),
    ({'confirmed': 1}, 'invalid_request'), ({'confirmed': False}, 'invalid_request'),
    ({'actor_uid': 0}, 'invalid_request'), ({'principal': 'root'}, 'invalid_request'),
    ({'authentication_method': 'os_peer_credentials'}, 'invalid_request'),
    ({'policy': {}}, 'invalid_request'), ({'payload': {}}, 'invalid_request'),
    ({'operation': 'revoke', 'reason_code': 'operator_revoked'}, 'invalid_review_transition'),
    ({'operation': 'decline'}, 'invalid_request'),
    ({'target': 'https://other.test/default/securitySolution'}, 'unauthorized'),
])
def test_decision_rejections(decisions, change, error):
    service, store, request, _, _ = decisions
    assert exchange(service, dict(request, **change)) == dict(version=1, ok=False, error=error)
    assert event_count(store) == 0


@pytest.mark.parametrize('field', ['request_id', 'expected_state', 'expected_previous_event_id',
                                   'expected_report_sha256', 'confirmed'])
def test_missing_decision_fields(decisions, field):
    service, store, request, _, _ = decisions
    del request[field]
    assert exchange(service, request)['error'] == 'invalid_request'
    assert event_count(store) == 0


def test_decision_conflict_and_replay_after_state_change(decisions):
    service, store, request, _, _ = decisions
    event = exchange(service, request)
    conflict = exchange(service, dict(request, reason_code='policy'))
    assert conflict['error'] == 'conflicting_request_id'
    assert service.store.claim_publication(request['publication_id'],
                                           request['expected_payload_sha256'])
    assert exchange(service, request) == event
    assert exchange(service, dict(request, request_id='new'))['error'] == 'stale_publication_state'
    assert event_count(store) == 1


def test_concurrent_socket_decisions(decisions):
    from concurrent.futures import ThreadPoolExecutor

    service, store, request, _, _ = decisions
    other = dict(request, request_id='other', operation='decline', reason_code='operator_declined')
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda value: exchange(service, value), [request, other]))
    assert sum(result['ok'] for result in results) == 1
    assert {result.get('error') for result in results} == {None, 'invalid_review_transition'}
    assert event_count(store) == 1


def test_rotation_between_admission_and_decision(decisions, monkeypatch):
    service, store, request, _, _ = decisions
    original = service.store.record_case_decision

    def rotate(**values):
        store.install_review_policy(replace(service.policy, version='review/2'),
                                    expected_generation=1)
        return original(**values)

    monkeypatch.setattr(service.store, 'record_case_decision', rotate)
    assert exchange(service, request)['error'] == 'policy_unavailable'
    assert event_count(store) == 0
    assert exchange(service, request)['error'] == 'policy_unavailable'


def test_rotation_waits_for_decision_transaction(decisions, monkeypatch):
    service, store, request, _, _ = decisions
    entered, release = threading.Event(), threading.Event()
    original = service.store._verify_case_publication

    def paused(*args):
        entered.set()
        assert release.wait(2)
        return original(*args)

    monkeypatch.setattr(service.store, '_verify_case_publication', paused)
    result = []
    client = threading.Thread(target=lambda: result.append(exchange(service, request)))
    client.start()
    assert entered.wait(1)
    rotated = []
    admin = Store(store.path, timeout=2)
    rotation = threading.Thread(target=lambda: rotated.append(admin.install_review_policy(
        replace(service.policy, version='review/2'), expected_generation=1)))
    rotation.start()
    release.set()
    client.join(2)
    rotation.join(2)
    assert result[0]['ok'] and rotated == [2]
    assert event_count(store) == 1
    assert exchange(service, request)['error'] == 'policy_unavailable'


@pytest.mark.parametrize('failure', [BrokenPipeError, TimeoutError])
def test_disconnect_after_commit_and_safe_retry(decisions, monkeypatch, failure):
    service, store, request, _, _ = decisions
    committed = threading.Event()
    original = service._respond

    def lost_response(*args):
        committed.set()
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(service, '_respond', lost_response)
        encoded = json.dumps(request).encode()
        with connect(service) as client:
            client.sendall(struct.pack('!I', len(encoded)) + encoded)
            client.shutdown(socket.SHUT_WR)
            assert committed.wait(1)
    monkeypatch.setattr(service, '_respond', original)
    assert exchange(service, request)['event_id'] == 1
    assert event_count(store) == 1


def test_decision_errors_are_sanitized(decisions, monkeypatch):
    service, store, request, _, _ = decisions

    def fail(**kwargs):
        raise StateError('SQL secret /private/file traceback')

    monkeypatch.setattr(service.store, 'record_case_decision', fail)
    assert exchange(service, request) == dict(version=1, ok=False, error='internal_failure')
    assert event_count(store) == 0


def test_corrupt_evidence(decisions):
    service, store, request, report, payload = decisions
    with store._connection() as conn:
        triggers = conn.execute("SELECT sql,name FROM sqlite_master WHERE type='trigger' "
                                "AND tbl_name='investigation_evidence'").fetchall()
        for row in triggers:
            conn.execute('DROP TRIGGER "' + row['name'] + '"')
        conn.execute("UPDATE investigation_evidence SET original_json='{}'")
        for row in triggers:
            conn.execute(row['sql'])
    assert exchange(service, request)['error'] == 'evidence_verification_failure'
    assert event_count(store) == 0


@pytest.mark.parametrize('decisions', [False], indirect=True)
def test_approval_requires_completed_preparation(decisions):
    service, store, request, _, _ = decisions
    assert exchange(service, request)['error'] == 'evidence_verification_failure'
    assert exchange(service, dict(request, operation='decline',
                                  reason_code='operator_declined'))['outcome'] == 'declined'
    assert event_count(store) == 1


@pytest.mark.parametrize('change', ['uid', 'operation'])
def test_decision_peer_authorization(decisions, change):
    service, store, request, _, _ = decisions
    if change == 'uid':
        service.policy = replace(service.policy, principals=((os.getuid() + 1, 'other'),))
    else:
        service.policy = replace(service.policy, decisions=frozenset({'declined', 'revoked'}))
    assert exchange(service, request)['error'] == 'unauthorized'
    assert event_count(store) == 0



def test_concurrent_socket_exact_replay(decisions, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    service, store, request, _, _ = decisions
    service.settings = replace(service.settings, connection_seconds=30)
    admitted = threading.Barrier(3, timeout=10)
    proceed = threading.Event()
    contending = threading.Event()
    busy_threads = set()
    guard = threading.Lock()
    original_decision = service.store.record_case_decision
    original_connect = sqlite3.connect

    def decision(**kwargs):
        # This entry follows peer, request and active-authority admission checks.
        admitted.wait()
        assert proceed.wait(10)
        return original_decision(**kwargs)

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            try:
                return super().execute(sql, *args, **kwargs)
            except sqlite3.OperationalError as exc:
                if sql == 'BEGIN IMMEDIATE' and exc.sqlite_errorcode == sqlite3.SQLITE_BUSY:
                    with guard:
                        busy_threads.add(threading.get_ident())
                        if len(busy_threads) == 2:
                            contending.set()
                raise

    def connect(*args, **kwargs):
        return original_connect(*args, **kwargs, factory=Connection)

    def send():
        encoded = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(30)
            client.connect(str(service.settings.path))
            client.sendall(struct.pack('!I', len(encoded)) + encoded)
            client.shutdown(socket.SHUT_WR)
            return receive(client)

    monkeypatch.setattr(service.store, 'record_case_decision', decision)
    monkeypatch.setattr(sqlite3, 'connect', connect)
    blocker = original_connect(store.path, isolation_level=None)
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(send) for _ in range(2)]
        try:
            admitted.wait()
            blocker.execute('BEGIN IMMEDIATE')
            proceed.set()
            # Both writers must actually encounter SQLite's held writer lock.
            assert contending.wait(10)
            blocker.rollback()
            results = [future.result(timeout=15) for future in futures]
        finally:
            admitted.abort()
            proceed.set()
            blocker.rollback()
            blocker.close()
    assert results[0] == results[1]
    assert results[0]['ok']
    assert results[0]['event_id'] == results[1]['event_id']
    assert event_count(store) == 1


def test_peer_credential_failure_is_sanitized(decisions, monkeypatch):
    import soc_automation.approval_socket as transport

    service, store, request, _, _ = decisions

    def fail(connection):
        raise OSError('/secret/peer')

    monkeypatch.setattr(transport, 'peer_credentials', fail)
    # Credentials fail before request reading; only read the framed error.
    with connect(service) as client:
        assert receive(client) == dict(version=1, ok=False, error='authentication_failure')
    assert event_count(store) == 0


@pytest.mark.parametrize('confirmation', [None, 'true', 'false', 1.0, 0.5])
def test_malformed_confirmation_no_decision(decisions, confirmation):
    service, store, request, _, _ = decisions
    request = dict(request, confirmed=confirmation)
    assert exchange(service, request)['error'] == 'invalid_request'
    assert event_count(store) == 0


def test_duplicate_confirmation_no_decision(decisions):
    service, store, request, _, _ = decisions
    raw = json.dumps(request).encode()
    raw = raw[:-1] + b', "confirmed": true}'
    assert exchange(service, raw=struct.pack('!I', len(raw)) + raw)['error'] == 'invalid_request'
    assert event_count(store) == 0
