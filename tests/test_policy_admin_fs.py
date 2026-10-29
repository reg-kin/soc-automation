"""Disposable descriptor fixtures; no root privileges or production access required."""

import hashlib
import json
import os
from contextlib import contextmanager

import pytest

from soc_automation import policy_admin_fs as fs
from soc_automation.approval import ReviewPolicy, _policy_content


def canonical():
    return _policy_content(ReviewPolicy(
        'review/1', ((1000, 'operator:test'),),
        frozenset({'https://example.test/default/securitySolution'}))).encode()


def prepare(evidence, value):
    evidence.prepare(value, '/source.json')


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    owner = os.getuid()
    safe = fs._safe

    def fixture_safe(info, **kwargs):
        # Map only the fixture owner's UID to root. Keep all production mode/type checks.
        values = list(info)
        values[4] = 0 if info.st_uid == owner else info.st_uid
        safe(os.stat_result(values), **kwargs)

    monkeypatch.setattr(fs, '_safe', fixture_safe)
    monkeypatch.setattr(fs.os, 'getuid', lambda: 0)
    monkeypatch.setattr(fs.os, 'geteuid', lambda: 0)
    tmp_path.chmod(0o700)
    (tmp_path / 'source.json').write_bytes(canonical())
    (tmp_path / 'source.json').chmod(0o600)
    original_open = os.open

    def fixture_open(name, *args, **kwargs):
        # The source reader still walks and validates every component; only its
        # root is redirected to a disposable directory, avoiding unsafe /tmp.
        return original_open(tmp_path if name == '/' else name, *args, **kwargs)

    monkeypatch.setattr(fs.os, 'open', fixture_open)
    fd = os.open(tmp_path, fs.DIR_FLAGS)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def manifest(name='op-1'):
    return dict(version=2, operation_id=name, operation='install', change_reference='CHG:1',
                state='prepared', expected_generation=0, expected_current_sha256=None,
                candidate_sha256=hashlib.sha256(canonical()).hexdigest(),
                candidate_version='review/1', candidate_size=len(canonical()))


def locked(sandbox):
    return fs._locked_at(sandbox[1], lambda: None)


def test_creation_lock_scope_inode_and_closed_handle(sandbox):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        assert evidence.discover() == {}
        inode = (path / 'admin.lock').stat().st_ino
        with pytest.raises(BlockingIOError), locked(sandbox):
            pytest.fail('Concurrent acquisition succeeded')
        assert (path / 'admin.lock').stat().st_mode & 0o777 == 0o600
        assert (path / 'operations').stat().st_mode & 0o777 == 0o700
    with pytest.raises(fs.EvidenceError):
        evidence.discover()
    with locked(sandbox):
        assert (path / 'admin.lock').stat().st_ino == inode


@pytest.mark.parametrize('real,effective', [(1, 0), (0, 1), (1, 1)])
def test_identity_before_any_filesystem(real, effective, monkeypatch):
    monkeypatch.setattr(fs.os, 'getuid', lambda: real)
    monkeypatch.setattr(fs.os, 'geteuid', lambda: effective)
    monkeypatch.setattr(fs.os, 'open', lambda *a, **k: pytest.fail('Filesystem accessed'))
    with pytest.raises(PermissionError), fs.administration():
        pass
    with pytest.raises(PermissionError), fs._locked_at(-1, lambda: None):
        pass


@pytest.mark.parametrize('attack', ['symlink', 'hardlink', 'mode', 'directory', 'fifo'])
def test_lock_attacks(sandbox, attack):
    path, _ = sandbox
    target = path / 'admin.lock'
    if attack == 'symlink':
        target.symlink_to('missing')
    elif attack == 'hardlink':
        (path / 'other').write_bytes(b'')
        (path / 'other').chmod(0o600)
        os.link(path / 'other', target)
    elif attack == 'mode':
        target.touch(mode=0o666)
        target.chmod(0o666)
    elif attack == 'directory':
        target.mkdir()
    else:
        os.mkfifo(target, 0o600)
    with pytest.raises((OSError, fs.EvidenceError)), locked(sandbox):
        pass


@pytest.mark.parametrize('kind', ['directory', 'lock'])
def test_unsafe_owner(kind, sandbox, monkeypatch):
    original = os.fstat

    def wrong_owner(fd):
        info = original(fd)
        values = list(info)
        if kind == 'directory' or not fs.stat.S_ISDIR(info.st_mode):
            values[4] = 123456
        return os.stat_result(values)

    monkeypatch.setattr(fs.os, 'fstat', wrong_owner)
    with pytest.raises(fs.EvidenceError), locked(sandbox):
        pass


@pytest.mark.parametrize('name', ['', '.', '..', '../x', 'a/b', 'a' * 65, 'é', 'a\x00'])
def test_ids(sandbox, name):
    with locked(sandbox) as evidence:
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest(name))
        assert evidence.discover() == {}


def test_lifecycle_exclusivity_and_immutable_metadata(sandbox):
    with locked(sandbox) as evidence:
        value = manifest()
        prepare(evidence, value)
        assert evidence.discover() == {'op-1': 'unresolved'}
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))
        with pytest.raises(fs.EvidenceError):
            evidence.update(dict(value, candidate_sha256='b' * 64, state='completed'))
        evidence.update(dict(value, state='completed'))
        assert evidence.discover() == {'op-1': 'completed'}
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, value)
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))
    with locked(sandbox) as evidence:
        assert evidence.discover() == {'op-1': 'completed'}


@pytest.mark.parametrize('damage', [b'', b'{', b'{}', b'{"version":1,"version":1}',
                                    b'x' * 4097, b'\xff'])
def test_corrupt_manifest(sandbox, damage):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        (path / 'operations/op-1/manifest.json').write_bytes(damage)
        assert evidence.discover() == {'op-1': 'corrupt'}
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


@pytest.mark.parametrize('changes', [
    {'version': True}, {'version': 3}, {'state': 'committed'}, {'extra': 'x'},
    {'operation': 'recover'}, {'expected_generation': True}, {'expected_generation': 1},
    {'expected_current_sha256': 'a' * 64}, {'candidate_size': 65537},
    {'candidate_sha256': 'A' * 64}, {'candidate_version': 'x' * 257},
    {'candidate_version': '\n'}, {'candidate_size': 1.0},
])
def test_strict_manifest(sandbox, changes):
    with locked(sandbox) as evidence:
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, dict(manifest(), **changes))
        assert evidence.discover() == {}


def test_contradictory_identity_and_extra_entries(sandbox):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        target = path / 'operations/op-1/manifest.json'
        target.write_text(json.dumps(manifest('different')))
        assert evidence.discover() == {'op-1': 'corrupt'}
        target.write_text(json.dumps(dict(manifest(), state='completed')))
        (target.parent / '.manifest-interrupted').touch()
        assert evidence.discover() == {'op-1': 'corrupt'}


@pytest.mark.parametrize('failure', ['write', 'file_fsync', 'rename', 'directory_fsync'])
def test_failed_atomic_update_blocks(sandbox, monkeypatch, failure):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        value = manifest()
        prepare(evidence, value)
        target = path / 'operations/op-1/manifest.json'
        original = target.read_bytes()
        fsync = os.fsync

        def fail(*a, **k):
            raise OSError('injected failure')

        def sync(fd):
            directory = fs.stat.S_ISDIR(os.fstat(fd).st_mode)
            if directory == (failure == 'directory_fsync'):
                fail()
            fsync(fd)

        with monkeypatch.context() as patch:
            if failure in ('file_fsync', 'directory_fsync'):
                patch.setattr(fs.os, 'fsync', sync)
            else:
                patch.setattr(fs.os, failure, fail)
            with pytest.raises(OSError):
                evidence.update(dict(value, state='completed'))
        if failure != 'directory_fsync':
            assert target.read_bytes() == original
            assert evidence.discover() == {'op-1': 'corrupt'}
        else:
            # Rename is visible, but failed fsync was never reported as durable success.
            assert evidence.discover() == {'op-1': 'completed'}
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


def test_atomic_order_and_replacement(sandbox, monkeypatch):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        target = path / 'operations/op-1/manifest.json'
        inode = target.stat().st_ino
        events = []
        sync, rename = os.fsync, os.rename

        def fsync(fd):
            events.append('directory' if fs.stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
            sync(fd)

        def move(*a, **k):
            events.append('rename')
            rename(*a, **k)

        monkeypatch.setattr(fs.os, 'fsync', fsync)
        monkeypatch.setattr(fs.os, 'rename', move)
        evidence.update(dict(manifest(), state='completed'))
        assert events == ['file', 'rename', 'directory']
        assert target.stat().st_ino != inode


def test_path_replacement_detected_and_lock_retained(sandbox):
    path, _ = sandbox
    with pytest.raises(fs.EvidenceError), locked(sandbox) as evidence:
        (path / 'admin.lock').rename(path / 'old.lock')
        (path / 'admin.lock').touch(mode=0o600)
        with pytest.raises(fs.EvidenceError):
            evidence.discover()


def test_production_walk_uses_fixed_descriptor_components(sandbox, monkeypatch):
    _, base = sandbox
    seen = []
    original = os.open

    def open_fixture(name, flags, *args, **kwargs):
        if name == '/':
            return os.dup(base)
        if name in ('var', 'lib', 'soc-policy-admin'):
            seen.append(name)
            assert flags & os.O_NOFOLLOW
            return os.dup(base)
        return original(name, flags, *args, **kwargs)

    @contextmanager
    def no_lock(fd, check):
        check()
        yield fd

    monkeypatch.setattr(fs.os, 'open', open_fixture)
    monkeypatch.setattr(fs, '_directory',
                        lambda parent, name, **k: fs._open(name, fs.DIR_FLAGS))
    monkeypatch.setattr(fs, '_same', lambda *a, **k: None)
    monkeypatch.setattr(fs, '_locked_at', no_lock)
    with fs.administration():
        assert seen == ['var', 'lib', 'soc-policy-admin']


def test_no_database_or_policy_access(sandbox, monkeypatch):
    import sqlite3

    monkeypatch.setattr(sqlite3, 'connect', lambda *a, **k: pytest.fail('SQLite accessed'))
    original = os.open
    names = []

    def tracked(name, *a, **k):
        names.append(name)
        return original(name, *a, **k)

    monkeypatch.setattr(fs.os, 'open', tracked)
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        evidence.discover()
    assert all(name in ('/', 'source.json', 'candidate.json',
                               'admin.lock', 'operations', 'op-1', 'manifest.json')
               or name.startswith('.manifest-') for name in names)


@pytest.mark.parametrize('attack', ['symlink', 'permissions', 'file'])
def test_directory_attacks(sandbox, attack):
    path, _ = sandbox
    target = path / 'operations'
    if attack == 'symlink':
        (path / 'other').mkdir(mode=0o700)
        target.symlink_to('other')
    elif attack == 'permissions':
        target.mkdir(mode=0o777)
        target.chmod(0o777)
    else:
        target.touch(mode=0o600)
    with pytest.raises((OSError, fs.EvidenceError)), locked(sandbox):
        pass


def test_cross_process_lock(sandbox):
    import multiprocessing

    context = multiprocessing.get_context('fork')
    receiver, sender = context.Pipe(duplex=False)

    def attempt():
        try:
            with locked(sandbox):
                sender.send('acquired')
        except BlockingIOError:
            sender.send('busy')
        finally:
            sender.close()

    with locked(sandbox):
        child = context.Process(target=attempt)
        child.start()
        try:
            assert receiver.poll(5)
            assert receiver.recv() == 'busy'
            child.join(5)
            assert child.exitcode == 0
        finally:
            if child.is_alive():
                child.kill()
                child.join()
            receiver.close()
            sender.close()


@pytest.mark.parametrize('damage', ['symlink', 'hardlink', 'permissions', 'missing'])
def test_manifest_filesystem_attacks(sandbox, damage):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        target = path / 'operations/op-1/manifest.json'
        if damage == 'symlink':
            target.rename(path / 'other')
            target.symlink_to(path / 'other')
        elif damage == 'hardlink':
            os.link(target, path / 'other')
        elif damage == 'permissions':
            target.chmod(0o640)
        else:
            target.unlink()
        assert evidence.discover() == {'op-1': 'corrupt'}
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


def test_rotate_expectations_and_evidence_bound(sandbox, monkeypatch):
    value = dict(manifest(), operation='rotate', expected_generation=1,
                 expected_current_sha256='b' * 64)
    with locked(sandbox) as evidence:
        prepare(evidence, value)
        evidence.update(dict(value, state='completed'))
        monkeypatch.setattr(fs, 'OPERATION_LIMIT', 0)
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


def test_interrupted_initial_manifest(sandbox, monkeypatch):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        def fail(*a, **k):
            raise OSError('interrupted write')

        with monkeypatch.context() as patch:
            patch.setattr(fs.os, 'write', fail)
            with pytest.raises(OSError):
                prepare(evidence, manifest())
        assert evidence.discover() == {'op-1': 'corrupt'}
        assert (path / 'operations/op-1/candidate.json').exists()
        assert not (path / 'operations/op-1/manifest.json').exists()
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


@pytest.mark.parametrize('name', ['operations', 'soc-policy-admin'])
def test_directory_parent_fsync_retry(sandbox, monkeypatch, name):
    path, parent = sandbox
    failure = OSError(5, 'parent sync failed')
    original = os.fsync
    calls = []

    def fail(fd):
        calls.append(fd)
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(fs.os, 'fsync', fail)
        for _ in range(2):
            with pytest.raises(OSError) as caught:
                fs._directory(parent, name, create=True)
            assert caught.value is failure
            assert (path / name).is_dir()
    assert calls == [parent, parent]

    def recovered(fd):
        calls.append(fd)
        original(fd)

    monkeypatch.setattr(fs.os, 'fsync', recovered)
    fd = fs._directory(parent, name, create=True)
    fs._close(fd)
    assert calls == [parent, parent, parent]


def test_fork_guarantees_required_before_access(sandbox, monkeypatch):
    monkeypatch.setattr(fs, '_fork_ready', False)
    monkeypatch.setattr(fs.os, 'open', lambda *a, **k: pytest.fail('Filesystem accessed'))
    with pytest.raises(fs.EvidenceError, match='Fork safety unavailable'), locked(sandbox):
        pass
    with pytest.raises(fs.EvidenceError, match='Fork safety unavailable'), fs.administration():
        pass


def test_inherited_handle_cleanup_and_lock_lifetime(sandbox, monkeypatch):
    import multiprocessing

    context = multiprocessing.get_context('fork')
    parent, child_send = context.Pipe(duplex=False)
    child_receive, parent_send = context.Pipe(duplex=False)
    manager = locked(sandbox)
    evidence = manager.__enter__()
    inode = (sandbox[0] / 'admin.lock').stat().st_ino

    def child():
        try:
            for operation in (evidence.discover,
                              lambda: prepare(evidence, manifest('child')),
                              lambda: evidence.update(manifest()),
                              lambda: evidence._read(-1, 'op-1'),
                              lambda: evidence._write(-1, b'')):
                with pytest.raises(fs.EvidenceError, match='Inherited'):
                    operation()
            # Fresh child acquisition must still contend with the parent's lock.
            with pytest.raises(BlockingIOError), locked(sandbox):
                pass
            # Exiting the inherited context must not close reused descriptor numbers.
            reused = os.dup(sandbox[1])
            try:
                with pytest.raises(fs.EvidenceError, match='Inherited'):
                    manager.__exit__(None, None, None)
                os.fstat(reused)
            finally:
                os.close(reused)
            assert not fs._owned_fds
            child_send.send('rejected')
            assert child_receive.recv() == 'parent preparing'
            with pytest.raises(fs.EvidenceError, match='Inherited'):
                prepare(evidence, manifest('concurrent-child'))
            child_send.send('concurrent prepare rejected')
            assert child_receive.recv() == 'parent exited'
            with locked(sandbox) as fresh:
                assert fresh.discover() == {'op-1': 'unresolved'}
            child_send.send('acquired')
            assert child_receive.recv() == 'finish'
        finally:
            child_send.close()
            child_receive.close()

    process = context.Process(target=child)
    process.start()
    try:
        assert parent.poll(5)
        assert parent.recv() == 'rejected'
        # Child exit did not release the lock; parent can prepare exclusively.
        with pytest.raises(BlockingIOError), locked(sandbox):
            pass
        write = evidence._write

        def during_parent_prepare(directory, data):
            parent_send.send('parent preparing')
            assert parent.poll(5)
            assert parent.recv() == 'concurrent prepare rejected'
            write(directory, data)

        monkeypatch.setattr(evidence, '_write', during_parent_prepare)
        prepare(evidence, manifest())
        manager.__exit__(None, None, None)
        # Child stays alive with its inherited handle: it cannot retain flock.
        with locked(sandbox):
            assert (sandbox[0] / 'admin.lock').stat().st_ino == inode
        parent_send.send('parent exited')
        assert parent.poll(5)
        assert parent.recv() == 'acquired'
        parent_send.send('finish')
        process.join(5)
        assert process.exitcode == 0
    finally:
        if evidence._active:
            manager.__exit__(None, None, None)
        if process.is_alive():
            process.kill()
            process.join()
        parent.close()
        child_send.close()
        child_receive.close()
        parent_send.close()


def _reap(pid, timeout=5):
    """Bounded wait; always reap even when an assertion or child callback fails."""
    import signal
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    pytest.fail('Fork child timed out')


@pytest.mark.parametrize('interval', ['open', 'register', 'deregister',
                                      'before_close', 'after_close'])
def test_signal_fork_descriptor_transition(sandbox, monkeypatch, interval):
    """Real signal -> Python fork at the exact unregistered-open boundary.

    On the old implementation the open child survives, inherits the subsequently
    acquired flock, and blocks acquisition after the parent's context exits.
    """
    import signal

    children = []
    release_read, release_write = os.pipe()
    ready_read, ready_write = os.pipe()
    original_open, original_close = os.open, os.close
    armed = True

    def handler(signum, frame):
        pid = os.fork()
        if pid == 0:
            # Old code resumes here with an untracked fd. Keep it alive until
            # the parent has tested fresh acquisition, with a bounded fallback.
            signal.alarm(10)
            os.write(ready_write, b'R')
            os.read(release_read, 1)
            os._exit(0)
        children.append(pid)

    def trigger():
        nonlocal armed
        if armed:
            armed = False
            signal.raise_signal(signal.SIGUSR1)

    def opened(name, *args, **kwargs):
        fd = original_open(name, *args, **kwargs)
        if name == 'admin.lock':
            trigger()
        return fd

    class Registry(set):
        def add(self, fd):
            trigger()
            super().add(fd)

        def remove(self, fd):
            super().remove(fd)
            trigger()

    def closed(fd):
        if interval == 'before_close':
            trigger()
        original_close(fd)
        if interval == 'after_close':
            trigger()

    previous = signal.signal(signal.SIGUSR1, handler)
    try:
        with monkeypatch.context() as patch:
            if interval == 'open':
                patch.setattr(fs.os, 'open', opened)
            elif interval in ('register', 'deregister'):
                registry = Registry(fs._owned_fds)
                # Trigger only the requested registry operation.
                if interval == 'register':
                    registry.remove = lambda fd: set.remove(registry, fd)
                else:
                    registry.add = lambda fd: set.add(registry, fd)
                patch.setattr(fs, '_owned_fds', registry)
            else:
                patch.setattr(fs.os, 'close', closed)
            with locked(sandbox):
                pass
        assert len(children) == 1
        import select

        original_close(ready_write)
        ready_write = None
        assert select.select([ready_read], [], [], 5)[0]
        resumed = os.read(ready_read, 1)
        status = None
        if not resumed:
            status = _reap(children.pop())
        # A vulnerable child reports R and stays alive through acquisition.
        with locked(sandbox):
            pass
        assert not resumed
        assert status == 1  # Unsafe children must never resume Python code.
        assert fs._fd_transitions == 0
        assert not fs._owned_fds
    finally:
        signal.signal(signal.SIGUSR1, previous)
        os.write(release_write, b'x')
        original_close(release_write)
        for pid in children:
            _reap(pid)
        original_close(release_read)
        original_close(ready_read)
        if ready_write is not None:
            original_close(ready_write)


def test_child_close_failure_is_fatal(sandbox, monkeypatch):
    parent_pid = os.getpid()
    original = os.close

    def close(fd):
        if os.getpid() != parent_pid:
            raise OSError('injected child close failure')
        original(fd)

    with locked(sandbox):
        with monkeypatch.context() as patch:
            patch.setattr(fs.os, 'close', close)
            pid = os.fork()
            if pid == 0:
                os._exit(99)  # Must never resume after a cleanup failure.
            assert _reap(pid) == 1
        with pytest.raises(BlockingIOError), locked(sandbox):
            pass
    with locked(sandbox):
        pass


@pytest.mark.parametrize('failure', [AttributeError, OSError, RuntimeError])
def test_at_fork_registration_failure(sandbox, monkeypatch, failure):
    import runpy

    def fail(**kwargs):
        raise failure('injected registration failure')

    monkeypatch.setattr(os, 'register_at_fork', fail)
    module = runpy.run_path(fs.__file__)
    assert module['_fork_ready'] is False
    monkeypatch.setattr(os, 'getuid', lambda: 0)
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(os, 'open', lambda *a, **k: pytest.fail('Filesystem accessed'))
    with pytest.raises(module['EvidenceError'], match='Fork safety unavailable'):
        with module['_locked_at'](sandbox[1], lambda: None):
            pass


def test_other_thread_fork_waits_for_descriptor_transition(sandbox, monkeypatch):
    import threading

    entered, attempted, release = threading.Event(), threading.Event(), threading.Event()
    original = os.open
    errors = []
    children = []

    def opened(*args, **kwargs):
        fd = original(*args, **kwargs)
        entered.set()
        if not release.wait(5):
            raise TimeoutError('transition release timed out')
        return fd

    def owner():
        try:
            fd = fs._open(sandbox[0], fs.DIR_FLAGS)
            fs._close(fd)
        except BaseException as error:
            errors.append(error)

    def fork():
        try:
            attempted.set()
            pid = os.fork()
            if pid == 0:
                os._exit(0 if not fs._owned_fds else 99)
            children.append(pid)
        except BaseException as error:
            errors.append(error)

    with monkeypatch.context() as patch:
        patch.setattr(fs.os, 'open', opened)
        worker = threading.Thread(target=owner)
        forker = threading.Thread(target=fork)
        worker.start()
        try:
            assert entered.wait(5)
            forker.start()
            assert attempted.wait(5)
            forker.join(0.1)
            assert forker.is_alive()
        finally:
            release.set()
            worker.join(5)
            if forker.ident is not None:
                forker.join(5)
            for pid in children:
                assert _reap(pid) == 0
    assert not worker.is_alive() and not forker.is_alive()
    assert not errors


def test_nested_contexts_fork_cleanup(sandbox):
    path, base = sandbox
    (path / 'nested').mkdir(mode=0o700)
    nested = os.open(path / 'nested', fs.DIR_FLAGS)
    try:
        with locked(sandbox) as outer:
            with fs._locked_at(nested, lambda: None) as inner:
                pid = os.fork()
                if pid == 0:
                    try:
                        for evidence in (outer, inner):
                            with pytest.raises(fs.EvidenceError, match='Inherited'):
                                evidence.discover()
                        for directory in (base, nested):
                            with pytest.raises(BlockingIOError):
                                with fs._locked_at(directory, lambda: None):
                                    pass
                        os._exit(0 if not fs._owned_fds else 98)
                    except BaseException:
                        os._exit(99)
                assert _reap(pid) == 0
                assert outer.discover() == inner.discover() == {}
            with fs._locked_at(nested, lambda: None):
                pass
            with pytest.raises(BlockingIOError), locked(sandbox):
                pass
        with locked(sandbox):
            pass
    finally:
        os.close(nested)


@pytest.mark.parametrize('changes', [
    {'candidate_sha256': '0' * 64}, {'candidate_version': 'review/2'},
    {'candidate_size': 1}, {'version': 1},
])
def test_candidate_expectations_before_creation(sandbox, changes):
    with locked(sandbox) as evidence:
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, dict(manifest(), **changes))
        assert list((sandbox[0] / 'operations').iterdir()) == []


def test_canonical_equivalence_and_tuple_order(sandbox):
    path, _ = sandbox
    value = json.loads(canonical())
    value['principals'] = [[1001, 'operator:second'], [1000, 'operator:first']]
    value['reason_requirements'].reverse()
    value['decisions'].reverse()
    value['version'] = 'review/1'
    raw = json.dumps(value, indent=2, ensure_ascii=False).encode()
    policy, expected = fs._canonical(raw)
    (path / 'source.json').write_bytes(raw)
    metadata = dict(manifest(), candidate_version=policy.version,
                    candidate_size=len(expected),
                    candidate_sha256=hashlib.sha256(expected).hexdigest())
    with locked(sandbox) as evidence:
        prepare(evidence, metadata)
        assert evidence.read_candidate('op-1') == expected
        assert expected.isascii() and not expected.endswith(b'\n')
        assert json.loads(expected)['principals'] == value['principals']
        assert json.loads(expected)['reason_requirements'] == value['reason_requirements']
        target = path / 'operations/op-1/candidate.json'
        before = target.stat()
        evidence.update(dict(metadata, state='completed'))
        after = target.stat()
        assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
        assert target.read_bytes() == expected
        assert after.st_mode & 0o7777 == 0o600
        assert after.st_nlink == 1


@pytest.mark.parametrize('raw', [b'{', b'{}', b'\xff',
                                 canonical().replace(b'completed_preparation', b'unverified'),
                                 canonical() + b' ' * 65536])
def test_invalid_source_before_creation(sandbox, raw):
    (sandbox[0] / 'source.json').write_bytes(raw)
    with locked(sandbox) as evidence:
        with pytest.raises((ValueError, UnicodeError)):
            prepare(evidence, manifest())
        assert evidence.discover() == {}


@pytest.mark.parametrize('path', ['', '/', 'relative', '/a/', '/a//b', '/./b',
                                  '/../b', '/a\x00', '/' + 'é' * 2048])
def test_source_path_contract(sandbox, path):
    with locked(sandbox) as evidence:
        with pytest.raises(ValueError):
            evidence.prepare(manifest(), path)
        assert evidence.discover() == {}


@pytest.mark.parametrize('attack', ['symlink', 'ancestor_symlink', 'ancestor_mode',
                                    'mode', 'hardlink', 'fifo', 'directory', 'socket'])
@pytest.mark.unix_socket
def test_protected_source_attacks(sandbox, attack):
    import socket

    path, _ = sandbox
    source = path / 'source.json'
    source_path = '/source.json'
    sock = None
    if attack.startswith('ancestor'):
        ancestor = path / 'ancestor'
        ancestor.mkdir(mode=0o700)
        source.rename(ancestor / 'source.json')
        source_path = '/ancestor/source.json'
        if attack == 'ancestor_mode':
            ancestor.chmod(0o777)
        else:
            ancestor.rename(path / 'original')
            ancestor.symlink_to('original')
    elif attack == 'symlink':
        source.rename(path / 'original')
        source.symlink_to('original')
    elif attack == 'mode':
        source.chmod(0o666)
    elif attack == 'hardlink':
        os.link(source, path / 'alias')
    else:
        source.unlink()
        if attack == 'fifo':
            os.mkfifo(source, 0o600)
        elif attack == 'directory':
            source.mkdir(mode=0o700)
        else:
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(source))
    try:
        with locked(sandbox) as evidence:
            with pytest.raises((ValueError, OSError)):
                evidence.prepare(manifest(), source_path)
            assert evidence.discover() == {}
    finally:
        if sock:
            sock.close()


@pytest.mark.parametrize('attack', ['replace', 'mutate', 'grow', 'ancestor'])
def test_source_read_races(sandbox, monkeypatch, attack):
    path, _ = sandbox
    ancestor = path / 'ancestor'
    ancestor.mkdir(mode=0o700)
    source = ancestor / 'source.json'
    (path / 'source.json').rename(source)
    read = os.read
    armed = True

    def raced(fd, size):
        nonlocal armed
        data = read(fd, size)
        if armed and os.fstat(fd).st_ino == source.stat().st_ino:
            armed = False
            if attack == 'replace':
                source.rename(ancestor / 'old')
                source.write_bytes(canonical())
                source.chmod(0o600)
            elif attack == 'ancestor':
                ancestor.rename(path / 'old')
                ancestor.mkdir(mode=0o700)
            else:
                source.write_bytes(canonical() + (b' ' if attack == 'grow' else b''))
        return data

    with locked(sandbox) as evidence:
        monkeypatch.setattr(fs.os, 'read', raced)
        with pytest.raises((ValueError, OSError)):
            evidence.prepare(manifest(), '/ancestor/source.json')
        assert evidence.discover() == {}


def test_short_reads_and_partial_writes(sandbox, monkeypatch):
    read, write = os.read, os.write
    monkeypatch.setattr(fs.os, 'read', lambda fd, size: read(fd, min(7, size)))
    monkeypatch.setattr(fs.os, 'write', lambda fd, data: write(fd, data[:5]))
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        assert evidence.read_candidate('op-1') == canonical()


@pytest.mark.parametrize('boundary', range(1, 6))
def test_staging_fsync_failures(sandbox, monkeypatch, boundary):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        sync = os.fsync
        calls = 0

        def failed(fd):
            nonlocal calls
            calls += 1
            if calls == boundary:
                raise OSError('injected staging fsync')
            sync(fd)

        with monkeypatch.context() as patch:
            patch.setattr(fs.os, 'fsync', failed)
            with pytest.raises(OSError):
                prepare(evidence, manifest())
        assert calls == boundary
        operation = path / 'operations/op-1'
        assert operation.is_dir()
        assert (operation / 'manifest.json').exists() == (boundary == 5)
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


@pytest.mark.parametrize('failure', ['zero', 'rename', 'candidate_close', 'verify'])
def test_staging_publication_failures(sandbox, monkeypatch, failure):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        def fail(*args, **kwargs):
            raise OSError('injected staging failure')

        with monkeypatch.context() as patch:
            if failure == 'zero':
                patch.setattr(fs.os, 'write', lambda *args: 0)
            elif failure == 'rename':
                patch.setattr(fs.os, 'rename', fail)
            elif failure == 'verify':
                patch.setattr(evidence, '_verify', fail)
            else:
                close = os.close

                def closed(fd):
                    info = os.fstat(fd)
                    close(fd)
                    if (fs.stat.S_ISREG(info.st_mode)
                            and (path / 'operations/op-1/candidate.json').exists()):
                        fail()

                patch.setattr(fs.os, 'close', closed)
            with pytest.raises(OSError):
                prepare(evidence, manifest())
        assert (path / 'operations/op-1').is_dir()
        assert not (path / 'operations/op-1/manifest.json').exists()
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


@pytest.mark.parametrize('damage', ['missing', 'truncate', 'modify', 'oversize',
                                    'noncanonical', 'extra', 'symlink', 'hardlink', 'mode'])
def test_corrupt_candidates(sandbox, damage):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        target = path / 'operations/op-1/candidate.json'
        if damage == 'missing':
            target.unlink()
        elif damage == 'truncate':
            target.write_bytes(canonical()[:-1])
        elif damage == 'modify':
            target.write_bytes(canonical().replace(b'review/1', b'review/2'))
        elif damage == 'oversize':
            target.write_bytes(b' ' * 65537)
        elif damage == 'noncanonical':
            raw = json.dumps(json.loads(canonical()), indent=1).encode()
            target.write_bytes(raw)
            # Even matching metadata cannot make noncanonical bytes acceptable.
            value = dict(manifest(), candidate_size=len(raw),
                         candidate_sha256=hashlib.sha256(raw).hexdigest())
            (target.parent / 'manifest.json').write_bytes(fs._manifest(value))
        elif damage == 'extra':
            (target.parent / 'unexpected').touch()
        elif damage == 'symlink':
            target.rename(path / 'original')
            target.symlink_to(path / 'original')
        elif damage == 'hardlink':
            os.link(target, path / 'alias')
        else:
            target.chmod(0o640)
        assert evidence.discover() == {'op-1': 'corrupt'}
        with pytest.raises((ValueError, OSError)):
            evidence.read_candidate('op-1')
        with pytest.raises((ValueError, OSError)):
            evidence.update(dict(manifest(), state='completed'))
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))


@pytest.mark.parametrize('state', ['prepared', 'completed'])
def test_legacy_metadata_only(sandbox, state):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        value = dict(manifest(), version=1, state=state)
        operation = path / 'operations/op-1'
        operation.mkdir(mode=0o700)
        (operation / 'manifest.json').write_bytes(fs._manifest(value))
        (operation / 'manifest.json').chmod(0o600)
        classification = 'completed' if state == 'completed' else 'unresolved'
        assert evidence.discover() == {'op-1': classification}
        with pytest.raises(fs.EvidenceError, match='Legacy'):
            evidence.read_candidate('op-1')
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest('op-2'))
        if state == 'prepared':
            evidence.update(dict(value, state='completed'))
            assert evidence.discover() == {'op-1': 'completed'}


def _sized_policy(size):
    value = json.loads(canonical())
    value['principals'] = [[uid, 'p' * 240] for uid in range(280)]
    value['principals'].append([1000, 'p'])
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    while len(data) > size:
        value['principals'].pop(0)
        data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    value['principals'][-1][1] += 'p' * (size - len(data))
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    assert len(data) == size
    return data


@pytest.mark.parametrize('size', [65535, 65536, 65537])
def test_canonical_size_boundary(sandbox, size):
    raw = _sized_policy(size)
    (sandbox[0] / 'source.json').write_bytes(raw)
    value = dict(manifest(), candidate_size=min(size, 65536),
                 candidate_sha256=hashlib.sha256(raw).hexdigest())
    with locked(sandbox) as evidence:
        if size > 65536:
            with pytest.raises(ValueError):
                prepare(evidence, value)
            assert evidence.discover() == {}
        else:
            prepare(evidence, value)
            assert evidence.read_candidate('op-1') == raw


@pytest.mark.parametrize('size', [65536, 65537])
def test_raw_size_boundary(sandbox, size):
    (sandbox[0] / 'source.json').write_bytes(canonical().ljust(size, b' '))
    with locked(sandbox) as evidence:
        if size > 65536:
            with pytest.raises(ValueError):
                prepare(evidence, manifest())
            assert evidence.discover() == {}
        else:
            prepare(evidence, manifest())
            assert evidence.read_candidate('op-1') == canonical()


def test_exclusive_candidate_creation(sandbox, monkeypatch):
    path, _ = sandbox
    opened = fs._open

    def raced(name, *args, **kwargs):
        if name == 'candidate.json' and args[0] & os.O_CREAT:
            target = path / 'operations/op-1/candidate.json'
            target.write_bytes(b'existing')
            target.chmod(0o600)
        return opened(name, *args, **kwargs)

    with locked(sandbox) as evidence:
        monkeypatch.setattr(fs, '_open', raced)
        with pytest.raises(FileExistsError):
            prepare(evidence, manifest())
        assert (path / 'operations/op-1/candidate.json').read_bytes() == b'existing'
        assert evidence.discover() == {'op-1': 'corrupt'}


def test_premature_eof_rejected(sandbox, monkeypatch):
    with locked(sandbox) as evidence:
        monkeypatch.setattr(fs.os, 'read', lambda *args: b'')
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest())
        assert evidence.discover() == {}


@pytest.mark.parametrize('stage', ['source', 'candidate'])
def test_fork_closes_staging_descriptors(sandbox, monkeypatch, stage):
    read = os.read
    fired = False

    def forked(fd, size):
        nonlocal fired
        if not fired and (stage == 'source' or
                          (sandbox[0] / 'operations/op-1/candidate.json').exists()):
            fired = True
            owned = tuple(fs._owned_fds)
            pid = os.fork()
            if pid == 0:
                if fs._owned_fds:
                    os._exit(2)
                for inherited in owned:
                    try:
                        os.fstat(inherited)
                    except OSError:
                        continue
                    os._exit(3)
                os._exit(0)
            assert _reap(pid) == 0
        return read(fd, size)

    with locked(sandbox) as evidence:
        monkeypatch.setattr(fs.os, 'read', forked)
        prepare(evidence, manifest())
        assert fired
        assert evidence.read_candidate('op-1') == canonical()


@pytest.mark.parametrize('mode', [0o601, 0o4600, 0o2600, 0o1600, 0o620])
def test_unsafe_source_modes(sandbox, mode):
    (sandbox[0] / 'source.json').chmod(mode)
    with locked(sandbox) as evidence:
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest())
        assert evidence.discover() == {}


@pytest.mark.parametrize('stage', ['parse', 'publication'])
def test_candidate_changed_during_verification(sandbox, monkeypatch, stage):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        prepare(evidence, manifest())
        candidate = path / 'operations/op-1/candidate.json'
        if stage == 'parse':
            binding = fs._binding

            def changed(*args):
                binding(*args)
                candidate.write_bytes(canonical())

            monkeypatch.setattr(fs, '_binding', changed)
            with pytest.raises(fs.EvidenceError):
                evidence.read_candidate('op-1')
        else:
            write = evidence._write

            def replaced(*args):
                write(*args)
                candidate.unlink()
                candidate.write_bytes(canonical())
                candidate.chmod(0o600)

            monkeypatch.setattr(evidence, '_write', replaced)
            with pytest.raises(fs.EvidenceError):
                evidence.update(dict(manifest(), state='completed'))


def test_source_ownership(sandbox, monkeypatch):
    inode = (sandbox[0] / 'source.json').stat().st_ino
    original = fs.os.fstat

    def wrong_owner(fd):
        info = original(fd)
        if info.st_ino == inode:
            values = list(info)
            values[4] = 123456
            return os.stat_result(values)
        return info

    with locked(sandbox) as evidence:
        monkeypatch.setattr(fs.os, 'fstat', wrong_owner)
        with pytest.raises(fs.EvidenceError):
            prepare(evidence, manifest())
        assert evidence.discover() == {}


def _inode_fds(directory):
    """Inspect Linux's actual fd table, independently of the module registry."""
    identity = os.fstat(directory)
    found = set()
    for name in os.listdir('/proc/self/fd'):
        try:
            info = os.fstat(int(name))
        except OSError:
            continue  # The proc enumeration's own descriptor has closed.
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            found.add(int(name))
    return found


def test_runtime_scandir_alias_lifetime(sandbox):
    _, directory = sandbox
    before = _inode_fds(directory)
    iterator = os.scandir(directory)
    aliases = _inode_fds(directory) - before
    assert len(aliases) == 1
    alias = aliases.pop()
    # A real child inherits this unregistered alias even though callbacks run.
    pid = os.fork()
    if pid == 0:
        os._exit(0 if alias in _inode_fds(directory) else 2)
    assert _reap(pid) == 0
    iterator.close()
    assert _inode_fds(directory) == before
    with os.scandir(directory) as iterator:
        assert len(_inode_fds(directory) - before) == 1
        list(iterator)
        assert _inode_fds(directory) == before  # Exhaustion releases it too.
    original = os.dup(directory)
    iterator = os.scandir(original)
    os.close(original)
    try:
        assert len(_inode_fds(directory) - before) == 1
        assert list(iterator)
    finally:
        iterator.close()
    assert _inode_fds(directory) == before


@pytest.mark.parametrize('operation', ['discover', 'verify', 'lifetime'])
@pytest.mark.parametrize('stage', ['construct_before', 'construct_after', 'open',
                                   'iterate', 'close_before', 'close_after', 'signal'])
def test_enumeration_fork_boundary(sandbox, monkeypatch, operation, stage):
    import signal

    children = []
    reports_read, reports_write = os.pipe()
    real_exit = os._exit
    real_scandir = os.scandir
    fired = False
    target = None
    expected_alias = False

    def inspected_exit(status):
        # Runs inside the fatal child callback, before process exit. Confirm the
        # actual inherited alias is usable; only process termination removes it.
        aliases = _inode_fds(target) - fs._owned_fds - {target}
        usable = any(os.stat('.', dir_fd=fd).st_ino == os.fstat(target).st_ino
                     for fd in aliases)
        os.write(reports_write, b'A' if usable else b'N')
        real_exit(status)

    def fork_now(*args):
        nonlocal fired, expected_alias
        if fired:
            return
        fired = True
        expected_alias = bool(_inode_fds(target) - fs._owned_fds - {target})
        pid = os.fork()
        if pid == 0:
            os.write(reports_write, b'S')  # A surviving child is always a failure.
            real_exit(99)
        children.append(pid)

    class Iterator:
        def __init__(self, directory):
            if stage == 'construct_before':
                fork_now()
            self.iterator = real_scandir(directory)
            if stage == 'construct_after':
                fork_now()

        def __enter__(self):
            if stage == 'open':
                fork_now()
            if stage == 'signal':
                signal.raise_signal(signal.SIGUSR1)
            return self

        def __iter__(self):
            return self

        def __next__(self):
            if stage == 'iterate':
                fork_now()
            return next(self.iterator)

        def __exit__(self, *args):
            if stage == 'close_before':
                fork_now()
            self.iterator.close()
            if stage == 'close_after':
                fork_now()

    previous = signal.signal(signal.SIGUSR1, fork_now)
    try:
        with locked(sandbox) as evidence:
            prepare(evidence, manifest())
            target = evidence._fd
            if operation == 'verify':
                target = fs._directory(evidence._fd, 'op-1')
            baseline = set(os.listdir('/proc/self/fd'))
            try:
                with monkeypatch.context() as patch:
                    patch.setattr(fs.os, 'scandir', Iterator)
                    patch.setattr(fs.os, '_exit', inspected_exit)
                    if operation == 'discover':
                        assert evidence.discover() == {'op-1': 'unresolved'}
                    elif operation == 'verify':
                        fs._entries(target, {'manifest.json', 'candidate.json'})
                    else:
                        with fs._scandir(target) as entries:
                            next(entries)
                assert fired
                assert _reap(children.pop()) == 1
                import select

                assert select.select([reports_read], [], [], 5)[0]
                report = os.read(reports_read, 1)
                assert report == (b'A' if expected_alias else b'N')
                assert fs._fd_transitions == 0
                assert set(os.listdir('/proc/self/fd')) == baseline
                with pytest.raises(BlockingIOError), locked(sandbox):
                    pass
                assert evidence.read_candidate('op-1') == canonical()
            finally:
                if operation == 'verify':
                    fs._close(target)
        with locked(sandbox):
            pass
    finally:
        signal.signal(signal.SIGUSR1, previous)
        for pid in children:
            _reap(pid)
        os.close(reports_read)
        os.close(reports_write)


@pytest.mark.parametrize('failure', ['construction', 'iteration', 'body', 'close'])
def test_enumeration_exception_cleanup(sandbox, monkeypatch, failure):
    real_scandir = os.scandir
    before = set(os.listdir('/proc/self/fd'))
    depth = fs._fd_transitions

    class Iterator:
        def __init__(self, directory):
            if failure == 'construction':
                raise RuntimeError('injected')
            self.iterator = real_scandir(directory)

        def __enter__(self):
            return self

        def __iter__(self):
            return self

        def __next__(self):
            raise RuntimeError('injected')

        def __exit__(self, *args):
            self.iterator.close()
            if failure == 'close':
                raise RuntimeError('injected')

    monkeypatch.setattr(fs.os, 'scandir', Iterator)
    with pytest.raises(RuntimeError), fs._scandir(sandbox[1]) as entries:
        if failure == 'body':
            raise RuntimeError('injected')
        if failure == 'iteration':
            next(entries)
    assert fs._fd_transitions == depth
    assert set(os.listdir('/proc/self/fd')) == before


def test_enumeration_exception_unwinding_fork(sandbox, monkeypatch):
    """Fork while an enumeration error unwinds, before runtime alias close."""
    import select
    import subprocess
    import sys

    real_scandir = os.scandir
    real_exit = os._exit
    children = []
    reports_read, reports_write = os.pipe()
    error = RuntimeError('injected enumeration failure')
    depth = fs._fd_transitions
    iterators = []
    aliases = set()
    target = None

    def lock_probe(expected):
        # A fresh interpreter uses its own open file description. It must not
        # inherit the parent's lock or execute the unsafe-depth fork callback.
        result = subprocess.run(  # noqa: S603 - fixed code and disposable fixture path
            [sys.executable, '-c',
             'import fcntl, os, sys\n'
             'fd = os.open(sys.argv[1], os.O_RDWR)\n'
             'try:\n'
             '    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n'
             'except BlockingIOError:\n'
             '    sys.exit(23)\n'
             'finally:\n'
             '    os.close(fd)\n',
             str(sandbox[0] / 'admin.lock')],
            close_fds=True, capture_output=True, timeout=5, check=False)
        assert result.returncode == expected, result.stderr

    def inspected_exit(status):
        # This runs only inside the established at-fork fatal callback. Prove
        # the exact runtime alias still exists and is usable before termination.
        live = aliases <= _inode_fds(target)
        usable = all(os.stat('.', dir_fd=fd).st_ino == os.fstat(target).st_ino
                     for fd in aliases)
        os.write(reports_write, b'A' if aliases and live and usable else b'N')
        real_exit(status)

    class Iterator:
        def __init__(self, directory):
            self.iterator = real_scandir(directory)
            self.closed = False
            self.advanced = False
            iterators.append(self)

        def __enter__(self):
            return self

        def __iter__(self):
            return self

        def __next__(self):
            # Advance the actual iterator without exhausting it, then fail on
            # the next step so this is active enumeration, not a body error.
            if not self.advanced:
                self.advanced = True
                return next(self.iterator)
            raise error

        def __exit__(self, exc_type, exc, traceback):
            try:
                assert exc_type is RuntimeError and exc is error
                assert traceback is not None and self.advanced and not self.closed
                aliases.update(_inode_fds(target) - before_aliases)
                assert len(aliases) == 1
                transition_depth = fs._fd_transitions
                lock_probe(23)
                pid = os.fork()
                if pid == 0:
                    os.write(reports_write, b'S')  # Forbidden Python continuation.
                    real_exit(99)
                children.append(pid)
                try:
                    status = _reap(pid)
                finally:
                    children.remove(pid)
                assert status == 1
                assert select.select([reports_read], [], [], 5)[0]
                assert os.read(reports_read, 16) == b'A'
                assert transition_depth == depth + 1
                assert aliases <= _inode_fds(target)  # Parent alias still live.
                lock_probe(23)  # Child exit must not unlock the parent's flock.
            finally:
                self.iterator.close()
                self.closed = True

    try:
        with locked(sandbox) as evidence:
            prepare(evidence, manifest())
            target = evidence._fd
            before_aliases = _inode_fds(target)
            before_fds = set(os.listdir('/proc/self/fd'))
            with monkeypatch.context() as patch:
                patch.setattr(fs.os, 'scandir', Iterator)
                patch.setattr(fs.os, '_exit', inspected_exit)
                with pytest.raises(RuntimeError, match='injected enumeration failure') as raised:
                    fs._entries(target, {'op-1'})
            assert raised.value is error
            assert len(iterators) == 1 and iterators[0].closed
            assert _inode_fds(target) == before_aliases
            assert set(os.listdir('/proc/self/fd')) == before_fds
            assert fs._fd_transitions == depth
            lock_probe(23)
            assert evidence.read_candidate('op-1') == canonical()
        lock_probe(0)
        with locked(sandbox):
            pass
    finally:
        for pid in children:
            _reap(pid)
        os.close(reports_read)
        os.close(reports_write)
