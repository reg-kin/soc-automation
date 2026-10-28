"""Disposable descriptor fixtures; no root privileges or production access required."""

import json
import os
from contextlib import contextmanager

import pytest

from soc_automation import policy_admin_fs as fs


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
    fd = os.open(tmp_path, fs.DIR_FLAGS)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def manifest(name='op-1'):
    return dict(version=1, operation_id=name, operation='install', change_reference='CHG:1',
                state='prepared', expected_generation=0, expected_current_sha256=None,
                candidate_sha256='a' * 64, candidate_version='review/1', candidate_size=123)


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
            evidence.prepare(manifest(name))
        assert evidence.discover() == {}


def test_lifecycle_exclusivity_and_immutable_metadata(sandbox):
    with locked(sandbox) as evidence:
        value = manifest()
        evidence.prepare(value)
        assert evidence.discover() == {'op-1': 'unresolved'}
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(manifest('op-2'))
        with pytest.raises(fs.EvidenceError):
            evidence.update(dict(value, candidate_sha256='b' * 64, state='completed'))
        evidence.update(dict(value, state='completed'))
        assert evidence.discover() == {'op-1': 'completed'}
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(value)
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(manifest('op-2'))
    with locked(sandbox) as evidence:
        assert evidence.discover() == {'op-1': 'completed'}


@pytest.mark.parametrize('damage', [b'', b'{', b'{}', b'{"version":1,"version":1}',
                                    b'x' * 4097, b'\xff'])
def test_corrupt_manifest(sandbox, damage):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        evidence.prepare(manifest())
        (path / 'operations/op-1/manifest.json').write_bytes(damage)
        assert evidence.discover() == {'op-1': 'corrupt'}
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(manifest('op-2'))


@pytest.mark.parametrize('changes', [
    {'version': True}, {'version': 2}, {'state': 'committed'}, {'extra': 'x'},
    {'operation': 'recover'}, {'expected_generation': True}, {'expected_generation': 1},
    {'expected_current_sha256': 'a' * 64}, {'candidate_size': 65537},
    {'candidate_sha256': 'A' * 64}, {'candidate_version': 'x' * 257},
    {'candidate_version': '\n'}, {'candidate_size': 1.0},
])
def test_strict_manifest(sandbox, changes):
    with locked(sandbox) as evidence:
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(dict(manifest(), **changes))
        assert evidence.discover() == {}


def test_contradictory_identity_and_extra_entries(sandbox):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        evidence.prepare(manifest())
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
        evidence.prepare(value)
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
            evidence.prepare(manifest('op-2'))


def test_atomic_order_and_replacement(sandbox, monkeypatch):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        evidence.prepare(manifest())
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
        evidence.prepare(manifest())
        evidence.discover()
    assert all(name in ('admin.lock', 'operations', 'op-1', 'manifest.json')
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
        evidence.prepare(manifest())
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
            evidence.prepare(manifest('op-2'))


def test_rotate_expectations_and_evidence_bound(sandbox, monkeypatch):
    value = dict(manifest(), operation='rotate', expected_generation=1,
                 expected_current_sha256='b' * 64)
    with locked(sandbox) as evidence:
        evidence.prepare(value)
        evidence.update(dict(value, state='completed'))
        monkeypatch.setattr(fs, 'OPERATION_LIMIT', 0)
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(manifest('op-2'))


def test_interrupted_initial_manifest(sandbox, monkeypatch):
    path, _ = sandbox
    with locked(sandbox) as evidence:
        def fail(*a, **k):
            raise OSError('interrupted write')

        with monkeypatch.context() as patch:
            patch.setattr(fs.os, 'write', fail)
            with pytest.raises(OSError):
                evidence.prepare(manifest())
        assert evidence.discover() == {'op-1': 'corrupt'}
        assert any(p.name.startswith('.manifest-') for p in (path / 'operations/op-1').iterdir())
        with pytest.raises(fs.EvidenceError):
            evidence.prepare(manifest('op-2'))


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
                              lambda: evidence.prepare(manifest('child')),
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
                evidence.prepare(manifest('concurrent-child'))
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
        evidence.prepare(manifest())
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
