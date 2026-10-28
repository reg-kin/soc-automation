"""Offline deployment checks: no host accounts, ownership changes or systemd required."""

import os
import shlex
import signal
import sqlite3
import subprocess
import sys
from configparser import ConfigParser
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_automation import approval_daemon as daemon
from soc_automation.approval_policy import PolicySource
from soc_automation.state import StateError, Store


def test_unit_and_actual_launcher_arguments(monkeypatch):
    unit = ConfigParser(interpolation=None)
    unit.read(Path(__file__).parents[1] / 'deploy/soc-approval.service')
    service = unit['Service']
    assert service['Type'] == 'notify'
    assert service['NotifyAccess'] == 'main'
    assert service['User'] == 'soc-automation'
    assert service['Group'] == 'soc-approval-operators'
    assert service['SupplementaryGroups'] == 'soc-automation'
    assert service['RuntimeDirectoryMode'] == '0750'
    assert service['RuntimeDirectoryPreserve'] == 'yes'
    assert service['StateDirectoryMode'] == '0700'
    assert service['UMask'] == '0077'
    assert service['CapabilityBoundingSet'] == service['AmbientCapabilities'] == ''
    assert service['RestrictAddressFamilies'] == 'AF_UNIX'
    assert service['IPAddressDeny'] == 'any'
    assert service['ProtectSystem'] == 'strict'
    assert service['ReadWritePaths'] == '/var/lib/soc-automation /run/soc-approval'
    assert service['Restart'] == 'on-failure'
    assert service['TimeoutStartSec'] == '30'
    assert service['TimeoutStopSec'] == '10'
    assert 'EnvironmentFile' not in service
    calls = []
    monkeypatch.setattr(daemon, 'notify_ready', lambda: calls.append('ready'))
    monkeypatch.setattr(daemon, 'composition', lambda: (None, None, None))

    class Service:
        def __init__(self, *args):
            import threading
            self.stopping = threading.Event()

        def start(self):
            calls.append('start')

        def serve_forever(self):
            # Exercise the real installed handler outside close's lock-taking path.
            signal.raise_signal(signal.SIGTERM)
            assert self.stopping.is_set()
            calls.append('serve')

        def close(self):
            calls.append('close')

    monkeypatch.setattr(daemon, 'ApprovalSocketService', Service)
    for field, expected in [('ExecStartPre', []),
                            ('ExecStart', ['start', 'ready', 'serve', 'close'])]:
        args = shlex.split(service[field])
        assert args[:4] == ['/opt/soc-automation/.venv/bin/python', '-I', '-m',
                            'soc_automation.approval_daemon']
        calls.clear()
        assert daemon.main(args[4:]) == 0
        assert calls == expected


def test_root_refused_before_state_access(monkeypatch):
    monkeypatch.setattr(daemon.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=1234))
    monkeypatch.setattr(daemon.grp, 'getgrnam', lambda _: SimpleNamespace(gr_gid=1234))
    monkeypatch.setattr(daemon.os, 'getuid', lambda: 0)
    monkeypatch.setattr(daemon, 'Store', lambda *_a, **_k: pytest.fail('state accessed'))
    assert daemon.main(['--check']) == 1


def test_unknown_configuration_rejected():
    with pytest.raises(SystemExit):
        daemon.main(['--policy', '/untrusted/policy'])


@pytest.fixture
def deployment(monkeypatch, request):
    # Reuse the real protected-home fixture; /tmp ancestors are intentionally untrusted.
    root, policy, source, store, _ = request.getfixturevalue('setup')
    runtime = root / 'run'
    runtime.mkdir(mode=0o750)
    store.path.chmod(0o600)
    monkeypatch.setattr(daemon, 'DATABASE', store.path)
    monkeypatch.setattr(daemon, 'POLICY', source.path)
    monkeypatch.setattr(daemon, 'SOCKET', runtime / 'operator.sock')
    monkeypatch.setattr(daemon.pwd, 'getpwnam',
                        lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(daemon.grp, 'getgrnam',
                        lambda _: SimpleNamespace(gr_gid=os.getgid()))
    # Test administrator is this unprivileged account, as in existing protected-path tests.
    monkeypatch.setattr(daemon, 'PolicySource',
                        lambda path: PolicySource(path, owner_uid=os.getuid()))
    return root, policy, source, store, runtime


# Register the existing fixture without replacing any protected-path validation.
from test_approval_socket import setup  # noqa: E402, F401


def test_preflight_readonly_no_listener_or_mutations(deployment):
    _, _, _, store, runtime = deployment
    before = store.path.read_bytes()
    assert daemon.main(['--check']) == 0
    assert list(runtime.iterdir()) == []
    assert store.path.read_bytes() == before


@pytest.mark.parametrize('item,mode', [('database', 0o640), ('directory', 0o750),
                                      ('runtime', 0o770), ('policy', 0o620), ('policy', 0o644)])
def test_unsafe_permissions_rejected(deployment, item, mode):
    _, _, source, store, runtime = deployment
    path = {'database': store.path, 'directory': store.path.parent,
            'runtime': runtime, 'policy': source.path}[item]
    path.chmod(mode)
    assert daemon.main(['--check']) == 1
    assert not (runtime / 'operator.sock').exists()


def test_policy_generation_mismatch_rejected(deployment):
    _, _, source, store, runtime = deployment
    source.path.write_text(source.path.read_text().replace('review/1', 'review/2'))
    before = store.path.read_bytes()
    assert daemon.main(['--check']) == 1
    assert store.path.read_bytes() == before
    assert list(runtime.iterdir()) == []


@pytest.mark.parametrize('legacy', ['missing', 'weaker_trigger', 'wrong_columns', 'extra_trigger'])
def test_schema10_legacy_fails_without_repair(tmp_path, legacy):
    store = Store(tmp_path / 'legacy.db')
    store.initialize()
    with sqlite3.connect(store.path) as conn:
        if legacy == 'missing':
            conn.execute('DROP TABLE review_policy_generations')
        elif legacy == 'weaker_trigger':
            conn.execute('DROP TRIGGER policy_generation_insert')
            conn.execute('CREATE TRIGGER policy_generation_insert BEFORE INSERT '
                         'ON review_policy_generations BEGIN SELECT 1; END')
        elif legacy == 'wrong_columns':
            conn.execute('ALTER TABLE review_policy_generations ADD COLUMN legacy TEXT')
        else:
            conn.execute('CREATE TRIGGER unexpected AFTER INSERT '
                         'ON review_policy_generations BEGIN SELECT 1; END')
    before = store.path.read_bytes()
    for action in (store.healthcheck, store.initialize):
        with pytest.raises(StateError, match='Migration 010 schema incompatible'):
            action()
        assert store.path.read_bytes() == before


def test_fresh_and_schema9_upgrade(tmp_path):
    store = Store(tmp_path / 'fresh.db')
    store.initialize()
    store.healthcheck()
    with sqlite3.connect(store.path) as conn:
        conn.execute('DROP TABLE review_policy_generations')
        conn.execute('PRAGMA user_version=9')
    store.initialize()
    store.healthcheck()
    with store._connection(readonly=True) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 10
        assert conn.execute('SELECT count(*) FROM review_policy_generations').fetchone()[0] == 0


@pytest.mark.unix_socket
def test_real_launcher_socket_lifecycle_has_no_state_side_effects(deployment, monkeypatch):
    _, _, _, store, runtime = deployment
    before = store.path.read_bytes()

    def bounded_loop(service):
        assert service.settings.special_uids == frozenset()
        assert service.settings.path.stat().st_mode & 0o777 == 0o660
        assert (runtime / 'operator.sock.lock').stat().st_mode & 0o777 == 0o600
        service.stopping.set()

    monkeypatch.setattr(daemon.ApprovalSocketService, 'serve_forever', bounded_loop)
    assert daemon.main([]) == 0
    assert not (runtime / 'operator.sock').exists()
    assert (runtime / 'operator.sock.lock').exists()
    assert store.path.read_bytes() == before


def test_supervisor_ready_notification(monkeypatch):
    sent = []

    class Notification:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def settimeout(self, seconds):
            assert seconds == 1

        def connect(self, address):
            sent.append(address)

        def sendall(self, data):
            sent.append(data)

    def create(family, kind):
        assert family == daemon.socket.AF_UNIX
        assert kind == daemon.socket.SOCK_DGRAM
        return Notification()

    monkeypatch.setattr(daemon.socket, 'socket', create)
    monkeypatch.setenv('NOTIFY_SOCKET', '@test-supervisor')
    daemon.notify_ready()
    assert sent == ['\0test-supervisor', b'READY=1']
    sent.clear()
    monkeypatch.delenv('NOTIFY_SOCKET')
    daemon.notify_ready()
    assert sent == []


@pytest.mark.parametrize('kind', ['symlink', 'readable'])
def test_unsafe_sidecar_rejected(deployment, kind):
    root, _, _, store, _ = deployment
    sidecar = Path(str(store.path) + '-journal')
    if kind == 'symlink':
        sidecar.symlink_to(root / 'untrusted')
    else:
        sidecar.write_bytes(b'')
        sidecar.chmod(0o640)
    assert daemon.main(['--check']) == 1


def test_missing_operator_group_rejected(deployment, monkeypatch):
    monkeypatch.setattr(daemon.grp, 'getgrnam', lambda _: SimpleNamespace(gr_gid=123456))
    assert daemon.main(['--check']) == 1


def filesystem_snapshot(root):
    return {str(path.relative_to(root)): (path.read_bytes() if path.is_file() else None,
            path.stat().st_ino, path.stat().st_mode, path.stat().st_size,
            path.stat().st_mtime_ns, path.stat().st_ctime_ns)
            for path in root.rglob('*')}


@pytest.mark.parametrize('scenario', ['fresh', 'wal', 'committed', 'missing_shm',
                                      'schema', 'policy', 'wal_schema'])
def test_confined_preflight_filesystem_and_wal(deployment, scenario):
    from dataclasses import replace

    from soc_automation.approval import _policy_content

    root, policy, source, store, _ = deployment
    connection = None
    try:
        if scenario in {'wal', 'committed', 'missing_shm', 'wal_schema'}:
            connection = subprocess.Popen(  # noqa: S603 - fixed script, temporary database only
                [sys.executable, '-c',
                 "import sqlite3,sys; "
                 "c=sqlite3.connect(sys.argv[1]); "
                 "c.execute('PRAGMA journal_mode=WAL'); "
                 "c.execute('PRAGMA wal_autocheckpoint=0'); "
                 "c.execute('PRAGMA user_version='+sys.argv[2]); c.commit(); "
                 "print('ready',flush=True); sys.stdin.read(); c.close()",
                 str(store.path), '999' if scenario == 'wal_schema' else '10'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            assert connection.stdout.readline() == 'ready\n'
            if scenario == 'committed':
                policy = replace(policy, version='review/2')
                store.install_review_policy(policy, expected_generation=1)
                source.path.write_text(_policy_content(policy))
            for suffix in ('-wal', '-shm'):
                Path(str(store.path) + suffix).chmod(0o600)
            assert Path(str(store.path) + '-wal').stat().st_size > 0
            if scenario == 'missing_shm':
                Path(str(store.path) + '-shm').unlink()
        elif scenario == 'schema':
            with sqlite3.connect(store.path) as conn:
                conn.execute('DROP TRIGGER policy_generation_insert')
        elif scenario == 'policy':
            source.path.write_text(source.path.read_text().replace('review/1', 'review/2'))
        before = filesystem_snapshot(root)
        expected = 1 if scenario in {'missing_shm', 'schema', 'policy', 'wal_schema'} else 0
        assert daemon.main(['--check']) == expected
        assert filesystem_snapshot(root) == before
    finally:
        if connection is not None:
            connection.communicate(timeout=5)
            assert connection.returncode == 0


def test_preflight_sandbox_unavailable_fails_closed(deployment, monkeypatch):
    root, *_ = deployment

    def unavailable():
        raise OSError('Landlock unavailable')

    monkeypatch.setattr(daemon, 'restrict_filesystem_writes', unavailable)
    monkeypatch.setattr(daemon, 'composition', lambda: pytest.fail('unconfined inspection'))
    before = filesystem_snapshot(root)
    assert daemon.main(['--check']) == 1
    assert filesystem_snapshot(root) == before


@pytest.mark.unix_socket
@pytest.mark.parametrize('failure', ['composition', 'construction', 'socket', 'notify',
                                     'runtime', 'cleanup', 'listen'])
def test_launcher_failures_release_listener(deployment, monkeypatch, failure):
    _, _, _, _, runtime = deployment
    ready = []
    instances = []
    original = daemon.ApprovalSocketService
    original_composition = daemon.composition
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def fail():
        raise OSError('injected failure')

    def compose():
        if failure == 'composition':
            fail()
        return original_composition()

    class Service(original):
        def __init__(self, *args):
            if failure == 'construction':
                fail()
            super().__init__(*args)
            instances.append(self)

        def start(self):
            if failure == 'socket':
                # Existing paths must survive even the launcher's cleanup path.
                (runtime / 'operator.sock').write_text('foreign artifact')
            return super().start()

        def serve_forever(self):
            if failure == 'runtime':
                fail()

        def close(self):
            super().close()
            if failure == 'cleanup':
                fail()

    def notify():
        if failure == 'notify':
            fail()
        ready.append(True)

    monkeypatch.setattr(daemon, 'composition', compose)
    monkeypatch.setattr(daemon, 'ApprovalSocketService', Service)
    if failure in {'listen', 'notify'}:
        real_socket = daemon.socket.socket

        class BrokenSocket:
            def __init__(self, wrapped=None):
                self.wrapped = wrapped

            def __getattr__(self, name):
                return getattr(self.wrapped, name)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                if self.wrapped is not None:
                    self.wrapped.close()

            def settimeout(self, _seconds):
                pass

            def connect(self, _address):
                fail()

            def listen(self, *_args):
                fail()

        def create(family, kind):
            if kind == daemon.socket.SOCK_DGRAM:
                return BrokenSocket()
            listener = real_socket(family, kind)
            return BrokenSocket(listener) if failure == 'listen' else listener

        monkeypatch.setattr(daemon.socket, 'socket', create)
    if failure == 'notify':
        monkeypatch.setenv('NOTIFY_SOCKET', str(runtime / 'absent-supervisor'))
    else:
        monkeypatch.setattr(daemon, 'notify_ready', notify)
    assert daemon.main([]) == 1
    assert ready == ([True] if failure in {'runtime', 'cleanup'} else [])
    assert {sig: signal.getsignal(sig) for sig in handlers} == handlers
    for instance in instances:
        assert instance.directory is None
        assert instance.listener is None or instance.listener.fileno() == -1
    if failure == 'socket':
        assert (runtime / 'operator.sock').read_text() == 'foreign artifact'
    else:
        assert not (runtime / 'operator.sock').exists()


@pytest.mark.parametrize('target', ['main.db', 'main.db-wal', 'main.db-shm', 'policy.json'])
@pytest.mark.parametrize('operation', ['write', 'create', 'truncate', 'rename', 'unlink',
                                       'link', 'mapping', 'inherited'])
def test_landlock_content_and_namespace_denials(tmp_path, target, operation):
    import errno
    import mmap

    from soc_automation.preflight import close_inherited_descriptors, restrict_filesystem_writes

    state = tmp_path / 'state'
    policy = tmp_path / 'policy'
    state.mkdir()
    policy.mkdir()
    path = (policy if target == 'policy.json' else state) / target
    if target == 'main.db':
        with sqlite3.connect(path) as conn:
            conn.execute('CREATE TABLE example(value)')
    else:
        path.write_bytes(b'x' * 4096)
    before = filesystem_snapshot(tmp_path)
    inherited = os.open(path, os.O_RDWR)
    pid = os.fork()
    if pid == 0:
        try:
            # Deliberately put writable protected files in all standard slots too.
            for fd in (0, 1, 2):
                os.dup2(inherited, fd)
            close_inherited_descriptors()
            restrict_filesystem_writes()
            if operation == 'inherited':
                for fd in (0, 1, 2, inherited):
                    try:
                        os.write(fd, b'corruption')
                    except OSError as exc:
                        assert exc.errno == errno.EBADF
                    else:
                        raise AssertionError('inherited write succeeded')
            else:
                try:
                    if operation == 'write':
                        with path.open('r+b') as stream:
                            stream.write(b'corruption')
                    elif operation == 'create':
                        (path.parent / 'created').write_bytes(b'corruption')
                    elif operation == 'truncate':
                        os.truncate(path, 0)
                    elif operation == 'rename':
                        path.rename(path.parent / 'renamed')
                    elif operation == 'unlink':
                        path.unlink()
                    elif operation == 'link':
                        os.link(path, path.parent / 'linked')
                    else:
                        with path.open('r+b') as stream:
                            mmap.mmap(stream.fileno(), 4096, flags=mmap.MAP_SHARED,
                                      prot=mmap.PROT_READ | mmap.PROT_WRITE)
                except OSError as exc:
                    assert exc.errno in {errno.EACCES, errno.EPERM}
                else:
                    raise AssertionError('Landlock allowed write operation')
            os._exit(0)
        except BaseException:
            os._exit(1)
    try:
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert filesystem_snapshot(tmp_path) == before
    finally:
        os.close(inherited)


@pytest.mark.parametrize('writable', [False, True])
def test_preflight_rejects_inherited_shared_mapping(tmp_path, monkeypatch, writable):
    import mmap

    path = tmp_path / 'mapped'
    path.write_bytes(b'x' * 4096)
    monkeypatch.setattr(daemon, 'composition', lambda: pytest.fail('inspection ran'))
    with path.open('r+b') as stream:
        with mmap.mmap(stream.fileno(), 4096, flags=mmap.MAP_SHARED,
                       prot=mmap.PROT_READ | (mmap.PROT_WRITE if writable else 0)):
            assert daemon.preflight() == 1
    assert path.read_bytes() == b'x' * 4096


def test_preflight_rejects_threaded_launcher(monkeypatch):
    import threading

    release = threading.Event()
    worker = threading.Thread(target=lambda: release.wait(10))
    monkeypatch.setattr(daemon, 'composition', lambda: pytest.fail('inspection ran'))
    worker.start()
    try:
        assert daemon.preflight() == 1
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive()


def test_preflight_procfs_unavailable_fails_closed(monkeypatch):
    from soc_automation import preflight

    def unavailable(_path):
        raise OSError('procfs unavailable')

    monkeypatch.setattr(preflight.os, 'listdir', unavailable)
    monkeypatch.setattr(daemon, 'composition', lambda: pytest.fail('inspection ran'))
    assert daemon.preflight() == 1


@pytest.mark.parametrize('parent', ['state', 'policy'])
@pytest.mark.parametrize('operation', ['mkdir', 'rmdir', 'rename'])
def test_landlock_parent_directory_denials(tmp_path, parent, operation):
    import errno

    from soc_automation.preflight import close_inherited_descriptors, restrict_filesystem_writes

    directory = tmp_path / parent
    directory.mkdir()
    before = filesystem_snapshot(tmp_path)
    pid = os.fork()
    if pid == 0:
        try:
            close_inherited_descriptors()
            restrict_filesystem_writes()
            try:
                if operation == 'mkdir':
                    (directory / 'created').mkdir()
                elif operation == 'rmdir':
                    directory.rmdir()
                else:
                    directory.rename(tmp_path / 'renamed')
            except OSError as exc:
                assert exc.errno in {errno.EACCES, errno.EPERM}
            else:
                raise AssertionError('directory mutation allowed')
            os._exit(0)
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert filesystem_snapshot(tmp_path) == before


def test_preflight_diagnostics_cannot_write_inherited_policy(tmp_path, monkeypatch):
    path = tmp_path / 'policy.json'
    path.write_bytes(b'protected policy')

    def unexpected_diagnostic():
        os.write(2, b'unsafe diagnostic')

    monkeypatch.setattr(daemon, 'composition', unexpected_diagnostic)
    pid = os.fork()
    if pid == 0:
        try:
            fd = os.open(path, os.O_WRONLY)
            for standard in (0, 1, 2):
                os.dup2(fd, standard)
            os.close(fd)
            os._exit(0 if daemon.preflight() == 1 else 1)
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert path.read_bytes() == b'protected policy'


def test_fixed_shared_database_and_account(monkeypatch):
    assert daemon.DATABASE == Path('/var/lib/soc-automation/soc_automation.db')
    names = []

    def account(name):
        names.append(name)
        raise KeyError(name)

    monkeypatch.setattr(daemon.pwd, 'getpwnam', account)
    with pytest.raises(KeyError):
        daemon.composition()
    assert names == ['soc-automation']
    for name in ('soc-approval', 'soc-investigation-worker', 'soc-investigation-recovery'):
        unit = ConfigParser(interpolation=None)
        unit.read(Path(__file__).parents[1] / f'deploy/{name}.service')
        assert unit['Service']['User'] == 'soc-automation'
        assert unit['Service']['StateDirectory'] == 'soc-automation'
        assert unit['Service']['StateDirectoryMode'] == '0700'


@pytest.mark.parametrize('mode', ['delete', 'wal'])
def test_explicit_journal_verification_no_switch(deployment, mode):
    root, _, _, store, _ = deployment
    with sqlite3.connect(store.path) as conn:
        assert conn.execute(f'PRAGMA journal_mode={mode}').fetchone()[0] == mode
        conn.execute('SELECT count(*) FROM sqlite_master').fetchone()
        if mode == 'wal':
            for suffix in ('-wal', '-shm'):
                Path(str(store.path) + suffix).chmod(0o600)
        before = filesystem_snapshot(root)
        # This process holds SQLite WAL mappings; confined-launcher coverage uses
        # the separate writer process in test_confined_preflight_filesystem_and_wal.
        assert daemon.composition()
        assert filesystem_snapshot(root) == before
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == mode


def test_policy_group_read_without_group_write(deployment):
    _, _, source, store, _ = deployment
    source.path.chmod(0o640)
    assert source.load(store)
    assert daemon.composition()
    source.path.chmod(0o660)
    with pytest.raises(ValueError, match='Unsafe protected path'):
        source.load(store)


@pytest.mark.parametrize('suffix', ['', '-wal', '-shm', '-journal'])
def test_foreign_database_ownership_rejected(deployment, monkeypatch, suffix):
    _, _, _, store, _ = deployment
    target = Path(str(store.path) + suffix)
    if suffix:
        target.write_bytes(b'')
        target.chmod(0o600)
    original = daemon.os.stat

    def foreign(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == target.name:
            fields = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
            fields['st_uid'] = os.getuid() + 1
            return SimpleNamespace(**fields)
        return info

    monkeypatch.setattr(daemon.os, 'stat', foreign)
    with pytest.raises(ValueError, match='database|sidecar'):
        daemon.composition()


def test_read_methods_do_not_reserve_writer_lock(tmp_path):
    store = Store(tmp_path / 'readonly.db', timeout=0)
    store.initialize()
    with sqlite3.connect(store.path) as writer:
        writer.execute('BEGIN IMMEDIATE')
        store.healthcheck()
        assert store.audit_records('missing') == []
        for method in (store.show_alert, store.show_investigation, store.show_case_publication):
            with pytest.raises(StateError, match='Unknown'):
                method('missing')
        with pytest.raises(StateError, match='snapshot mismatch'):
            store.validate_case_evidence({'investigation_id': 'missing', 'retrieved_evidence': []})


def test_foreign_state_directory_owner_rejected(deployment, monkeypatch):
    _, _, _, store, _ = deployment
    original = daemon.os.fstat
    inode = store.path.parent.stat().st_ino

    def foreign(fd):
        info = original(fd)
        if info.st_ino == inode:
            fields = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
            fields['st_uid'] = os.getuid() + 1
            return SimpleNamespace(**fields)
        return info

    monkeypatch.setattr(daemon.os, 'fstat', foreign)
    with pytest.raises(ValueError):
        daemon.composition()


def test_missing_database_not_initialized(deployment):
    root, _, _, store, _ = deployment
    store.path.unlink()
    before = filesystem_snapshot(root)
    assert daemon.main(['--check']) == 1
    assert filesystem_snapshot(root) == before


def test_fresh_database_default_journal_mode(tmp_path):
    store = Store(tmp_path / 'fresh.db')
    store.initialize()
    with sqlite3.connect(store.path) as conn:
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'


@pytest.mark.parametrize('mode', ['truncate', 'persist', 'memory', 'off'])
def test_unsupported_journal_modes_rejected(deployment, monkeypatch, mode):
    from contextlib import contextmanager

    _, _, _, store, _ = deployment
    # These modes are connection-local: keep the actual SQLite connection pinned
    # so composition observes the selected mode rather than a new DELETE default.
    with sqlite3.connect(store.path) as conn:
        assert conn.execute(f'PRAGMA journal_mode={mode}').fetchone()[0] == mode

        @contextmanager
        def pinned(self, **kwargs):
            assert kwargs == {'readonly': True}
            yield conn

        monkeypatch.setattr(Store, '_connection', pinned)
        with pytest.raises(ValueError, match='Unsupported deployment journal mode'):
            daemon.composition()
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == mode
