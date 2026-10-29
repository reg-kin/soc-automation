"""Administrative entry point tests use disposable state exclusively."""

import hashlib
import json
import os

import pytest

from soc_automation import policy_admin_cli as cli
from soc_automation.approval import ReviewPolicy, _policy_content
from soc_automation.approval_policy import PolicySource
from soc_automation.state import StateError, Store


def arguments(operation='inspect', generation='0'):
    return [operation, '--operation-id', 'op-1', '--change-reference', 'CHG:1',
            '--expected-generation', generation]


def reply(capsys, code, expected):
    out = capsys.readouterr()
    assert out.err == ''
    assert len(out.out.encode()) <= 4096
    value = json.loads(out.out)
    assert set(value) == {'contract_version', 'operation', 'operation_id', 'status',
                          'active_generation', 'active_sha256', 'live_match', 'error'}
    assert code == expected
    return value


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, 'DATABASE_PATH', tmp_path / 'authority.db')
    monkeypatch.setattr(cli, 'LIVE_POLICY_PATH', tmp_path / 'policy.json')
    monkeypatch.setattr(cli.os, 'getuid', lambda: 0)
    monkeypatch.setattr(cli.os, 'geteuid', lambda: 0)


@pytest.mark.parametrize('args', [
    [], ['--help'], ['ins'], arguments() + ['--unknown', 'secret'],
    arguments() + ['--operation-id=duplicate'], arguments() + ['extra'],
    arguments() + ['--expected-gen', '0'], arguments(generation='-1'),
    arguments(generation='9223372036854775808'), arguments(generation='1' * 5000),
    arguments(generation='١'), arguments()[:-1],
    ['inspect', '--operation-id', '../secret'] + arguments()[3:],
    arguments() + ['--candidate', '/secret'],
    arguments('verify'), arguments('install', '1'),
    arguments() + ['x' * 20000],
])
def test_invalid(args, capsys, monkeypatch):
    monkeypatch.setattr(cli, 'Store', lambda *a: pytest.fail('state accessed'))
    value = reply(capsys, cli.main(args), 2)
    assert value['error'] == 'invalid_arguments'
    assert value['operation'] is None
    assert value['operation_id'] is None


def test_root_refusal(capsys, monkeypatch):
    monkeypatch.setattr(cli.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(cli, 'Store', lambda *a: pytest.fail('state accessed'))
    assert reply(capsys, cli.main(arguments()), 3)['error'] == 'permission_denied'


@pytest.mark.parametrize('name', ['SOC_DATABASE_PATH', 'SOC_POLICY_PATH',
                                  'SOC_POLICY_ADMIN_LOCK_PATH'])
def test_environment_refusal(name, capsys, monkeypatch):
    monkeypatch.setenv(name, '/secret')
    monkeypatch.setattr(cli, 'Store', lambda *a: pytest.fail('state accessed'))
    assert reply(capsys, cli.main(arguments()), 2)['error'] == 'invalid_arguments'


@pytest.mark.parametrize('operation', ['install', 'rotate', 'recover'])
def test_unavailable(operation, capsys, monkeypatch, tmp_path):
    args = arguments(operation, '0' if operation == 'install' else '1')
    if operation in {'install', 'rotate'}:
        args += ['--candidate', '/does/not/exist']
    args += ['--candidate-sha256', 'a' * 64]
    if operation != 'install':
        args += ['--expected-current-sha256', 'a' * 64]
    monkeypatch.setattr(cli, 'Store', lambda *a: pytest.fail('state accessed'))
    monkeypatch.setattr(PolicySource, 'read_candidate', lambda *a: pytest.fail('file accessed'))
    from soc_automation import policy_admin_fs

    monkeypatch.setattr(policy_admin_fs, 'administration',
                        lambda: pytest.fail('staging accessed'))
    monkeypatch.setattr(policy_admin_fs, '_source_bytes',
                        lambda *a: pytest.fail('candidate accessed'))
    value = reply(capsys, cli.main(args), 4)
    assert value['error'] == 'maintenance_required'
    assert value['operation'] is None
    assert list(tmp_path.iterdir()) == []


def test_readonly(capsys, monkeypatch, tmp_path):
    store = Store(cli.DATABASE_PATH)
    store.initialize()
    assert reply(capsys, cli.main(arguments()), 0)['active_generation'] is None
    policy = ReviewPolicy('review/1', ((1000, 'operator:test'),),
                          frozenset({'https://example.test/default/securitySolution'}))
    store.install_review_policy(policy, expected_generation=None)
    content = _policy_content(policy)
    cli.LIVE_POLICY_PATH.write_text(content)
    cli.LIVE_POLICY_PATH.chmod(0o640)
    # Exercise real bounded protected file reading; only disposable /tmp ancestry is substituted.
    import soc_automation.approval_policy as policy_module
    monkeypatch.setattr(policy_module, 'protected_directory',
                        lambda path, owners: os.open(path, os.O_RDONLY))
    monkeypatch.setattr(cli, 'PolicySource',
                        lambda path: PolicySource(
                            path, owner_uid=cli.LIVE_POLICY_PATH.stat().st_uid))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    inspect = reply(capsys, cli.main(arguments(generation='1')), 0)
    digest = hashlib.sha256(content.encode()).hexdigest()
    assert inspect['active_sha256'] == digest
    assert inspect['live_match'] is None
    args = arguments('verify', '1') + ['--expected-current-sha256', digest]
    assert reply(capsys, cli.main(args), 0)['live_match'] is True
    assert reply(capsys, cli.main(arguments()), 5)['error'] == 'expectation_conflict'
    assert reply(capsys, cli.main(args[:-1] + ['0' * 64]), 5)['error'] == 'digest_mismatch'
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize('error,code,classification', [
    (StateError('secret SQLite error'), 6, 'authority_unavailable'),
    (TimeoutError('secret'), 6, 'authority_unavailable'),
    (OSError('secret path'), 6, 'io_failure'),
])
def test_sanitized(error, code, classification, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(cli, 'inspect_policy_ledger', fail)
    value = reply(capsys, cli.main(arguments()), code)
    assert value['error'] == classification
    assert value['active_sha256'] is None


def test_separate_entry_point():
    import tomllib
    from pathlib import Path

    scripts = tomllib.loads(Path('pyproject.toml').read_text())['project']['scripts']
    assert scripts['soc-automation'] == 'soc_automation.cli:main'
    assert scripts['soc-policy-admin'] == 'soc_automation.policy_admin_cli:main'


@pytest.mark.parametrize('operation,generation,extra', [
    ('install', '0', ['--candidate', '/candidate/../secret', '--candidate-sha256', 'a' * 64]),
    ('install', '0', ['--candidate', '/candidate', '--candidate-sha256', 'A' * 64]),
    ('rotate', str(2**63 - 1), ['--candidate', '/candidate', '--candidate-sha256', 'a' * 64,
                              '--expected-current-sha256', 'b' * 64]),
    ('recover', '1', ['--candidate-sha256', 'a' * 64,
                      '--expected-current-sha256', 'b' * 64]),
])
def test_invalid_mutation_contract(operation, generation, extra, capsys):
    assert reply(capsys, cli.main(arguments(operation, generation) + extra), 2)['error'] == (
        'invalid_arguments')


def test_maximum_labels_and_equals(capsys):
    args = ['inspect', '--operation-id=' + 'a' * 64, '--change-reference=' + 'b' * 128,
            '--expected-generation=0']
    # Missing disposable DB: sanitized failure still respects the output bound.
    value = reply(capsys, cli.main(args), 6)
    assert value['operation_id'] == 'a' * 64


def test_wal_state_unchanged(capsys, tmp_path):
    import sqlite3

    store = Store(cli.DATABASE_PATH)
    store.initialize()
    with sqlite3.connect(store.path) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('SELECT * FROM review_policy_generations').fetchall()
        before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
        assert reply(capsys, cli.main(arguments()), 6)['error'] == 'authority_unavailable'
        assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize('real,effective', [(0, 0), (1000, 0), (0, 1000), (1000, 1000)])
def test_uid_combinations(real, effective, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, 'getuid', lambda: real)
    monkeypatch.setattr(cli.os, 'geteuid', lambda: effective)
    calls = []

    def inspect(*args, **kwargs):
        calls.append(True)
        raise StateError('disposable sentinel')

    monkeypatch.setattr(cli, 'inspect_policy_ledger', inspect)
    allowed = real == effective == 0
    value = reply(capsys, cli.main(arguments()), 6 if allowed else 3)
    assert value['error'] == ('authority_unavailable' if allowed else 'permission_denied')
    assert bool(calls) == allowed


@pytest.mark.parametrize('method', ['getuid', 'geteuid'])
def test_identity_failure(method, monkeypatch, capsys):
    def fail():
        raise OSError('private identity diagnostic')

    monkeypatch.setattr(cli.os, method, fail)
    monkeypatch.setattr(cli, 'Store', lambda *a: pytest.fail('state accessed'))
    value = reply(capsys, cli.main(arguments()), 6)
    assert value['error'] == 'io_failure'
    assert value['active_generation'] is None


@pytest.fixture
def live_authority(monkeypatch):
    import soc_automation.approval_policy as policy_module

    policy = ReviewPolicy('review/1', ((1000, 'operator:test'),),
                          frozenset({'https://example.test/default/securitySolution'}))
    store = Store(cli.DATABASE_PATH)
    store.initialize()
    store.install_review_policy(policy, expected_generation=None)
    content = _policy_content(policy)
    cli.LIVE_POLICY_PATH.write_text(content)
    cli.LIVE_POLICY_PATH.chmod(0o640)
    owner = cli.LIVE_POLICY_PATH.stat().st_uid
    monkeypatch.setattr(policy_module, 'protected_directory',
                        lambda path, owners: os.open(path, os.O_RDONLY))
    monkeypatch.setattr(cli, 'PolicySource', lambda path: PolicySource(path, owner_uid=owner))
    digest = hashlib.sha256(content.encode()).hexdigest()
    return arguments('verify', '1') + ['--expected-current-sha256', digest]


@pytest.mark.parametrize('case,code,error', [
    ('symlink', 6, 'io_failure'), ('permissions', 3, 'unsafe_path'),
    ('digest', 5, 'digest_mismatch'), ('generation', 5, 'expectation_conflict'),
    ('missing', 6, 'io_failure'),
])
def test_live_policy_failures(case, code, error, live_authority, capsys, tmp_path):
    args = live_authority
    if case == 'symlink':
        target = tmp_path / 'target.json'
        cli.LIVE_POLICY_PATH.rename(target)
        cli.LIVE_POLICY_PATH.symlink_to(target)
    elif case == 'permissions':
        cli.LIVE_POLICY_PATH.chmod(0o666)
    elif case == 'digest':
        cli.LIVE_POLICY_PATH.write_text(cli.LIVE_POLICY_PATH.read_text().replace('review/1',
                                                                              'review/2'))
    elif case == 'generation':
        args = arguments('verify', '2') + args[-2:]
    else:
        cli.LIVE_POLICY_PATH.unlink()
    before = {p.name: (p.lstat(), p.read_bytes()) for p in tmp_path.iterdir()}
    value = reply(capsys, cli.main(args), code)
    assert value['error'] == error
    assert all(value[key] is None for key in ('active_generation', 'active_sha256', 'live_match'))
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == {
        name: data for name, (_, data) in before.items()}


@pytest.mark.parametrize('stage', [
    'before_read', 'during_read', 'after_content', 'final', 'inspect',
])
def test_complete_deadline(stage, live_authority, monkeypatch, capsys):
    from soc_automation.approval_policy import inspect_policy_ledger

    ledger = inspect_policy_ledger(Store(cli.DATABASE_PATH))
    now = [100.0]
    monkeypatch.setattr(cli.time, 'monotonic', lambda: now[0])
    deadlines = []

    def inspect(store, *, deadline):
        deadlines.append(deadline)
        if stage in {'before_read', 'inspect'}:
            now[0] = deadline
        return ledger

    monkeypatch.setattr(cli, 'inspect_policy_ledger', inspect)
    source = cli.PolicySource
    reads = []

    class Reader:
        def read_candidate(self):
            reads.append(True)
            policy = source(cli.LIVE_POLICY_PATH).read_candidate()
            if stage == 'during_read':
                now[0] = 105.0
            return policy

    monkeypatch.setattr(cli, 'PolicySource', lambda path: Reader())
    content = cli._policy_content

    def canonical(policy):
        result = content(policy)
        if stage == 'after_content':
            now[0] = 105.0
        return result

    monkeypatch.setattr(cli, '_policy_content', canonical)
    check = cli.check_deadline
    checks = []

    def checked(deadline):
        checks.append(deadline)
        if stage == 'final' and len(checks) == 5:
            now[0] = deadline
        check(deadline)

    monkeypatch.setattr(cli, 'check_deadline', checked)
    args = arguments(generation='1') if stage == 'inspect' else live_authority
    value = reply(capsys, cli.main(args), 6)
    assert value['error'] == 'authority_unavailable'
    assert value['active_generation'] is value['active_sha256'] is value['live_match'] is None
    assert deadlines == [105.0]
    assert set(checks) == {105.0}
    assert bool(reads) == (stage not in {'before_read', 'inspect'})


@pytest.mark.parametrize('operation', ['inspect', 'verify'])
@pytest.mark.parametrize('stage', ['serialization', 'before_output'])
def test_final_response_deadline(operation, stage, live_authority, monkeypatch, capsys):
    ledger = cli.inspect_policy_ledger(Store(cli.DATABASE_PATH))

    def inspect(store, *, deadline):
        assert deadline == 105.0
        return ledger

    monkeypatch.setattr(cli, 'inspect_policy_ledger', inspect)
    now = [100.0]
    monkeypatch.setattr(cli.time, 'monotonic', lambda: now[0])
    dumps = cli.json.dumps
    prepared = []

    def serialize(value, **kwargs):
        payload = dumps(value, **kwargs)
        if value.get('status') == 'ok':
            # Earlier checks have passed; nothing may have reached stdout yet.
            assert capsys.readouterr().out == ''
            prepared.append(payload)
            if stage == 'serialization':
                now[0] = 105.0
        return payload

    monkeypatch.setattr(cli.json, 'dumps', serialize)
    check = cli.check_deadline
    final_checks = []

    def checked(deadline):
        if prepared:
            final_checks.append(deadline)
            if stage == 'before_output':
                now[0] = deadline
        check(deadline)

    monkeypatch.setattr(cli, 'check_deadline', checked)
    args = arguments(generation='1') if operation == 'inspect' else live_authority
    value = reply(capsys, cli.main(args), 6)
    assert len(prepared) == 1
    assert final_checks == [105.0]
    assert value['status'] == 'error'
    assert value['error'] == 'authority_unavailable'
    assert value['active_generation'] is value['active_sha256'] is value['live_match'] is None


def test_installed_launcher(tmp_path):
    """Build/install offline; startup guard substitutes identity and forbids state access."""
    import shutil
    import subprocess
    import venv
    from pathlib import Path

    source = tmp_path / 'source'
    source.mkdir()
    shutil.copy('pyproject.toml', source)
    shutil.copytree('src', source / 'src')
    environment = tmp_path / 'environment'
    # Reuse local build tooling only; install the application exclusively in this venv.
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(environment)
    python = environment / 'bin/python'
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('SOC_', 'PYTHON', 'PIP_'))}
    env.update(PIP_NO_INDEX='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
    installed = subprocess.run(  # noqa: S603
        [str(python), '-m', 'pip', 'install', '--no-index', '--no-deps',
         '--no-build-isolation', str(source)], env=env, capture_output=True, text=True,
        timeout=120)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    site = subprocess.run(  # noqa: S603
        [str(python), '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
        env=env, capture_output=True, text=True, check=True)
    Path(site.stdout.strip(), 'admin_test_guard.py').write_text('''
import os
import sys
import soc_automation.policy_admin_cli as cli
assert cli.__file__.startswith(sys.prefix + '/')
os.getuid = lambda: 0
os.geteuid = lambda: 0
def forbidden(*args, **kwargs):
    raise AssertionError('administrative state accessed')
cli.Store = forbidden
cli.PolicySource = forbidden
def audit(event, args):
    if event == 'open' and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        if path.startswith(('/var/lib/soc-', '/etc/soc-approval')):
            os._exit(99)
sys.addaudithook(audit)
''')
    Path(site.stdout.strip(), 'admin_test_guard.pth').write_text('import admin_test_guard\n')
    launcher = environment / 'bin/soc-policy-admin'
    cases = [
        (arguments(), 6, 'authority_unavailable', 'inspect'),
        (arguments() + ['--unknown', 'private'], 2, 'invalid_arguments', None),
        (arguments('install') + ['--candidate', '/never/opened',
                                  '--candidate-sha256', 'a' * 64],
         4, 'maintenance_required', None),
    ]
    for args, code, error, operation in cases:
        process = subprocess.run(  # noqa: S603
            [str(launcher), *args], env=env, cwd=tmp_path, capture_output=True,
            text=True, timeout=10)
        assert process.returncode == code
        assert process.stderr == ''
        value = json.loads(process.stdout)
        assert value['error'] == error
        assert value['operation'] == operation
        assert value['status'] == 'error'
        assert value['active_generation'] is value['active_sha256'] is None
        assert len(process.stdout.encode()) <= 4096
