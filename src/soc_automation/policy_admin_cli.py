"""Strict offline administration foundation. No privileged mutation implementation."""

import json
import os
import re
import sys
import time
from pathlib import Path

from soc_automation.approval import _policy_content
from soc_automation.approval_policy import PolicySource, inspect_policy_ledger
from soc_automation.deadline import check_deadline
from soc_automation.state import StateError, Store

DATABASE_PATH = Path('/var/lib/soc-automation/soc_automation.db')
LIVE_POLICY_PATH = Path('/etc/soc-approval/review-policy.json')
MAX_GENERATION = 2**63 - 1
INPUT_LIMIT = 16384
OUTPUT_LIMIT = 4096
OPERATIONS = {'inspect', 'verify', 'install', 'rotate', 'recover'}
COMMON = {'operation-id', 'change-reference', 'expected-generation'}
EXTRA = {
    'inspect': set(),
    'verify': {'expected-current-sha256'},
    'install': {'candidate', 'candidate-sha256'},
    'rotate': {'candidate', 'candidate-sha256', 'expected-current-sha256'},
    'recover': {'candidate-sha256', 'expected-current-sha256'},
}


def _parse(argv):
    if (not argv or len(argv) > 20
            or sum(len(arg.encode('utf-8')) for arg in argv) > INPUT_LIMIT
            or argv[0] not in OPERATIONS):
        raise ValueError
    operation = argv[0]
    values = {}
    # Accept only exact long options with one value, in separate or equals form.
    index = 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith('--'):
            raise ValueError
        key, equal, value = token[2:].partition('=')
        if key not in COMMON | EXTRA[operation] or key in values:
            raise ValueError
        if not equal:
            index += 1
            if index == len(argv) or argv[index].startswith('--'):
                raise ValueError
            value = argv[index]
        values[key] = value
        index += 1
    if set(values) != COMMON | EXTRA[operation]:
        raise ValueError
    for key, pattern in (
        ('operation-id', r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}'),
        ('change-reference', r'[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}'),
        ('expected-generation', r'[0-9]{1,19}'),
    ):
        if re.fullmatch(pattern, values[key], flags=re.ASCII) is None:
            raise ValueError
    generation = int(values['expected-generation'])
    if generation > MAX_GENERATION:
        raise ValueError
    if operation == 'install' and generation != 0:
        raise ValueError
    if operation in {'verify', 'rotate', 'recover'} and generation == 0:
        raise ValueError
    if operation == 'rotate' and generation == MAX_GENERATION:
        raise ValueError
    for key in EXTRA[operation] - {'candidate'}:
        if re.fullmatch(r'[0-9a-f]{64}', values[key], flags=re.ASCII) is None:
            raise ValueError
    if 'candidate' in values:
        path = values['candidate']
        if (len(path.encode('utf-8')) > 4096 or not path.startswith('/')
                or '\x00' in path or any(p in {'', '.', '..'} for p in path.split('/')[1:])):
            raise ValueError
    if operation == 'recover' and values['candidate-sha256'] != values['expected-current-sha256']:
        raise ValueError
    return operation, values, generation


def main(argv=None):
    result = dict(contract_version=1, operation=None, operation_id=None, status='error',
                  active_generation=None, active_sha256=None, live_match=None, error=None)
    code = 2
    try:
        operation, values, generation = _parse(sys.argv[1:] if argv is None else argv)
        result.update(operation=operation, operation_id=values['operation-id'])
        # Never load Settings, dotenv, operator authorization or caller-selected paths.
        if any(key.startswith('SOC_') and
               ('PATH' in key or 'POLICY' in key or 'DATABASE' in key or 'ADMIN' in key)
               for key in os.environ):
            result['error'] = 'invalid_arguments'
        elif os.getuid() != 0 or os.geteuid() != 0:
            code, result['error'] = 3, 'permission_denied'
        elif operation in {'install', 'rotate', 'recover'}:
            result.update(operation=None, operation_id=None, error='maintenance_required')
            code = 4
        else:
            deadline = time.monotonic() + 5
            ledger = inspect_policy_ledger(Store(DATABASE_PATH), deadline=deadline)
            check_deadline(deadline)
            active = ledger.active
            if (None if active is None else active.generation) != (generation or None):
                code, result['error'] = 5, 'expectation_conflict'
            elif (operation == 'verify'
                  and active.content_sha256 != values['expected-current-sha256']):
                code, result['error'] = 5, 'digest_mismatch'
            elif operation == 'verify':
                check_deadline(deadline)
                policy = PolicySource(LIVE_POLICY_PATH).read_candidate()
                check_deadline(deadline)
                if _policy_content(policy) != active.content:
                    code, result['error'] = 5, 'digest_mismatch'
                else:
                    code = 0
                    result['live_match'] = True
            else:
                code = 0
            check_deadline(deadline)
            if code == 0:
                result.update(status='ok', active_generation=active.generation if active else None,
                              active_sha256=active.content_sha256 if active else None)
                check_deadline(deadline)
    except (ValueError, UnicodeError):
        result['error'] = 'invalid_arguments' if result['operation'] is None else 'unsafe_path'
        code = 2 if result['operation'] is None else 3
    except RecursionError:
        code, result['error'] = 5, 'invalid_candidate'
    except (StateError, TimeoutError):
        code, result['error'] = 6, 'authority_unavailable'
    except OSError:
        code, result['error'] = 6, 'io_failure'
    except Exception:
        # Internal implementation failures never become an external diagnostic API.
        code, result['error'] = 6, 'authority_unavailable'
    if code != 0:
        result.update(status='error', active_generation=None, active_sha256=None, live_match=None)
    payload = json.dumps(result, separators=(',', ':'), sort_keys=True) + '\n'
    if len(payload.encode('utf-8')) > OUTPUT_LIMIT:
        result.update(operation=None, operation_id=None, status='error',
                      active_generation=None, active_sha256=None, live_match=None,
                      error='size_limit')
        payload = json.dumps(result, separators=(',', ':')) + '\n'
        code = 5
    if code == 0:
        # Serialize and bound the entire response before the last cooperative check.
        # Keep this at the sole write site so every successful response is covered.
        try:
            check_deadline(deadline)
        except TimeoutError:
            code = 6
            result.update(status='error', active_generation=None, active_sha256=None,
                          live_match=None, error='authority_unavailable')
            payload = json.dumps(result, separators=(',', ':'), sort_keys=True) + '\n'
    sys.stdout.write(payload)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
