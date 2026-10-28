"""Explicit operator intent, dispatched before administrative configuration loading."""

import argparse
import json
import sys

from soc_automation.approval import REASONS
from soc_automation.approval_client import (
    ERROR_EXITS,
    ClientError,
    encode_request,
    exchange,
    validate_endpoint,
)
from soc_automation.state import _canonical_case_target

COMMANDS = {'approval-service-health': 'health', 'approve-case-publication': 'approve',
            'decline-case-publication': 'decline', 'revoke-case-approval': 'revoke'}


def predecessor(value):
    if value == 'null':
        return None
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 2**63 - 1:
        raise argparse.ArgumentTypeError('Expected null or positive event ID')
    return int(value)


def main(argv):
    parser = argparse.ArgumentParser(description='Authenticated local approval operator',
                                     allow_abbrev=False)
    parser.add_argument('command', choices=COMMANDS)
    parser.add_argument('--socket-path', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--timeout-seconds', type=float, default=2.0)
    operation = COMMANDS[argv[0]]
    if operation != 'health':
        for name in ('publication-id', 'request-id', 'expected-payload-sha256',
                     'expected-report-sha256', 'expected-renderer-version',
                     'expected-review-policy-version'):
            parser.add_argument('--' + name, required=True)
        parser.add_argument('--expected-state', required=True, choices=['prepared'])
        parser.add_argument('--expected-previous-event-id', type=predecessor, required=True)
        parser.add_argument('--reason-code', choices=sorted(REASONS))
        parser.add_argument('--confirm', action='store_true',
                            help='Confirm this exact intent, including without a terminal')
    args = parser.parse_args(argv)
    request = dict(version=1, operation=operation, target=args.target)
    try:
        validate_endpoint(args.socket_path, args.timeout_seconds)
        if not _canonical_case_target(args.target):
            raise ValueError
        if operation != 'health':
            for name in ('publication_id', 'request_id', 'expected_state',
                         'expected_previous_event_id', 'expected_payload_sha256',
                         'expected_report_sha256', 'expected_renderer_version',
                         'expected_review_policy_version', 'reason_code'):
                request[name] = getattr(args, name)
            # Validate the wire representation before prompting; never transmit until confirmed.
            encode_request(dict(request, confirmed=True))
            print('Intended decision: ' + json.dumps(request, sort_keys=True), file=sys.stderr)
            confirmed = args.confirm
            if not confirmed and sys.stdin.isatty():
                print('Type yes to confirm: ', end='', file=sys.stderr, flush=True)
                try:
                    confirmed = sys.stdin.readline().strip() == 'yes'
                except KeyboardInterrupt:
                    confirmed = False
                except OSError:
                    print('terminal confirmation read failed', file=sys.stderr)
                    confirmed = False
            if not confirmed:
                print('cancelled: no decision request sent', file=sys.stderr)
                return 3
            request['confirmed'] = True
        result = exchange(args.socket_path, request, seconds=args.timeout_seconds)
        if not result['ok']:
            raise ClientError(result['error'], ERROR_EXITS[result['error']])
        if operation != 'health':
            result['request_id'] = args.request_id
            result['receipt'] = 'historical event receipt; current effectiveness not established'
        print(json.dumps(result, sort_keys=True))
        return 0
    except ClientError as error:
        print(error.code, file=sys.stderr)
        if error.exit_code == 9 and operation != 'health':
            print('Outcome uncertain. After confirming current authorization, retry with the SAME '
                  'request ID and identical material request fields.', file=sys.stderr)
        return error.exit_code
    except (ValueError, TypeError, UnicodeError, RecursionError):
        print('local_argument_validation_failure', file=sys.stderr)
        return 2
