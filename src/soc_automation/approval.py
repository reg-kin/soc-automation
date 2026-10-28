"""Internal trusted decision boundary. No authentication, policy loader or transport."""

import json
import re
import sqlite3
from dataclasses import asdict, dataclass

from soc_automation.deadline import check_deadline, sha256_text

DECISIONS = frozenset({'approved', 'declined', 'revoked'})
REASONS = frozenset({'operator_declined', 'operator_revoked', 'incorrect_payload', 'policy'})


def _text(value):
    if (type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}', value)):
        raise ValueError('Invalid policy or identity token')


def _uid(value):
    if type(value) is not int or not 0 <= value <= 2**32 - 1:
        raise ValueError('Invalid UID')


@dataclass(frozen=True, slots=True, init=False)
class TrustedIdentity:
    """Typed assertion by trusted code, NOT proof of authentication.

    Only a future authenticated adapter may invoke the explicit trusted factory.
    Python callers in this process are trusted; this is not a sandbox boundary.
    """

    uid: int
    principal: str
    authentication_method: str

    def __init__(self):
        raise TypeError("Use the explicit trusted peer credential boundary")

    @classmethod
    def from_verified_peer_credentials(cls, *, uid, principal):
        """Trusted boundary: caller must have verified kernel peer credentials."""
        _uid(uid)
        _text(principal)
        instance = object.__new__(cls)
        object.__setattr__(instance, 'uid', uid)
        object.__setattr__(instance, 'principal', principal)
        object.__setattr__(instance, 'authentication_method', 'os_peer_credentials')
        return instance


def _identity(identity):
    if type(identity) is not TrustedIdentity:
        raise ValueError('Trusted identity required')
    _uid(identity.uid)
    _text(identity.principal)
    if identity.authentication_method != 'os_peer_credentials':
        raise ValueError('Unsupported authentication method')


@dataclass(frozen=True, slots=True)
class ReviewPolicy:
    """Immutable active policy supplied by trusted composition, never operator input.

    Tuple/frozenset fields avoid mutable aliases. Provenance cannot be relaxed for
    approval; deterministic evidence is permitted only for decline/revocation.
    """

    version: str
    principals: tuple[tuple[int, str], ...]
    targets: frozenset[str]
    decisions: frozenset[str] = DECISIONS
    renderer_version: str = "soc-case/2"
    approval_provenance: str = 'completed_preparation'
    decline_provenance: str = 'verified_evidence'
    revocation_provenance: str = 'verified_evidence'
    reason_requirements: tuple[tuple[str, frozenset[str]], ...] = (
        ('approved', frozenset()),
        ('declined', frozenset({'operator_declined', 'incorrect_payload', 'policy'})),
        ('revoked', frozenset({'operator_revoked', 'incorrect_payload', 'policy'})),
    )

    def __post_init__(self):
        from soc_automation.cases import RENDERER_VERSION
        from soc_automation.state import _canonical_case_target

        _text(self.version)
        if type(self.principals) is not tuple or not self.principals:
            raise ValueError('UID/principal mapping required')
        seen = set()
        for pair in self.principals:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError('Invalid principal mapping')
            uid, principal = pair
            _uid(uid)
            _text(principal)
            if uid in seen:
                raise ValueError('Duplicate UID')
            seen.add(uid)
        if (type(self.targets) is not frozenset or not self.targets
                or not all(_canonical_case_target(t) for t in self.targets)):
            raise ValueError('Canonical targets required')
        if (type(self.decisions) is not frozenset or not self.decisions
                or not self.decisions <= DECISIONS):
            raise ValueError('Invalid decisions')
        if (self.renderer_version != RENDERER_VERSION
                or self.approval_provenance != 'completed_preparation'
                or self.decline_provenance != 'verified_evidence'
                or self.revocation_provenance != 'verified_evidence'):
            raise ValueError('Unsupported renderer or provenance policy')
        if type(self.reason_requirements) is not tuple or len(self.reason_requirements) != 3:
            raise ValueError('Decision reason policy required')
        seen = set()
        for pair in self.reason_requirements:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError('Invalid reason policy')
            decision, reasons = pair
            if (decision not in DECISIONS or decision in seen
                    or type(reasons) is not frozenset or not reasons <= REASONS
                    or (decision != 'approved' and not reasons)):
                raise ValueError('Invalid reason policy')
            seen.add(decision)
        # Revocation must remain available wherever approvals can be granted.
        if 'approved' in self.decisions and 'revoked' not in self.decisions:
            raise ValueError('Approval requires revocation support')

    def authorize(self, identity, *, target, decision):
        from soc_automation.state import StateError

        _identity(identity)
        if ((identity.uid, identity.principal) not in self.principals
                or target not in self.targets or decision not in self.decisions):
            raise StateError('Identity, target or decision unauthorized by active policy')

    def check_artifact(self, review, decision):
        from soc_automation.state import StateError

        if review['renderer_version'] != self.renderer_version:
            raise StateError('Renderer unauthorized by active policy')
        if decision == 'approved' and 'preparation' not in review['report_hash_sources']:
            raise StateError('Approval requires verified completed preparation provenance')


def _policy_content(policy):
    """Canonical complete immutable semantics, including the non-reusable version."""
    def canonical(value):
        check_deadline()
        if isinstance(value, frozenset):
            return sorted(canonical(item) for item in value)
        if isinstance(value, tuple):
            return [canonical(item) for item in value]
        if isinstance(value, dict):
            return {key: canonical(item) for key, item in value.items()}
        return value

    return json.dumps(canonical(asdict(policy)), sort_keys=True, separators=(',', ':'))


class ApprovalStore:
    @staticmethod
    def _active_policy_generation(conn):
        from soc_automation.state import StateError

        try:
            rows = conn.execute(
                'SELECT * FROM review_policy_generations ORDER BY generation'
            ).fetchall()
            for generation, row in enumerate(rows, 1):
                check_deadline()
                content = row['content']
                if (row['generation'] != generation
                        or sha256_text(content) != row['content_sha256']
                        or json.loads(content)['version'] != row['version']):
                    raise ValueError('Invalid policy ledger')
            return rows[-1] if rows else None
        except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            raise StateError('Authoritative active policy state corrupt or unavailable') from exc

    def install_review_policy(self, policy, *, expected_generation):
        """TRUSTED ADMIN ONLY: explicit installation/rotation, never request input.

        Caller must authenticate administrative authority and load policy from a
        protected source. In-process Python and database writers are trusted.
        None bootstraps an empty ledger; otherwise a positive generation is a CAS.
        Every installation requires a fresh version, including rollback policies.
        Store construction and ordinary request handling never invoke this method.
        """
        from soc_automation.state import StateError, _timestamp

        if type(policy) is not ReviewPolicy:
            raise ValueError('Validated policy required')
        if expected_generation is not None and (
                type(expected_generation) is not int or expected_generation < 1):
            raise ValueError('Explicit expected generation required')
        content = _policy_content(policy)
        with self._connection() as conn:
            self._validate(conn)
            active = self._active_policy_generation(conn)
            if (active['generation'] if active else None) != expected_generation:
                raise StateError('Active policy generation conflict')
            if conn.execute('SELECT 1 FROM review_policy_generations WHERE version=?',
                            (policy.version,)).fetchone():
                raise StateError('Policy version cannot be reused')
            generation = 1 if active is None else active['generation'] + 1
            conn.execute('INSERT INTO review_policy_generations VALUES(?,?,?,?,?)',
                         (generation, policy.version, content,
                          sha256_text(content), _timestamp()))
        return generation

    def _require_active_policy(self, conn):
        from soc_automation.state import StateError

        active = self._active_policy_generation(conn)
        policy = self._publication_policy
        if (type(policy) is not ReviewPolicy or active is None
                or active['content'] != _policy_content(policy)):
            raise StateError('Trusted active policy unavailable or superseded')
        return policy

    def record_case_decision(
        self, *, identity, policy, request_id, publication_id, decision,
        expected_previous_event_id, expected_payload_sha256, expected_report_sha256,
        expected_target, expected_renderer_version, expected_review_policy_version,
        confirmed, reason_code=None, deadline=None,
    ):
        """Record one explicit intent, or return its historical committed replay.

        All expectations are mandatory, including an explicit None predecessor.
        The supplied policy must be the Store's trusted active policy snapshot.
        """
        from soc_automation.state import StateError, _canonical_case_target, _identifier, _timestamp

        check_deadline(deadline)
        if type(policy) is not ReviewPolicy or policy is not self._publication_policy:
            raise StateError('Trusted active policy required')
        _identifier(request_id, 256)
        _identifier(publication_id, 256)
        if type(decision) is not str or decision not in DECISIONS or confirmed is not True:
            raise ValueError('Valid decision and explicit intent confirmation required')
        if (expected_previous_event_id is not None
                and (type(expected_previous_event_id) is not int
                     or not 1 <= expected_previous_event_id <= 2**63 - 1)):
            raise ValueError('Invalid predecessor')
        for value in (expected_payload_sha256, expected_report_sha256):
            if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
                raise ValueError('Exact SHA256 required')
        if not _canonical_case_target(expected_target):
            raise ValueError('Canonical target required')
        _text(expected_renderer_version)
        _text(expected_review_policy_version)
        if reason_code is not None and (type(reason_code) is not str or reason_code not in REASONS):
            raise ValueError('Invalid reason')
        policy.authorize(identity, target=expected_target, decision=decision)
        check_deadline(deadline)
        intent = dict(
            request_id=request_id, publication_id=publication_id, decision=decision,
            previous_event_id=expected_previous_event_id, payload_sha256=expected_payload_sha256,
            report_sha256=expected_report_sha256, target=expected_target,
            renderer_version=expected_renderer_version,
            review_policy_version=expected_review_policy_version, actor_uid=identity.uid,
            actor_principal=identity.principal,
            authentication_method=identity.authentication_method,
            reason_code=reason_code,
        )
        with self._connection(deadline=deadline) as conn:
            self._validate(conn)
            self._require_active_policy(conn)
            prior = conn.execute('SELECT * FROM case_review_events WHERE request_id=?',
                                 (request_id,)).fetchone()
            if prior is not None:
                # Access is authorized above before any historical event is returned.
                if any(prior[k] != v for k, v in intent.items()):
                    raise StateError('Request ID conflict')
                result = dict(prior)
            else:
                if expected_review_policy_version != policy.version:
                    raise StateError('Active review policy version mismatch')
                reasons = dict(policy.reason_requirements)[decision]
                if ((reasons and reason_code not in reasons)
                        or (not reasons and reason_code is not None)):
                    raise ValueError('Decision reason required or disallowed by policy')
                review = self._verify_case_publication(conn, publication_id)
                if review['state'] != 'prepared' or not review['is_current_head']:
                    raise StateError('Current prepared publication head required')
                for name in ('payload_sha256', 'report_sha256', 'target', 'renderer_version'):
                    if review[name] != intent[name]:
                        raise StateError('Stale publication binding')
                latest = review['latest_review']
                if expected_previous_event_id != (latest['id'] if latest else None):
                    raise StateError('Stale review predecessor')
                allowed = ({'revoked'} if latest and latest['decision'] == 'approved'
                           else {'approved', 'declined'})
                if decision not in allowed:
                    raise StateError('Invalid decision transition')
                policy.check_artifact(review, decision)
                conn.execute(
                    'INSERT INTO case_review_events(request_id,publication_id,decision,'
                    'previous_event_id,payload_sha256,report_sha256,target,renderer_version,'
                    'review_policy_version,actor_uid,actor_principal,authentication_method,'
                    'reason_code,decided_at) VALUES(:request_id,:publication_id,:decision,'
                    ':previous_event_id,:payload_sha256,:report_sha256,:target,:renderer_version,'
                    ':review_policy_version,:actor_uid,:actor_principal,:authentication_method,'
                    ':reason_code,:decided_at)', dict(intent, decided_at=_timestamp()),
                )
                result = dict(conn.execute('SELECT * FROM case_review_events WHERE request_id=?',
                                           (request_id,)).fetchone())
        # Exiting the connection commits before returning any success, including replay.
        return result

    def _check_publication_policy(self, conn, publication_id):
        from soc_automation.state import StateError

        policy = self._require_active_policy(conn)
        review = self._verify_case_publication(conn, publication_id)
        event = review['latest_review']
        if (event is None or event['decision'] != 'approved'
                or event['review_policy_version'] != policy.version):
            raise StateError('Current approval under active policy required')
        identity = TrustedIdentity.from_verified_peer_credentials(
            uid=event['actor_uid'], principal=event['actor_principal'],
        )
        if event['authentication_method'] != identity.authentication_method:
            raise StateError('Unsupported approval authentication method')
        policy.authorize(identity, target=review['target'], decision='approved')
        policy.check_artifact(review, 'approved')
        reasons = dict(policy.reason_requirements)['approved']
        if ((reasons and event['reason_code'] not in reasons)
                or (not reasons and event['reason_code'] is not None)):
            raise StateError('Approval reason unauthorized by active policy')
