# Internal approval persistence (Milestone 6.3B-1)

The persistence contract below is preserved. Milestones 6.3B-2A/2B add the
protected policy loader and authenticated health and decision transport documented
in [authenticated approval operations](approval-socket.md).

Schema 10 adds an initially empty, append-only policy-generation ledger to schema 9.
Migration installs no policy and grants no authority. Approval records remain append-only,
and the database approval trigger remains unchanged. Preparation, frozen artifacts,
read-only review, explicit manual publication, uncertain-outcome reconciliation, and
the separate production assurance platform retain their responsibilities. This
module performs local SQLite operations only; it has no transport or remediation.

## Trusted composition and identity

`TrustedIdentity.from_verified_peer_credentials(uid=..., principal=...)` is an
explicit assertion boundary for trusted in-process code. It returns an immutable,
validated numeric UID, principal, and `os_peer_credentials` method. **The typed
object does not authenticate an operator.** Its factory must only be called after
an authenticated adapter has obtained kernel peer credentials and selected the
policy-bound principal. The 6.3B-1 persistence layer supplies no adapter; the
subsequent health-only adapter is described in the linked admission document.
There is no approval CLI, environment identity inference, or client actor override.
Python code running inside this process is trusted; objects cannot protect against
hostile Python code or a privileged database writer.

Trusted application composition constructs a validated `ReviewPolicy` and binds it
through `Store(path, publication_policy=policy)`. This is only a candidate snapshot;
construction never installs policy. The decision call must supply the same object.
Neither request data, CLI arguments nor environment variables establish authority.

`Store.install_review_policy(policy, expected_generation=...)` is a **trusted
administrative in-process API**, not an authenticated endpoint. Only protected
application composition may call it after authenticating administrative authority
and obtaining policy from a protected administrator-owned source. Never dispatch
this API using operator request data. Python code in the process and database
writers remain trusted. The persistence layer supplies no administrator
authentication adapter, rotation CLI, or environment override. The subsequent protected loader does not install policy.

Installation uses `BEGIN IMMEDIATE`: `expected_generation=None` explicitly
bootstraps an empty ledger; rotation requires the exact current positive generation.
A stale expectation rolls back. Every install requires a never-used version;
rollback to previous semantics also requires a fresh version. Each generation
stores canonical complete immutable policy content and its SHA256. A version cannot
be rebound to changed content or reactivated, so exact content identifies one unique
generation. Ordinary Store construction cannot replace the active policy.

Every decision (including replay) and candidate publication claim validates the
ledger and compares its latest generation's full content to the Store snapshot
inside its existing immediate transaction. Retained Stores fail after rotation;
new Stores with the installed content can operate. Empty, missing or inconsistent
state fails closed. Missing/corrupt authority must be investigated by administrators,
never repaired by adopting a request policy. Migration leaves historical review and
publication rows untouched. SQLite serializes rotation with decisions and claims:
an operation admitted before rotation can commit first; after rotation commits,
old snapshots cannot admit work. Rotation does not cancel an already committed
sending claim or undo an external side effect.

## Policy semantics and provenance

`ReviewPolicy` is frozen and uses immutable tuples/frozensets. It specifies a
version, unique UID-to-principal mapping, nonempty canonical targets, allowed
decisions, the supported `soc-case/2` renderer, provenance rules, and allowed
reason codes for each decision. Unknown decisions, unsupported renderers or
provenance modes, mutable collections, invalid UIDs, duplicate UIDs and malformed
values are rejected. Approval permission requires revocation support.

Approval always requires a completed preparation job whose report bytes/hash,
evidence fingerprint, investigation, target and renderer verify against the frozen
publication. A review event alone never meets this requirement. Deterministic
publications without preparation may be reviewed and declined. A decline adds a
review hash binding for the existing public review output, but cannot bootstrap
approval provenance. Revocation requires verified evidence and an immediately
preceding approval; it does not require the earlier policy version or earlier
actor to remain authorized. The revoking actor must be authorized under the active
policy. Unsupported renderers or unauthorized targets still fail closed.

By default approvals have no reason code; declines require `operator_declined`,
`incorrect_payload`, or `policy`; revocations require `operator_revoked`,
`incorrect_payload`, or `policy`. The policy can restrict these sets or require an
approval reason using schema-supported codes. Decline and revocation reasons
cannot be made optional. Reasons are bounded codes, not operator-provided prose.

## Internal decision contract

`Store.record_case_decision()` takes keyword-only arguments:

- `identity`, `policy`, unique `request_id`, `publication_id`, `decision`.
- Mandatory `expected_previous_event_id`: explicit `None` for an initial decision;
  omission is a Python argument error.
- Exact `expected_payload_sha256`, `expected_report_sha256`, `expected_target`,
  `expected_renderer_version`, and `expected_review_policy_version`.
- `confirmed=True` and optional `reason_code`.

Decision strings are `approved`, `declined`, `revoked`. Initially, and after a
decline or revocation, approval or decline is allowed. After approval only
revocation is allowed. Consecutive declines are allowed; consecutive approvals or
revocations are rejected. All new decisions require the current prepared head.
The engine compares every expectation without replacing stale values.

After validating input and authorizing the UID/principal, target and decision, the
engine opens one `BEGIN IMMEDIATE` connection, validates schema and authoritative policy generation, checks the request
ID, verifies frozen artifacts and evidence using the private connection-scoped
review verifier, checks head, bindings, predecessor, transition and policy, and
inserts parameterized SQL with a server UTC timestamp. Success returns the full
committed event dictionary only after commit. Errors roll back. No payload, report,
preparation, audit or publication state is modified by a decision.

## Replay

The request ID is globally unique. Access is authenticated by the caller's trusted
identity assertion and authorized against the active policy before lookup. An
existing request must match actor UID/principal/method, publication, decision,
predecessor, both hashes, target, renderer, policy version and reason exactly.
Confirmation must again be explicit. Changed content raises `StateError` with
`Request ID conflict`; exact replay returns the original event, timestamp and ID
without inserting another row. Server timestamp and event ID are not client intent.

Exact authorized replay is historical: it skips current head, state, provenance,
transition and policy-version equality checks. It can return an earlier event
after revocation, publication or policy rotation; it does **not** assert that the
approval remains effective. Active authorization can deny access to historical
requests. Use current review state and the publication claim gate for current
eligibility, never a replay result alone.

## Publication enforcement and compatibility

`claim_publication(publication_id, approval_hash)` keeps its signature and previous
noncandidate `False` result. For a matching prepared head, it additionally checks
the durable active generation and Store's matching policy in the existing immediate transaction before
updating state. It verifies the artifacts and evidence, latest approved event,
exact policy version, current UID/principal authorization, authentication method,
target, renderer, approval reason and preparation provenance. Existing hash,
head, state and database trigger guards still apply. Approval never sends a case.
`publish_case()` still requires explicit manual authorization and its exact reviewed
hash; network creation only follows a successful claim. Reconciliation does not
need a new claim and never enables a resend.

A default Store has no active policy and fails closed on any otherwise eligible
claim. Consequently the ordinary production CLI cannot initiate publication in
this stage, even if a durable approval was manually inserted. Authenticated socket decision dispatch is available in 6.3B-2B; no permissive default, policy label argument or environment override bypass exists. Already published results
and uncertain-outcome reconciliation preserve their existing behavior.

Historical schema/service tests use `tests.review_helpers.LegacyClaimStore`, an
explicit test-only override of the new application policy gate. Those synthetic
records predate completed preparation and active policy. This keeps the old
trigger/manual-publication/uncertain-outcome contracts exercised without a
production compatibility switch. `tests/test_approval.py` uses the real Store and
covers the full new gate and manual publication with valid preparation and policy.

## Remaining boundaries

Milestones 6.3B-2A/2B add protected policy loading and kernel-authenticated Unix
socket health and decision operations; see [the protocol](approval-socket.md).
Approval records authorization; it does not publish a case. Policy deployment
integration, operator CLI, automatic publication and remediation remain absent.
The example UID 10001 grant is effective and must be replaced before deployment. There
is no new runtime dependency or production infrastructure change. Deployment
ownership and permissions remain administrative responsibilities. Checksums detect stored
inconsistency; they do not authenticate a database against an actor able to rewrite
all artifacts and bindings. Publication credentials and the production assurance
platform remain operationally separate from approval decisions.

`Store.record_case_decision(..., deadline=None)` accepts an optional absolute
`time.monotonic()` deadline. Existing trusted callers may omit it; the authenticated
socket always passes its original accept-time deadline, shared with admission.
The transaction checks expiry before and after writer acquisition, cooperatively
through policy/evidence loops and hashing, through a SQLite progress handler, and
immediately before COMMIT. Any observed expiry before COMMIT rolls back all decision
writes. Progress handlers and context-local deadline state are cleaned up on exit.

This guarantee bounds cooperative execution, not kernel or filesystem latency.
Native JSON operations and other indivisible calls may overrun; their return is
followed by deadline checks and rollback before commit. COMMIT/fsync itself cannot
safely be interrupted: a commit begun before expiry may complete afterward. A client
may time out after a successful commit. Retry the unchanged request with its original
request ID to recover the committed historical event, subject to current authorization,
without a new event or review-head mutation. No thread is asynchronously cancelled.
