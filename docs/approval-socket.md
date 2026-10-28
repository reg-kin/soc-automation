# Authenticated case approval operations (6.3B-2B)

The Linux AF_UNIX service supports health, approve, decline and revoke through
schema 10's existing decision engine. Approval records authorization; it does not
publish a case. There is no publication, reconciliation, remediation, policy
administration or production service installation in this transport milestone.
The subsequent [operator CLI](operator-cli.md) uses this exact protocol.
See [internal approval persistence](internal-approval.md).

## Trust boundary and accounts

Trusted service composition constructs `PolicySource`, `SocketSettings`, and
`Store` with fixed administrator-selected absolute paths. There is no environment
configuration loader for this service and no request field for a policy, database,
socket path, identity, SQL, command, or migration. The existing CLI `--policy`
option configures ingestion only; it has no role here. Do not wrap these APIs in
an operator-controlled configuration or import path.

Use a dedicated service account, a separate administrator (normally UID 0), and
an operator group. Operators must have distinct Unix UIDs that map to stable
principal names in `ReviewPolicy.principals`. Numeric UID membership is necessary;
Unix group membership alone grants no application authority. The group permits
reaching the socket, while the policy permits health on its listed targets and the decision operations
mapped to its `decisions`: approve → approved, decline → declined, revoke → revoked.
All other operations are rejected.

Kernel `SO_PEERCRED` supplies PID, UID, and GID from each accepted stream. Only the
numeric UID selects a principal. PID/GID are obtained but do not grant authority.
The adapter constructs `TrustedIdentity` only after UID, operation, and target
checks. It never infers identity from environment variables, actor arguments, or
the service process's UID. Root and the configured service UID are denied even
when listed in the policy, by default. A deliberate exception requires **both**
an explicit UID-to-principal policy mapping in the installed generation **and**
the UID in trusted `SocketSettings.special_uids`. That set defaults to empty and
may contain only root and the service UID. Keep exceptions empty in deployment;
synthetic same-account offline tests explicitly enable the service UID exception.
These trusted settings must be protected as carefully as the policy.

SO_PEERCRED identifies the local process credentials associated with connection
creation. It does not establish recent human authentication, physical presence,
interactive intent, or the identity of a person sharing an account. Credential
changes after connection creation and forwarding/passing connected descriptors
are limitations. Compromised authorized accounts can exercise their authority.
Administrators must remove retired UIDs from policy *before* recycling accounts,
rotate the generation, and restart the service. Never reuse a principal as an
implicit way to grant a recycled UID access.

## Protected files and policy authority

An example layout, to be provisioned by administrators rather than the service:

| Path | Owner/group | Mode | Purpose |
| --- | --- | --- | --- |
| `/etc/soc-approval` | root / service group | 0750 | Protected policy directory |
| `/etc/soc-approval/review-policy.json` | root / service group | 0640 | Administrator policy |
| `/run/soc-approval` | service / operators | 0750 | Socket directory |
| `/run/soc-approval/operator.sock` | service / operators | 0660 | Created by service |
| `/var/lib/soc-automation` | service / service | 0700 | Existing initialized database |
| `/var/lib/soc-automation/soc_automation.db` | service / service | 0600 | Schema 10 authority |

All ancestors, including `/`, are checked. Policy ancestors must be owned by root
or `PolicySource.owner_uid`, with no group/other write bits. The policy itself
must belong to exactly that administrator UID, be a regular single-link file,
have no group/other write bits, executable bits, or special mode bits. The default
administrator UID is 0. Group read access is allowed so the unprivileged service
can read administrator-owned policy. No symlink or writable `/tmp` ancestor is
accepted, even with the sticky bit. Files, FIFOs, devices, directory substitutions,
and missing paths fail closed. Linux `openat` via `dir_fd`, `O_DIRECTORY`,
`O_NOFOLLOW`, `O_CLOEXEC`, and `fstat` pin and verify every component. File reads
are bounded and before/after metadata checks detect concurrent content changes;
access-time updates are deliberately excluded. Privileged path writers remain
trusted; this is not protection from a malicious administrator.

The policy is a complete JSON encoding of the existing `ReviewPolicy` fields;
[the template](../deploy/approval-policy.example.json) intentionally has a string
UID placeholder and fails validation. It contains no active numeric UID grant.
Replace it with reviewed operator UIDs and principals, and replace the target and
version before protected candidate validation. Never install the template unchanged.
Arrays represent tuples and sets. All fields are required;
unknown fields, duplicate keys, duplicate set items, floats (including overflow),
nonfinite constants, invalid UTF-8, and invalid policy types/values are rejected.
The maximum input is 65,536 bytes. The loader reconstructs `ReviewPolicy` and uses
its existing canonical complete content, including version, to bind semantics.
It verifies schema 10, contiguous generation numbers, unique versions, every
historical generation's strict policy semantics and canonical serialization,
SHA256, and version binding, and an exact match with the latest generation.
Whitespace in the policy file does not change the canonical digest. Loading
never creates a database, runs migrations, installs, rotates, or repairs policy.

`PolicySource.read_candidate()` performs only protected parsing. It is for
separate trusted administration; it does **not** establish active authority.
`PolicySource.load(store)` additionally requires durable authority. The service
loads at startup and rechecks its snapshot against the ledger before every
successful health response, in a short read-only transaction after socket input.
Missing, damaged, or superseded authority returns `policy_unavailable` at runtime
and prevents startup. No database transaction is held while reading clients.
There is no hot reload; rotation requires restarting with the new policy file.

Protect the database, its parent, journal/WAL files, backups, and all processes
with database write access. The loader verifies ledger consistency; it does not
cryptographically authenticate a database against a writer who can forge the
entire ledger. Schema validation now compares migration 010 policy objects with
the repository definitions; other migrations still check required object names
rather than all bodies. Publication and approval persistence retain
their existing independent checks. Decisions recheck authority inside the existing
atomic decision transaction.

## Explicit administrative installation and rotation

Administration is a separate, trusted in-process operation, not an endpoint or a
new CLI. The following is a composition sketch for an administrator-controlled
script, using fixed paths. It is not executed by this milestone:

```python
from pathlib import Path
from soc_automation.approval_policy import PolicySource
from soc_automation.state import Store

source = PolicySource(Path('/etc/soc-approval/review-policy.json'), owner_uid=0)
store = Store(Path('/var/lib/soc-automation/soc_automation.db'))
candidate = source.read_candidate()
# Only after separate administrative authentication/authorization:
store.install_review_policy(candidate, expected_generation=None)
```

Initialize/migrate the database through existing trusted administration first.
`None` is an explicit bootstrap of an empty ledger. For rotation, stop admission,
review a protected candidate with a never-used version, and supply the exact
current positive generation instead of `None`. The existing installation API
uses a compare-and-swap transaction. Install that candidate, atomically replace
the protected policy file with its matching content, preserving owner and mode,
and restart admission. Administrators must arrange database file ownership when
running their script; do not accidentally leave root-owned journals. A rollback
also requires a fresh version and a new generation. A mismatch during rollout
fails closed rather than silently installing file contents. Back up and audit
these administrative changes independently.

## Socket lifecycle and service composition

`ApprovalSocketService(settings, source, store).start()` validates the directory
and opens a persistent sibling `operator.sock.lock` with `O_NOFOLLOW`, requiring
a service-owned single-link regular file with no group/other permissions. A
nonblocking `flock` remains held for the listener's lifetime. Never unlink the
lock: doing so could let two processes lock different inodes. The socket directory
must be service-owned, have the configured operator GID, and have no group/other
write or other access bits. Its ancestors may be root-, administrator-, or
service-owned and must reject group/other writes and symlinks.

Binding uses Linux `/proc/self/fd/<directory-fd>/<socket-name>` to pin the socket
to the validated directory. Linux procfs is therefore a deployment requirement;
clients connect through the configured absolute public path. The service checks
the bound address, type, and owner, uses umask 0177 for initial creation, sets the
configured group, then mode 0660. A nonroot service can do this when it owns the
directory/socket and belongs to the operator group. Start before other application
threads: umask is process-global. It is restored immediately after bind. Put the
accept loop in `serve_forever()` and arrange a trusted signal handler to call
`close()`; the deployment launcher now supplies signal handling; see
[secure deployment](secure-approval-deployment.md).

Any existing socket path, even an apparently stale socket, prevents startup.
No automatic unlink occurs. A concurrent listener remains excluded even if its
socket name is removed. Shutdown stops accepting, waits for bounded workers,
and removes only the exact device/inode of the socket it created, relative to
the pinned directory. Replacement files, symlinks, and sockets survive cleanup.
A crash leaves the socket entry behind: an administrator must first establish
that no listener owns it and that no competing process can restart, then remove
only that stale entry. Do not remove the persistent lock file. An unexpected
replacement, owner change, or authority mismatch requires investigation, not an
unconditional unlink or policy adoption.

The default concurrency limit is eight active handlers (configurable 1–64);
excess accepted clients receive `busy` and close. The kernel backlog is bounded
by the same setting. Each accepted request has a monotonic total request deadline
(default two seconds; configurable 0.05–30), so drip-fed bytes do not reset it.
Writes have a maximum 0.1-second window, including a small window after an input
timeout for its error response. SQLite admission and decision checks disable native
busy waiting and use deadline-aware lock retries and a deadline progress handler. Host scheduling and
filesystem stalls are not hard real-time bounded. Apply supervisor process and
resource limits in deployment. These controls limit resource use; authorized
local clients can still deny service by repeatedly filling all slots.

## Protocol version 1

Only Linux AF_UNIX/SOCK_STREAM is supported. There is no TCP/HTTP listener or
outbound network call. Each connection carries exactly one request:

1. Four-byte unsigned big-endian payload length, from 1 through 4096.
2. That many bytes of UTF-8 JSON.
3. Client write-half shutdown (`shutdown(SHUT_WR)`); extra bytes are rejected.

```json
{"version":1,"operation":"health","target":"https://example.test/default/securitySolution"}
```

Health requires exactly those three fields and preserves its existing response:
`{"ok":true,"operation":"health","version":1}`.

Decisions require exactly the following fields; substitute `decline` or `revoke`
for `approve` as appropriate:

```json
{
  "version": 1,
  "operation": "approve",
  "target": "https://example.test/default/securitySolution",
  "request_id": "operator-intent-unique-1",
  "publication_id": "exact-publication-id",
  "expected_state": "prepared",
  "expected_previous_event_id": null,
  "expected_payload_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_report_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "expected_renderer_version": "soc-case/2",
  "expected_review_policy_version": "review/1",
  "confirmed": true,
  "reason_code": null
}
```

All fields are mandatory, including explicit null predecessor and reason when
appropriate. Identifiers are nonblank strings of at most 256 characters with no
characters below U+0020. Hashes are exactly 64 lowercase hexadecimal characters.
The predecessor is null initially, otherwise an integer from 1 through 2^63−1;
bools are rejected. Renderer and review version are existing engine tokens of
1–256 ASCII letters/digits and `:._/-`, starting with a letter/digit. State must
be the literal `prepared`; other strings return `stale_publication_state`.
Confirmation must be the boolean true. Version is integer 1. Operation and target
are strings. Unknown fields, identity/authority claims, payloads, unsupported types,
duplicate keys, floats and nonfinite constants are rejected. The 4096-byte limit
and one-request framing remain unchanged.

Reason is null or an existing bounded reason code: `operator_declined`,
`operator_revoked`, `incorrect_payload`, `policy`. New decisions must use a code
allowed by the installed policy for that outcome; an empty reason set requires
null. Default approval requires null, decline requires `operator_declined`,
`incorrect_payload` or `policy`, and revoke requires `operator_revoked`,
`incorrect_payload` or `policy`. No free-form reason text is accepted.

Obtain exact bindings through the trusted offline publication review workflow.
The engine verifies frozen payload, report, evidence ledger, renderer, current
prepared head and predecessor in its transaction. Approval additionally requires
verified completed preparation provenance. Decline/revoke accept verified evidence
under their existing policy. Initially or after decline/revocation, approve or
decline is allowed. After approval only revoke is allowed. Published, sending,
uncertain and superseded records cannot receive new decisions.

A successful decision response has exactly these fields:

```json
{"version":1,"ok":true,"event_id":1,"outcome":"approved","historical":true}
```

`event_id` is the durable positive review event ID; outcome is `approved`,
`declined` or `revoked`. Every result describes a recorded historical event,
including the first response. It never asserts current effective approval.
No evidence, identity, timestamps or policy contents are returned.

Every request obtains SO_PEERCRED, resolves UID using the retained trusted policy,
and authorizes the operation and target before mutation. Only then is
TrustedIdentity constructed. Full authoritative ledger verification precedes dispatch;
the Store rechecks the exact active generation in its BEGIN IMMEDIATE transaction.
Rotation and decisions serialize on the same SQLite writer lock. If rotation wins,
stale authority cannot persist a decision. If the decision wins, its event remains
auditable after rotation. Restart with matching protected policy after rotation;
there is no implicit adoption or installation. Existing root/service exclusions
and trusted test-only exception composition remain unchanged; no new override exists.

The globally unique request ID binds the engine's full immutable intent. Exact
authorized replay returns the original event without another write, even after
revocation or publication state changes. It skips current eligibility checks;
the required `prepared` expectation describes the original intent. Conflicting
reuse returns `conflicting_request_id`. A current retained authority is always
required, even for replay. After restart under a rotated policy, authorized
historical replay may retain the original expected review policy version.

Commit completes before response writing. A disconnected client or failed response
write does not undo it. No automatic retries occur. On a missing/truncated response,
retry the identical intent with the same request ID to discover the historical
outcome; do not generate a new ID merely because delivery failed.

Errors have exactly `version:1`, `ok:false`, and a stable `error` string:

| Code | Meaning |
| --- | --- |
| `authentication_failure` | Kernel peer credentials unavailable/invalid |
| `unauthorized` | UID, special UID, operation or target denied |
| `invalid_request` | Invalid JSON, fields, types, confirmation or reason |
| `policy_unavailable` | Missing, invalid, superseded or mismatched policy authority |
| `stale_publication_state` | Wrong state, head, publication or artifact binding |
| `conflicting_request_id` | Existing request has different intent |
| `invalid_review_transition` | Stale predecessor or disallowed transition |
| `evidence_verification_failure` | Corrupt artifacts/evidence or missing approval provenance |
| `internal_failure` | Other decision/internal failure, including database contention |

Existing framing/admission codes remain `unsupported_version`, `request_too_large`,
`truncated_request`, `timeout`, `busy`; health retains generic `unavailable`.
No exception text, SQL, paths, secrets or tracebacks are transmitted. Error delivery
cannot be guaranteed. An internal failure is not permission to change the intent.

Offline tests use synthetic SQLite and temporary real AF_UNIX sockets. IP sockets
and DNS remain blocked. Coverage includes strict admission, all decisions, replay,
conflicts, predecessor/state/hash guards, evidence and provenance, concurrent heads,
rotation ordering, and response loss after commit. No Kibana or remediation call
is dispatched; decision persistence only adds a review event.

Remaining limitations include account provisioning, distinct-account access,
ACL/LSM and capability enforcement, UID namespaces/recycling, descriptor passing,
recent human authentication, supervisor hardening, administrator authentication,
backup integrity and production procfs availability. Authorized account compromise
can exercise that account's policy. Database writers and trusted in-process code
remain privileged. Checksums do not defend against a writer rewriting every binding.
No production deployment is certified. The template is intentionally invalid until
provisioned. See [secure deployment](secure-approval-deployment.md) for the launcher
and offline deployment checks.

Decision execution uses the same absolute monotonic deadline established when
accepting the connection; admission and database delays never renew it. The durable
decision API checks expiry before and after acquiring the writer lock, during
policy/evidence verification and chunked hashing, and immediately before COMMIT.
SQLite VM work has a progress handler; writer acquisition retries without a SQLite
busy wait, checking the remaining budget. Expiry before commit rolls back the whole
transaction, including any inserted review event, and returns the sanitized `timeout`
error when the response can still be delivered. Connection handlers are removed
and transaction context is reset on every exit.

Transient `SQLITE_BUSY` (including `SQLITE_BUSY_SNAPSHOT` and SQLite errors
directly chained by the ledger helper into `StateError`) inside policy admission
restarts the complete read-only authority transaction after rollback and connection
closure. Every attempt revalidates the schema, ledger and exact active policy in a
fresh snapshot, using the original request deadline. Retry pauses are at most 5 ms
and capped by the remaining budget. Held contention expires as `timeout`; genuine
policy corruption or supersession remains `policy_unavailable`. This retry does
not replay approval mutations or an uncertain commit and does not change the
request-ID replay contract. Administrative loading without a request deadline
retains its existing SQLite timeout and does not restart authority transactions.

This is a cooperative execution deadline, not a hard real-time completion bound.
Filesystem/kernel calls, JSON parsing/serialization, individual native operations,
and COMMIT/fsync cannot safely be interrupted. After such verification work returns,
expiry prevents commit. A COMMIT started within the deadline can finish after it;
its durable outcome must be treated as committed. No asynchronous thread cancellation
is used. Response delivery can time out or the client can disconnect after commit.
Retry the exact original intent with its original request ID: an authorized exact
replay returns the existing event without adding an event or changing the review
head. Current UID, operation and target authorization still apply to every retry.

Production assets and current operational requirements are documented in
[secure approval deployment](secure-approval-deployment.md).
