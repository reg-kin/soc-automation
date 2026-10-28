# Trusted policy administration foundation — Phase 2A

## Scope and implementation status

Implemented: `inspect_policy_ledger(store, *, deadline=None)` in
`approval_policy.py`, immutable `PolicyLedger` / `PolicyGeneration` results,
shared runtime history validation, and raw/canonical size guards. No new CLI,
daemon, socket, privileged writer, manifest writer, staging, replacement, recovery,
or deployment action is implemented. The interfaces below are a design contract
for subsequent review and implementation, not executable commands.

There is one authoritative SQLite database, one trusted soc-automation writer UID,
and one existing policy-generation ledger. Root controls policy installation.
Human operators retain socket-only approval access; membership in the operator
group conveys no installation authority. Approval decisions and publication
claims retain their existing semantics.

## Planned bounded offline command contract

Future root-only `soc-policy-admin` accepts exactly one operation: `install`,
`rotate`, `verify`, `inspect`, or `recover`. No interactive prompts, stdin policy,
environment overrides, alternate database/live paths, inferred expectations,
network retrieval, automatic selection, rollback, or implicit service restart.
Unknown/duplicate arguments are rejected. Production paths are fixed:

* Database: `/var/lib/soc-automation/soc_automation.db`.
* Live policy: `/etc/soc-approval/review-policy.json`.
* Persistent lock: `/var/lib/soc-policy-admin/admin.lock`.
* Operation evidence: `/var/lib/soc-policy-admin/operations/<operation-id>/`.

All operations require `--operation-id` (1–64 ASCII characters matching
`[A-Za-z0-9][A-Za-z0-9_-]{0,63}`), `--change-reference` (1–128 ASCII characters
matching `[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}`), and
`--expected-generation` (decimal integer 0–9223372036854775807; 0 explicitly means
empty bootstrap, mapped to Store's `None`). Nonzero values identify the exact
active generation. Digests below are exactly 64 lowercase hexadecimal characters.

| Operation | Additional required arguments | Success condition |
| --- | --- | --- |
| install | `--candidate`, `--candidate-sha256`; expected generation must be 0 | Fresh version committed as generation 1, live file fully verified |
| rotate | `--candidate`, `--candidate-sha256`, `--expected-current-sha256`; generation must be positive and less than maximum | Exact current generation/digest matched; fresh version committed as next generation, live file fully verified |
| inspect | None | Ledger valid, including empty; live-file agreement not required |
| verify | `--expected-current-sha256`; positive generation | Valid nonempty ledger, exact active generation/digest, protected live file matches |
| recover | `--candidate-sha256`, `--expected-current-sha256`; positive generation | Explicitly identified committed generation and operation evidence reconciled; protected live file fully verified |

`--candidate` is a normalized absolute protected regular-file path, at most 4096
UTF-8 bytes including filename; no symlinks, hardlinks, executable/special files,
or mutable ancestor directories. Candidate digest always means SHA-256 of the
complete canonical policy UTF-8 bytes, never raw file bytes. Candidate version
must be byte-for-byte unchanged and absent from every historical generation.
A new operation ID cannot reuse an evidence directory. `recover` refers to the
original operation ID and original change reference; it never creates a new
installation. It supplies the intended candidate digest and the now-active digest
(they must agree). Precommit abandonment uses inspect and an explicit root
maintenance assessment; recover cannot invent a commit.

Every invocation emits one bounded JSON object on stdout, maximum 4096 UTF-8 bytes,
with exactly: `contract_version` (1), `operation`, `operation_id`, `status`
(`ok` or `error`), `active_generation` (integer or null), `active_sha256` (digest or
null), `live_match` (boolean or null), `error` (classification or null).
Invalid or unavailable operation/operation_id values are null rather than echoed.
Unvalidated/unavailable authority yields null authority fields. No policy content,
principals, raw exceptions, SQLite diagnostics, candidate paths, or secret values
are emitted. stderr remains empty. Exit 0 means the stated operation succeeded;
exit 2 means `invalid_arguments`; exit 3 means `permission_denied` or
`unsafe_path`; exit 4 means `maintenance_required` or `lock_busy`; exit 5 means
`invalid_candidate`, `size_limit`, `digest_mismatch`, `version_reused`, or
`expectation_conflict`; exit 6 means `authority_unavailable`, `schema_unsupported`,
`history_corrupt`, `io_failure`, or `recovery_required`. Errors never imply that
an uncertain commit did not happen. Partial output/termination is uncertain and
requires inspection. Internal exception causes are not an external error API.

## Trust boundaries and maintenance prerequisites

Root launches the future offline utility in a controlled environment with no
operator-supplied import paths or executable hooks. Before mutation, root stops
admission and quiesces all approval, preparation, publication and database writers,
including existing processes and in-flight requests. Merely stopping a socket
listener is insufficient. The maintenance gate remains closed until explicit full
verification and deliberate service resumption. No new administrative daemon or
socket is introduced.

Root owns the policy directory (0750, root/service group) and live policy
(0640, root/service group): service-readable, never service-writable. Every
ancestor is pinned and checked without following symlinks. Candidate ownership
is root, with no group/other writes or unsafe ancestors; its identity and metadata
must remain stable during bounded reading. Production cannot use the test-only
configurable owner UID as an ownership relaxation.

The administration directory, persistent lock inode, and durable evidence are
root-owned, root-only (0700 directories, 0600 files), outside service-writable
storage. Lock acquisition pins a validated inode; never unlink the lock to
release it. Hold an exclusive lock across inspection, staging, commit,
replacement, verification and evidence updates. Refuse overlapping or unresolved
operations. Evidence and staged bytes must survive reboot; `/run` is insufficient.

All future administrative database access runs in a child with the trusted
service UID; only that UID writes SQLite. Ordinary SQLite read-only connections
may create WAL sidecars; strict inspection instead uses the separate nonmutating
path documented below. Root must never
open SQLite in a mode that creates root-owned WAL/SHM/journal sidecars. Drop
supplementary groups and privileges before opening the DB; use fixed code and
bounded structured IPC, not shell commands. The child repeats full ledger
validation and generation/current-digest CAS inside the write transaction. Parent
validates the reply and independently verifies durable authority afterward. Root
owns filesystem replacement; the child cannot replace policy or evidence.
Service UID compromise can alter database state: this architecture trusts that UID
and does not supply tamper-proof audit against it or root.

## Implemented ledger inspection semantics

`verify_authority` retains the Store's existing runtime read connection.
`inspect_policy_ledger(Store(path), deadline=None)` never
opens the source through SQLite: a fixed-program helper process under the same
UID opens a regular file read-only on Linux with
O_NOFOLLOW, acquires a nonblocking shared OFD lock over SQLite's pending, reserved
and shared lock bytes (1073741824 through 1073742335), and reads the main file
while holding that lock. The helper returns only snapshot bytes; failures become
a sanitized unavailable error. Process isolation is required: closing source file
descriptors in the parent could release its runtime SQLite POSIX locks. The
helper neither drops nor gains privileges and is not the planned privileged
administration child. A private SQLite `:memory:` connection deserializes the
bytes and runs the same validation in a query-only transaction. This requires
SQLite deserialize support and Linux native OFD/struct-flock support. Unsupported
platforms, locking failures and unreadable inputs fail closed. `mode=ro` alone
does not guarantee filesystem nonmutation.

Only rollback-format headers (read/write versions both 1) with no `-journal`,
`-wal` or `-shm` entry are supported. All WAL states are explicitly unavailable,
including absent sidecars and existing sidecars containing committed transactions;
no main-only WAL snapshot is returned. Inspection never changes journal mode,
checkpoints, recovers, or opens sidecars. A pending/reserved/exclusive writer
conflicts with the OFD lock; with a deadline the helper retries that same lock
until the original deadline, otherwise it reports unavailable. The parent enforces the original deadline
across helper startup, IPC and lock acquisition; on timeout it kills and reaps
the helper. Missing SQLite deserialize support is also unavailable.

This contract assumes a trusted local Linux filesystem with working POSIX/OFD
lock interoperability and ordinary SQLite unix VFS writers. Network filesystems,
custom/no-lock VFS writers, hostile direct file writers, concurrent pathname
replacement/unlink, and incompatible native flock ABIs are unsupported operating
conditions. Administrators must quiesce pathname changes and nonconforming writers.
Read access may update filesystem access timestamps; nonmutation means directory
entries and database/sidecar bytes, not atime. The whole database snapshot consumes
memory; deadlines are checked around the file read, which cannot interrupt blocked
OS I/O. No live database copy is taken without the rollback lock.

Inspection does not initialize, migrate,
create a missing database, install a policy, or read a live file. It validates the
supported schema (including existing exact policy table/trigger definitions),
contiguous generations starting at 1, every historical policy's canonical content
and ReviewPolicy semantics, SHA-256/content/version binding, and unique versions.
The immutable result contains all generations with generation, version, content,
content_sha256 and installed_at; `active` is the last entry or None. Timestamps
are ledger metadata, not authenticated administrator attribution. Empty valid
schema is a bootstrap state, never permission for runtime admission.

Inspection returns evidence of its read snapshot; it is not a lease, CAS token,
or alternative authority. It may observe superseded state after its transaction
ends. `verify_authority` uses the same history validation and additionally requires
a nonempty ledger and exact active canonical content matching its policy. Busy
snapshot retries retain existing deadline behavior; invalid/unavailable state is
sanitized to StateError and deadline expiry raises TimeoutError. No approval or
publication authority check is relaxed.

Raw policy JSON and canonical policy content each have an inclusive 65536-byte
UTF-8 limit. Protected reads are bounded to limit+1. Direct parsing rejects raw
oversize before JSON parsing; canonical serialization is checked after semantic
validation; trusted Store installation rejects oversized canonical content before
opening its write connection. Historical content has the same limit. The exact
ReviewPolicy dataclass, canonical ordering, compact serialization, ASCII escaping,
and SHA-256 over canonical UTF-8 are preserved. Versions are never stripped,
case-folded, normalized or silently rewritten. No additional policy fields exist.

## Planned crash consistency and recovery

The mandatory order is **STAGE → LEDGER COMMIT → FILE REPLACEMENT → VERIFICATION**.
There is no atomic transaction spanning SQLite and the filesystem. The ledger is
the sole authority at every point. A manifest records bounded operation metadata,
expected old generation/digest, reviewed candidate digest/version, stage identity,
and progress; it is recovery evidence, never a policy database. A progress label
cannot prove commit or authorize choosing a policy. Evidence updates use a durable
file, atomic rename and directory fsync; staged content uses file and directory
fsync. SQLite commit uses its existing FULL durability settings.

| Boundary / interruption | Required behavior on next invocation |
| --- | --- |
| Before candidate validation completes | No mutation; reject invalid candidate; remain in maintenance if already quiesced |
| Validated, before durable intent | Ledger and live file untouched; no operation may be inferred from memory |
| Intent file fsync but before evidence-directory fsync | Intent durability uncertain; inspect authority and disk evidence, do not assume absent intent proves no commit |
| Durable intent, before complete staging | Old authority remains; validate evidence and discard incomplete staging only under explicit assessment |
| Stage file fsync but before stage-directory fsync | Stage may be absent after reboot; no commit permitted until durable stage verified |
| Durable stage, before ledger transaction | Old authority remains; explicitly abandon or begin a newly reviewed operation after assessment; never automatically install staged content |
| During transaction or uncertain child reply | Query validated ledger before any retry; classify unchanged old state, exact intended new state, or unresolved divergence |
| Ledger commit durable, before manifest progress update | New generation is authoritative regardless of manifest label; never roll it back |
| Commit confirmed, before file replacement | Admission closed; recover exact committed content only, requiring matching reviewed evidence and explicit expectations |
| Replacement rename, before policy-directory fsync | Live name durability uncertain; re-read ledger and protected file; reconcile only to exact committed authority |
| Policy directory durable, before full verification | Replacement alone is not success; validate entire ledger, ownership, bytes and digest again |
| Verification complete, before durable completion evidence | Reverify after restart; uncertain completion is not permission to resume |
| Completion evidence durable | Explicit fresh full verification is required before deliberate service resumption |

Full verification checks schema, all history, exact intended active generation,
canonical candidate digest/version, protected path metadata and exact live policy
content. Mismatch, missing stage/evidence, corrupt history, unexpected generations,
or conflicting operation IDs keep admission closed. If a valid committed policy
can be reconstructed from canonical ledger content, recovery still requires an
explicit matching digest/generation and reviewed root evidence; no automatic policy
selection. Missing or contradictory evidence requires manual assessment, not an
unrecorded repair. A precommit operation may be explicitly abandoned only after
proving the ledger unchanged; a changed/uncertain ledger forbids blind retry.

Never automatically roll back committed generations, reuse historical versions,
repair corrupt history, or resume admission during unresolved mismatch. A desired
return to older semantics is a **forward rollback**: reviewed content with a fresh
version, a new operation ID, and a new generation through ordinary rotation after
reconciliation. Backup restoration/history reconstruction is a separately reviewed
disaster-recovery procedure, outside this utility's repair authority.

## Attribution, remaining stages and host acceptance

Operation ID and change reference are administrator-supplied correlation labels,
not proof of a particular human. Root credentials identify the execution boundary;
sudo/session records may supplement attribution but root can alter local evidence.
The existing ledger stores generation/version/content/digest/time, not a signed
administrator identity. Do not claim cryptographic nonrepudiation or expand the
policy schema to simulate it.

Remaining stages implement and review argument parsing, root maintenance gating,
lock/evidence durability, protected staging, service-UID child/CAS protocol,
replacement, explicit recovery and final verification. No Phase 2A component
provides these privileged lifecycle guarantees yet.

Before host deployment, demonstrate ownership and ancestor checks, socket-only
operator access, one service writer UID, absent root-owned SQLite sidecars, reliable
quiescence of every writer and in-flight request, persistent exclusive locking,
and durable evidence. Test interruption at every boundary (including commit with
lost IPC reply, rename without fsync and reboot), concurrent stale operations,
corrupt/missing evidence/history, backup restoration procedures and fail-closed
admission. Verify service cannot write policy/evidence and operators cannot access
DB or admin paths. Verify no automatic restart and deliberate verified resumption.
Repository tests cannot establish filesystem/power-loss or deployed UID guarantees;
production acceptance and privileged implementation remain separate work.

## Inspection resource and deadline contract

The inclusive main-database snapshot limit is **67,108,864 bytes (64 MiB)**,
including unused SQLite pages and all non-policy tables. Larger databases require
separately reviewed support; this interface never truncates a database or cuts off
policy generations. Every historical generation is validated before any authority
is returned. The existing inclusive 65,536-byte raw/canonical policy limits remain.

The helper checks file size after acquiring the source lock and before allocating
the snapshot, copies in chunks of at most 65,536 bytes up to that size, and rejects
short reads, changed final size, or any byte beyond the initial end. Conforming
SQLite writers cannot change size under this lock. Maintenance exclusion must also
prevent pathname replacement and direct/nonconforming writers: size comparisons
cannot detect hostile same-size rewrites or replace the exclusion requirement.

IPC consists of an eight-byte unsigned big-endian length followed by exactly that
many database bytes and EOF. The inclusive IPC limit is **67,108,872 bytes**.
The parent independently bounds reads to that limit plus one detection byte,
rejects oversized declared lengths, extra bytes, short frames and nonzero helper
exit status, and discards stderr without capture. Deserialization receives at most
67,108,864 bytes, only after framing and exit validation. Buffer copies and SQLite
allocations add bounded-input memory overhead; these byte limits are not an RSS
quota. SQLite queries and the complete immutable history also consume memory.

One absolute monotonic deadline covers helper startup, lock acquisition, copying,
IPC, deserialization, schema/SQLite validation, every historical policy check and
successful return. Cooperative checks surround synchronous work and precede the
final return after connection cleanup. SQLite's progress handler interrupts query
execution; only interruption attributed to that deadline handler becomes
TimeoutError. Other SQLite failures remain sanitized StateError failures. No
partially validated ledger is returned. Timeout and resource failures terminate
and reap a still-running helper, close pipes/connections and release source locks.
Errors disclose only fixed classifications, including snapshot size limit or
malformed IPC; helper diagnostics are never forwarded. No administrative mutation
is retried or implemented.

These are cooperative deadlines, not hard real-time guarantees. Uninterruptible
kernel I/O, process creation/termination/reaping, deserialization, and individual
Python/SQLite operations may delay detection or cleanup beyond the deadline.
The supported journal states and filesystem exclusions above apply to successes
and failures alike: rollback-format main files with no journal/WAL/SHM entry only;
hot rollback journals are rejected without recovery. Directory entries and source
and sidecar bytes remain unchanged; atime updates remain the documented exception.
