# Secure approval deployment — Milestone 6.3B-3C Phase 2

These are offline assets, not an installation or a production certification.
Baseline: `05339f076a8885d6a7c1412f51daef3f7c045960`.
No accounts, permissions, policies, services or persistent databases are changed
by this milestone. Do not enable the unit until the prerequisites below have
been independently provisioned and reviewed.

## Architecture and privileges

`deploy/soc-approval.service` runs the installed Python module
`soc_automation.approval_daemon` using the existing `ApprovalSocketService`.
Install the package into the administrator-controlled virtual environment at
`/opt/soc-automation/.venv`; `-I` excludes user site packages, environment Python
settings and the working directory from import resolution. Editable installations
pointing into a user-writable checkout are unsuitable for production. Code, the
interpreter, unit and every ancestor must be administrator-controlled. No SOC
environment file, provider credential or publication credential is loaded.

Use the single trusted non-login `soc-automation` user and private `soc-automation`
group, and an explicit `soc-approval-operators` group. The unit's primary group is
operators so systemd creates the runtime directory with the required GID. The
private supplementary group permits policy reads. The launcher verifies that
its real/effective UID is the dedicated nonzero UID and that its groups include
the operator GID. It offers no root or service-UID authorization exception.
Only the service should have the private group. Operators must not share its UID.

| Path | Owner / group | Mode |
| --- | --- | --- |
| `/etc/soc-approval` | root / soc-automation | 0750 |
| `/etc/soc-approval/review-policy.json` | root / soc-automation | 0640 |
| `/var/lib/soc-automation` | soc-automation / soc-approval-operators | 0700 |
| `/var/lib/soc-automation/soc_automation.db` | soc-automation / soc-approval-operators | 0600 |
| SQLite `-journal`, `-wal`, `-shm` when present | service UID | 0600 |
| `/run/soc-approval` | soc-automation / soc-approval-operators | 0750 |
| `operator.sock` | soc-automation / soc-approval-operators | 0660 |
| `operator.sock.lock` | service UID | 0600 |

The operator GID on state files grants no access with these modes. Never add
operator ACLs to the state tree or backups. The database must already exist with
supported schema and installed policy authority. StateDirectory is persistent
storage, not database initialization; the launcher never creates or migrates it.
Preflight verifies database/sidecar regular-file type, single link, ownership,
0600 mode and state-directory 0700 mode. Ancestors reject symlinks and untrusted
ownership or group/other writes. The private directory prevents untrusted
replacement between validation and SQLite open. The service UID and database
writers remain trusted; this is not isolation from a compromised service.

The process has no Linux capabilities or privilege escalation, has filesystem,
namespace and process hardening, and can write only its state/runtime trees
(plus its isolated temporary area). It needs Linux procfs `/proc/self/fd` for
pinned-directory Unix socket binding; do not hide that path. No IP socket family
is permitted. There are no TCP listeners or external calls. `TasksMax=16` covers
the main process and eight bounded workers; no publication, policy installation,
reconciliation or remediation command is dispatched.

The unit uses Type=notify, a 30-second startup bound including ExecStartPre
`--check` and listener startup, a ten-second shutdown bound and rate-limited
on-failure restart. The main process sends READY=1 only after policy validation
and successful socket binding, using the manager-provided NOTIFY_SOCKET Unix
datagram address. That environment value controls supervisor notification only,
never application paths or authority. Runtime configuration may take time on a
failing filesystem; the supervisor bounds the process. Authenticated `approval-service-health` is the readiness check, using a
real authorized operator UID and an explicit authorized target. Root or service
health probes are deliberately denied. No automatic decision is a health probe.

RuntimeDirectoryPreserve=yes retains both socket and lock on stop/restart.
Clean shutdown removes only the service's exact bound socket inode and leaves
the lock. A crash leaves a stale socket and subsequent starts fail closed.
Administrators must stop the unit, exclude competing listeners/restarts and
establish that no listener owns the socket before removing only the stale socket.
Never unlink the lock while a process could hold it. `/run` is cleared at boot
when old processes cannot survive. Do not add a socket activation unit, tmpfiles
cleanup, ExecStartPre unlink, or automatic stale-socket recovery.

## Offline policy provisioning and recovery

1. Review numeric UIDs against the target host's account inventory; use distinct
   stable principals. Check operator group membership with the host's account
   management tools and require a new login session when membership changes.
   Group membership permits connecting; only an active UID mapping authorizes
   operations. Remove mappings before recycling UIDs. SO_PEERCRED does not prove
   recent human authentication and connected descriptors must not be forwarded.
2. Copy the example as a candidate, never as a live policy. Its string UID
   placeholder deliberately fails strict validation; UID 10001 is no longer a
   grant. Replace the placeholder, principal, canonical target(s), and version.
   Every mapped principal receives the policy's target and decision sets; there
   are no per-principal subsets. Use separate service/policy deployments when
   those scopes must differ. Keep root and service UIDs absent.
3. Stage the candidate under administrator-owned trusted ancestors. All parents
   including `/` must be root-owned (or explicitly selected administrator UID
   for API-only validation), with no group/other write permission or symlinks.
   Require a single-link administrator-owned regular policy file without execute,
   special or group/other write bits; production uses 0640 with the private group.
   The launcher additionally rejects any other-account policy access bits.
   Group/ACL/LSM settings must permit the service to read it without operator
   access. Do not use `/tmp`, symlinks, in-place writes, or operator-writable paths.
4. In an administrator-controlled offline process, use
   `PolicySource(candidate_path).read_candidate()` to check protected paths and
   strict semantics. This checks no account inventory and grants no authority.
   Validate UID/group membership separately on the intended host. No supplied
   command installs or rotates a policy. Existing trusted APIs and compare-and-swap
   installation are documented in [approval socket administration](approval-socket.md).
5. Before bootstrap or rotation, stop admission and other database writers,
   take a verified consistent backup, and assess schema compatibility. Bootstrap
   uses `Store.install_review_policy(candidate, expected_generation=None)` only
   for an empty ledger; rotation requires the exact current positive generation.
   Each version must be new. Never edit history or reset the ledger. A rollback
   of policy intent also needs a fresh version and forward generation.
6. Install only after separate administrative review. Replace the protected file
   atomically from a same-directory staged file with verified owner/group/mode
   and a single link; synchronize staged content and directory for durability.
   Do not change ownership or modes after exposing an untrusted candidate.
   Stop competing privileged file writers. Installation and rename are not one
   transaction: a crash or mismatch intentionally prevents admission.
7. Recover a mismatch by retaining backups, reading the authoritative ledger
   through trusted administration, and restoring a protected file with the exact
   active canonical policy content. `PolicySource.load(store)` checks every
   generation, digest/version and exact active content; it never adopts a candidate.
   If the intended policy differs, perform another authorized forward generation.
   Do not restore an older database just to bypass a newer policy generation.
   Run the unit's exact `--check` command under the service identity, then start
   and test operator health. This task does not perform those host actions.

`--check` is read-only and opens no listener; it checks identity, protected state,
runtime-directory modes, schema and active policy consistency. systemd creates
its directories before ExecStartPre. Running it directly requires those paths
already provisioned. There are no configuration path flags or environment
fallbacks. Tests use synthetic protected home directories and temporary databases.

## Migration 010 compatibility

The framework applies numbered SQL files transactionally through individual
complete statements, then advances `PRAGMA user_version`. It has **no checksum
ledger**. At version 10, initialize skips migration 010. Repository history
contains only the current migration 010 (introduced at `f9dc8e6`); no historical
older 010 definition is available here to certify or automatically transform.
An externally used older 010 can therefore be incompatible despite version 10.

Validation now compares the SQLite-stored table, index and trigger definitions
for `review_policy_generations` to an in-memory execution of the unchanged
repository migration 010. Missing objects, altered columns, weaker triggers and
extra objects on that table all fail closed, including on initialize. Exact SQL
comparison deliberately rejects ambiguous equivalent rewrites too. This is a
current schema assessment, not proof of the original applied migration bytes or
protection from privileged database writers. Other migration bodies are not fully
fingerprinted. Full authority semantics are independently checked by policy load.

Fresh initialization and schema 9 to current 10 work and install no policy.
Existing matching 10 works; divergent 10 receives `Migration 010 schema
incompatible; administrative assessment required` internally (the launcher emits
a generic failure). No applied migration was edited, no version advanced to hide
incompatibility, and no automatic repair or new migration is provided. The
framework supports a future numbered forward migration, but an uncharacterized
older schema/data layout cannot safely be transformed by guessing. Obtain its
original SQL, inspect constraints/data/history and design a separately reviewed
forward migration with explicit preconditions if such a database exists.

Before migration or investigation, quiesce all writers and take an access-restricted
SQLite backup using the SQLite backup API or a validated SQLite-aware backup
procedure. Copying only the main file from a live WAL database is insufficient.
Retain schema SQL, user_version, code version and ledger inventory with the backup;
verify integrity/foreign keys and test restore on a separate temporary copy.
Assess with `Store._validate` in a read-only connection and
`PolicySource.load(store)` under trusted administration. Never delete/reset the
database, silently rerun applied SQL, lower user_version, remove history, or
manually replace triggers as a production repair. Preserve an incompatible
original for investigation. Any full disaster restore needs separate incident
review to avoid losing decisions or rolling back authorization history.

## Operator review access

Use the existing `list-case-publications` and `review-case-publication` read-only
workflow through an already authorized trusted reviewer. SQLite mode=ro does not
itself grant filesystem access or constitute target authorization. Do not add
operators to the service group or give them database/backup access. A reviewer
with authorized access can review a consistent protected backup, avoiding write
access to the live database; backups contain sensitive information across targets.

The reviewer securely conveys the verified frozen payload/report and exact
`id`, `target`, `state`, hashes, renderer, `is_current_head`, preparation provenance,
and latest event ID (or null) to the authorized operator. Include the active
policy version verified against the ledger by trusted administration; historical
event versions alone are insufficient. Require `prepared`, current head, verified
report binding and completed preparation provenance for approval. Review checks
and limits are specified in [frozen review](case-publication-review.md). The
operator then submits exact bindings through the existing CLI. State can change
after handoff; the decision transaction checks it again.

No read socket operation is necessary for this assisted workflow, and the wire
protocol remains health/approve/decline/revoke only. Independent self-service
socket-only discovery/review remains a separate dependency. Such an endpoint
would need authenticated UID and target authorization *before* disclosing any
record, filtering of cross-target discovery/history/identity data, bounded large
artifact responses and privacy review. The 4096-byte mutation transport is not a
safe implicit artifact export API. No mutation expansion is introduced here.

## Remaining gates

Account and path provisioning, installed-code integrity, Linux/systemd version
support, procfs/ACL/LSM access and distinct-account integration must be checked on
the intended host. Offline tests do not certify kernel hardening enforcement.
An actual divergent legacy 010 needs its source/schema and a reviewed recovery
plan. Trusted review handoff and administrative installation/backup processes
must exist before use. Self-service review requires separate work if required.
Publication stays disabled by the existing CLI's missing trusted publication
policy composition; this unit intentionally does not resolve that independent
dependency. It neither publishes real cases nor executes remediation.

The approval database is `/var/lib/soc-automation/soc_automation.db`, the same
live authority used by investigation, preparation, recovery and future trusted
publication composition. Configure all worker/recovery environment files and other
trusted CLI compositions to this exact absolute path; the approval daemon ignores
environment configuration. Never use a copied approval-only fork. All direct
writers run as `soc-automation` and belong to the approval-integrity trust boundary:
a compromised worker can affect approval authority. This architecture deliberately
does not isolate trusted writers from each other. Operators receive socket access
only and must never join the private service group. Read-only review backups must
never become an alternative decision authority.

## Journal policy and startup ordering

The default deployment policy is SQLite DELETE rollback journaling. Fresh explicit
`Store.initialize()` uses SQLite's default DELETE mode; initialization is an
administrator action, never a service startup action. Do not assume initialization
changes an existing database's journal mode. Under quiescence, an administrator
must inspect `PRAGMA journal_mode` and require `delete` for this default profile.
Approval startup checks that the existing mode is `delete` or `wal`, rejecting
other observed modes without changing them. Non-WAL modes such as PERSIST and
TRUNCATE are connection-local and are not a durable deployment selection; new
connections normally observe DELETE. This check is not an initialization
or migration command. Ordinary Store connections retain FULL synchronous mode,
foreign keys, and existing transaction/locking semantics.

WAL is a supported explicit administrative alternative, not enabled by these
assets. Before selecting it, stop all readers/writers and admission, take and test
a consistent backup, assess schema and policy, and obtain deployment review.
Only that controlled administrative connection may execute
`PRAGMA journal_mode=WAL` outside a transaction; require the returned value `wal`
and verify it again from a new connection. Record the selected profile in the host
runbook. Changing an existing database's mode requires this separate procedure;
no service performs it. Do not issue mode-setting PRAGMAs as health probes.

Provision code, accounts, protected policy, shared state and runtime directories
first; initialize/migrate schema and install matching policy authority only through
separate reviewed administration. Validate worker and recovery configuration before
starting any writer. Neither example unit initializes schema. Stop competing writers
during administration, run the exact isolated approval preflight as the service
identity, and start approval only after it succeeds. No extra systemd unit is needed.

WAL and SHM must be service-owned, single-link regular files, mode 0600, within the
0700 state directory; rollback journals have the same requirements. With WAL,
normal last-connection close may remove sidecars. Before confined preflight, trusted
administration must establish usable sidecars through SQLite with a controlled
connection retained as needed; never fabricate empty sidecars. Missing or unusable
sidecars, pending recovery or unsupported schema cause preflight failure. Diagnose
and recover under stopped admission; never bypass Landlock or use immutable reads.
A cleanly checkpointed WAL database without usable sidecars may still require this
administrative preparation before the read-only confined check can succeed.

Schedule and monitor checkpoints through trusted administration/writer composition;
long-lived readers can prevent completion. Before cold-file backup or restore, stop
all connections, perform and verify a complete SQLite checkpoint (for example
`PRAGMA wal_checkpoint(TRUNCATE)` with no busy readers), and close cleanly. Prefer
the SQLite backup API for consistent online backups. Never copy only a live main
file, delete WAL/SHM to repair failures, or discard committed uncheckpointed frames.
Retain the original database and sidecars for recovery assessment. Restore to a
temporary location first, verify integrity, foreign keys, schema and exact active
policy generation, and review authorization-history rollback risks before replacing
production state. Recheck modes and run confined preflight before reopening admission.

## Preflight confinement and limits

`--check` retains a disposable fork inspector. The launcher must be a fresh
execution of the installed, administrator-controlled Python module (`-I`, as in
the unit), before starting workers or opening application resources. It requires
readable Linux procfs: `/proc/self/task`, `/proc/self/smaps` and `/proc/self/fd`.
It fails closed if native threads or writable/potentially writable shared mappings are present,
or if these checks cannot be completed. It checks again in the child. Private
mappings are copy-on-write across fork. Shared read-only mappings with the kernel VM_MAYWRITE flag are rejected
too: these can potentially be upgraded with mprotect after their descriptor is
closed. Shared mappings without write or may-write permission (such as the libc
conversion cache) cannot be upgraded and are allowed. This avoids inheriting writable shared
mappings without adding another executable protocol or changing identities.
Do not embed preflight in an arbitrary running application; trusted startup code
must not race these checks with signal handlers that create threads or mappings.

Before confinement or inspection the child closes **every** inherited descriptor,
including 0, 1 and 2, irrespective of access mode or FD_CLOEXEC. Close-on-exec does
not protect a fork. Thus writable database, WAL/SHM, policy, directory, diagnostic
and other descriptors cannot bypass Landlock. The child opens no diagnostic
stream and reports only a bounded success/failure exit status to its waiting
parent. `--check` intentionally emits no child diagnostic; a nonzero status calls
for separate administrator assessment of confinement, provisioning and health.
Parent resources remain open in the parent, which performs no inspection writes.

On Linux x86-64 and aarch64, enabled Landlock ABI **3 or newer** is required.
An empty allowlist denies WRITE_FILE, TRUNCATE, REMOVE_DIR, REMOVE_FILE,
MAKE_CHAR, MAKE_DIR, MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM and
REFER (cross-directory reparenting/linking). This prevents existing-file content
writes, creation, truncation, rename, unlink and hard-link creation across the
filesystem, including database, sidecars, policy and their parent directories.
ABI 5 and newer also deny IOCTL_DEV. No read, execute or directory-read rights
are handled. `no_new_privs` is set before enforcing the ruleset. Missing kernel
support, unsupported architecture, failed resource sanitization, failed ruleset
installation or failed validation returns failure, with no unconstrained fallback.
New writable shared file mappings require a writable file descriptor; inherited
ones are rejected, inherited descriptors are closed and new writable opens are
denied. The inspector must not acquire descriptors from another process.

This is **not absolute filesystem immutability**. Landlock does not restrict
chmod, chown, timestamp changes and other metadata operations such as supported
extended-attribute changes. Reads may update access times according to the
filesystem and mount policy (including relatime); Landlock does not suppress
atime updates. Snapshot tests intentionally exclude atime. Do not infer metadata
immutability from tests observing unchanged content, namespace, mtime and ctime.

The inspector uses the existing SQLite `mode=ro` transaction and full
schema/authority validation, with no copy, checkpoint or repair. `immutable=1`
is deliberately not used: it assumes an unchanging database and can bypass WAL
handling, losing visibility of committed uncheckpointed transactions. Existing
usable WAL/SHM permit a read-only WAL reader and preserve committed WAL visibility.
Missing/unusable sidecars, recovery requirements or incompatible state cause
failure rather than validation of the main file alone. The snapshot starts at
the first SQLite read; later commits are outside that snapshot. Administrators
must resolve provisioning/health failures separately.

This is not general process isolation: reads, file locks, metadata operations,
process memory, IPC and other non-filesystem behavior are not comprehensively
confined by this ruleset. Trusted installed code, launcher context, service UID
and database writers remain assumptions. Ordinary service startup and writable
connections retain their existing behavior.

The concurrent exact-replay test uses test-only synchronization after both
requests pass admission, then a separate SQLite writer lock. It observes both
workers receiving SQLITE_BUSY on BEGIN IMMEDIATE before releasing that lock.
No two-party barrier runs inside competing write transactions. Waits are bounded,
cleanup releases workers/locks, and this test uses a generous local deadline;
production deadline tests remain separate. The original intermittent failure
trace was unavailable, so its root cause has not been proven.
