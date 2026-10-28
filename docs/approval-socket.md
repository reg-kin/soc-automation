# Local authenticated admission foundation (6.3B-2A)

This stage supplies tested Linux library code for protected policy loading and an
AF_UNIX health endpoint. It does **not** supply a production approval command,
production service installation, approval mutation dispatch, publication,
reconciliation, remediation, or an administrative socket endpoint. Existing
persistence and publication guards remain in place. See
[internal approval persistence](internal-approval.md) for the schema 10 contract.

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
reaching the socket, while the policy permits the one `health` operation for its
listed targets. Review decisions in `ReviewPolicy.decisions` retain their existing
meaning and do not enable transport operations. All other operations are rejected.

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
| `/var/lib/soc-approval` | service / service | 0700 | Existing initialized database |
| `/var/lib/soc-approval/soc_automation.db` | service / service | 0600 | Schema 10 authority |

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
[the example](../deploy/approval-policy.example.json) contains an effective
placeholder grant: UID 10001 maps to `example:operator` and can authenticate for
health on the example target (subject to the root/service UID restrictions).
The existing schema requires at least one UID mapping, so this is not a
deny-by-default policy. Replace this grant with reviewed operator UIDs and
principals, and replace the target and version before installation. Never install
the example unchanged. Arrays represent tuples and sets. All fields are required;
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
entire ledger. Existing schema validation checks required schema objects, not
maliciously rewritten trigger bodies. Publication and approval persistence retain
their existing independent checks; this endpoint calls neither. A future mutation
adapter must recheck authority inside the existing atomic decision transaction.

## Explicit administrative installation and rotation

Administration is a separate, trusted in-process operation, not an endpoint or a
new CLI. The following is a composition sketch for an administrator-controlled
script, using fixed paths. It is not executed by this milestone:

```python
from pathlib import Path
from soc_automation.approval_policy import PolicySource
from soc_automation.state import Store

source = PolicySource(Path('/etc/soc-approval/review-policy.json'), owner_uid=0)
store = Store(Path('/var/lib/soc-approval/soc_automation.db'))
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
`close()`; no signal handler or production launcher is installed here.

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
by the same setting. Each accepted request has a monotonic total read deadline
(default two seconds; configurable 0.05–30), so drip-fed bytes do not reset it.
Writes have a maximum 0.1-second window, including a small window after an input
timeout for its error response. Read-only SQLite checks use a busy timeout no
larger than 0.1 seconds and a deadline progress handler. Host scheduling and
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

Exactly those three fields are required. The version is an integer, not a bool;
operation and target are strings. Only `health` is accepted, and the target must
belong to the active policy. No client identity fields or additional operations
are accepted. All JSON strictness rules above apply. Responses use the same
four-byte length framing, followed by one deterministic JSON object; the server
closes the stream. Success has no principal, policy content, paths, or database
information:

```json
{"ok":true,"operation":"health","version":1}
```

Errors contain `version: 1`, `ok: false`, and one stable `error` code:
`invalid_request`, `unsupported_version`, `request_too_large`, `truncated_request`,
`unauthorized`, `timeout`, `busy`, `policy_unavailable`, or `unavailable`.
Malformed shape/JSON is rejected before authorization; a validly shaped unknown
UID or unauthorized target gets `unauthorized`. Internal exception text is never
sent. For timeout, disconnected, or nonreading clients, delivery of an error
cannot be guaranteed. A client must treat missing/truncated responses as failure.

## Tested scope and remaining work

Offline tests use real Linux AF_UNIX streams and SO_PEERCRED under the test UID,
private temporary directories, synthetic policy, and temporary SQLite databases.
They test file/path attacks, strict parsing/framing, authorization and default
root/service denials, authority corruption/rotation, listener locking and
replacement, timeouts, concurrency, shutdown, and unchanged database contents.
Root and differing UID cases use synthetic credential tuples as well as actual
same-UID transport denials; tests do not require root or create OS accounts.
Only explicitly marked tests may create AF_UNIX stream sockets. IP sockets,
connection helpers, and DNS remain blocked. No Elasticsearch or Kibana is used.

Account provisioning, actual multi-account group access, ACL/LSM behavior,
namespace/UID mapping, supervisor hardening, administrator authentication,
backup integrity, and production filesystem/procfs availability are deployment
assumptions, not certified by these tests. ACLs, Linux capabilities, root, and
service-account compromise remain part of the host trust boundary. Do not grant
operators directory write access through ACLs or capabilities. No production
deployment is claimed complete.

6.3B-2B still needs an explicitly scoped approval request contract, authenticated
intent and stale-state bindings, dispatch to the existing atomic persistence API,
response/retry semantics, and corresponding end-to-end security tests. An
operator client/CLI and production service composition need separate design and
review. This stage adds no approval, decline, revocation, publication, policy
administration, arbitrary database, or remediation dispatch.
