# Authenticated operator CLI (6.3B-3A)

Install the package with Python 3.11 or later, for example
`.venv/bin/python -m pip install -e .`. Invoke `soc-automation` from that environment
(or `.venv/bin/python -m soc_automation.cli`). No new dependencies are required.
These commands load no SOC environment configuration, policy file, database
credentials, Elasticsearch credentials or Kibana credentials. They never open the
database. They require Linux and the existing approval service running under
trusted administrative composition; no launcher or systemd installation is added.

## Commands and exact options

```
soc-automation approval-service-health --socket-path /run/soc-approval/operator.sock \
  --target https://example.test/default/securitySolution
```

Health is authenticated and target-authorized. It verifies active service policy
authority; it does not check a publication or establish current approval.

Decision commands are `approve-case-publication`, `decline-case-publication`, and
`revoke-case-approval`. Each accepts exactly the same options:

```
soc-automation approve-case-publication \
  --socket-path /run/soc-approval/operator.sock \
  --target https://example.test/default/securitySolution \
  --publication-id EXACT_PUBLICATION_ID \
  --request-id UNIQUE_IMMUTABLE_INTENT_ID \
  --expected-state prepared \
  --expected-previous-event-id null \
  --expected-payload-sha256 EXACT_64_LOWERCASE_HEX_DIGITS \
  --expected-report-sha256 EXACT_64_LOWERCASE_HEX_DIGITS \
  --expected-renderer-version soc-case/2 \
  --expected-review-policy-version EXACT_ACTIVE_VERSION
```

Replace all illustrative values with reviewed exact values. Every binding option
above is required. Use literal `null` for no predecessor; otherwise supply the
latest review event's positive integer ID (at most 2^63-1). No state, hash, version,
predecessor, publication identifier or request ID is generated or refreshed.
Identifiers follow the existing protocol: nonblank, at most 256 characters,
without characters below U+0020. The serialized request must fit 4096 bytes.

`--reason-code` optionally supplies one of `operator_declined`, `operator_revoked`,
`incorrect_payload`, `policy`; omission sends JSON null. The active server policy
remains authoritative about which codes are required or forbidden. Under default
policy omit it for approval, use `--reason-code operator_declined` for decline,
and `--reason-code operator_revoked` for revoke. Custom policy can restrict or
require other supported codes; the client does not load policy or duplicate its
semantics. Revocation uses the current approved event ID as predecessor.

All four commands accept `--timeout-seconds` (default 2, finite 0.05–30), a total
monotonic connect/write/read budget, and `--help`. Socket path and canonical target
are always explicit; there is no configured-target alias or environment fallback.
Decision commands additionally accept `--confirm`. Unrelated administrative,
identity, payload, policy and credential options are rejected. Options do not
abbreviate. Use the command name first, as in these examples.

## Intent and confirmation

The CLI prints the intended operation, publication ID, target, exact state,
hashes, renderer and policy version, predecessor, reason and request ID to stderr
as escaped JSON. Without `--confirm`, a terminal user must type the literal `yes`
when prompted. Enter, EOF and other answers cancel with no socket request.
Keyboard interruption or a terminal confirmation read failure also cancels with
exit code 3 and no socket request. Read failures display a short diagnostic
without exception details or a traceback.
Noninteractive stdin never confirms a decision, even if it contains `yes`.

For deliberate noninteractive use, add `--confirm`. This flag explicitly confirms
the exact displayed intent without a prompt, including in a terminal. It is
powerful: compromised scripts or authorized accounts can exercise that account's
permissions without human interaction. Review immutable arguments before using
it; do not insert it into unattended publication workflows. Validation precedes
confirmation; `confirmed:true` is transmitted only after local confirmation.
No connection or health preflight is sent on cancellation.

## Obtaining bindings and privileges

Reviewing, approving and publishing are separate operations. Existing authorized
reviewers use `list-case-publications` to discover identifiers, then
`review-case-publication --publication-id EXACT_PUBLICATION_ID` to inspect the
frozen payload, report and evidence verification. Review output supplies `id`,
`state`, `target`, `payload_sha256`, `report_sha256`, `renderer_version`,
`is_current_head`, preparation provenance in `report_hash_sources`, and
`latest_review` (its `id`, or null for no predecessor). Approval needs the current
prepared head and verified completed preparation provenance. Copy exact bindings
from the reviewed record. Obtain the active review policy version from the trusted
administrator's authorized policy-version communication; a historical event's
version alone does not identify the active generation. Never guess a version.

The review commands still use their existing configured database access and
security semantics. Socket-only operators are **not** granted database access by
this milestone. An authorized reviewer must securely convey the reviewed record
and exact bindings to such operators. A self-service socket-only review workflow
requires a separately designed and authorized read-only socket endpoint; none is
implemented here. Review can become stale; server checks remain authoritative.

Operators need distinct Unix UIDs, socket-directory traversal and socket access
through the operator group, and an active policy UID/principal, target and operation
grant. Group membership alone is insufficient. Root/service UIDs remain denied by
default; the CLI offers no overrides. No database or publication credentials are
needed for these four commands. See [service permissions](approval-socket.md) for
the protected service-owned directory (typically 0750) and socket (0660), policy
administration and account-lifecycle requirements.

The client accepts only an absolute normalized filesystem Unix socket path of at
most 107 encoded bytes, rejects a symlink or non-socket final endpoint, and uses
AF_UNIX/SOCK_STREAM exclusively. It performs no DNS, TCP or HTTP operations.
Pathname checks **do not authenticate the server** and are subject to replacement
races. Deployment must supply a trusted directory and ancestors, protect them
against operator/untrusted writes and symlinks, and ensure only the intended trusted
service can create/replace the endpoint. Privileged path writers remain trusted.
The client does not implement server peer-UID pinning. The server authenticates
the operator using kernel SO_PEERCRED, not client-supplied identity.

## Responses, errors and exit codes

Success is JSON on stdout. Decision success includes durable `event_id`, recorded
`outcome`, submitted `request_id`, `historical:true`, and a historical-event-receipt
notice. The server does not echo request ID; the CLI labels its submitted immutable
ID alongside the receipt. Success never asserts that an approval remains currently
effective. A fresh authorized review and the authoritative publication claim gate
are required for current eligibility. Approval adds a review event and never
publishes, reconciles or remediates anything.

Diagnostics and intent are on stderr. Internal exception details are suppressed.
Known server error codes are preserved verbatim, with these stable exit codes:

| Exit | Meaning |
| --- | --- |
| 0 | Successful health or historical decision receipt |
| 2 | Local argument/encoding validation, argparse usage, or server invalid-request/version/framing rejection |
| 3 | Operator cancellation, including missing noninteractive confirmation or terminal confirmation read failure |
| 4 | `authentication_failure` or `unauthorized` |
| 5 | `stale_publication_state`, `invalid_review_transition`, `evidence_verification_failure` |
| 6 | `policy_unavailable` |
| 7 | `conflicting_request_id` |
| 8 | Connection failure or unsafe/non-socket endpoint |
| 9 | Timeout, disconnect after connect, malformed/unexpected/truncated/oversized response; uncertain outcome |
| 10 | `internal_failure`, `unavailable`, or `busy` |

The client uses the version-1 four-byte big-endian length framing, strict JSON,
4096-byte request and response limits, write-half shutdown, and requires response
EOF with no extra bytes. It rejects unknown/extra response fields, unknown errors,
wrong types, version or outcome, duplicate keys, floats and nonfinite numbers.
The deadline covers response EOF as well as its body. Socket/filesystem operations
and process scheduling are not hard real-time bounded.

Timeout is never proof that the decision failed. The server may have committed
before a response was lost. No automatic retry occurs, and no replacement request
ID is ever generated. After confirming current authorization, retry using the
**SAME request ID and identical material request fields**, explicitly confirming
again. Keep an independent record of the original exact intent. Do not change
bindings to make an uncertain request pass. Investigate conflicts and internal
failures; they are not permission to substitute a fresh intent.

The server binds request ID globally to actor and all material intent fields.
Exact authorized replay returns the original historical event without another
mutation, even if current publication state changed. Changed intent conflicts.
Policy rotation fails closed until trusted service restart with matching active
authority; the client never installs or adopts policy. Active authorization is
checked even for replay. An authorized replay after rotation retains the original
expected policy version; a genuinely new decision needs the newly reviewed active
version and a new explicit intent. Rotation may deny historical access.

## Deployment limitations

Trusted service composition, administrative installation/rotation, protected
paths, account provisioning and review handoff are deployment responsibilities.
No production infrastructure or systemd changes are included. Shared accounts,
credential forwarding, UID reuse, compromised authorized accounts, privileged
path writers and database writers retain the limitations documented in the
[service protocol](approval-socket.md). This CLI does not establish recent human
authentication. Publication remains a separate manual workflow with its existing
policy composition limitation described in [internal approval](internal-approval.md).
No automatic case publication is introduced.
