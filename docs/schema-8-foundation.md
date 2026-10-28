# Schema 8 persistence contract (Stage 6.2A)

Migration 008 adds preparation jobs, automatically generated preparation audit,
operator review history, a publication approval guard, and publication head
insertion validation. It does not execute jobs or authenticate operators.

Use Store connections, which enable foreign keys and register `coordination_now`,
`sha256_text` (SHA-256 of UTF-8 text), and `canonical_case_target`. A target must
match the existing KibanaTargetSettings canonical HTTPS destination, including
`/default/securitySolution`. A report hash covers the exact frozen `report_json`
text, not a caller's reserialized version. Evidence provenance must equal the
investigation's stored evidence fingerprint. Preparation identity is unique per
investigation, target, renderer and report hash.

New jobs start queued with zero attempts, lease generation and audit sequence.
Every update must increment `audit_sequence` by one. Claims increment attempts
and lease generation together and preserve `available_at`; renewals keep the owner and generation and extend
an unexpired lease. Only a lease may complete, fail or enter retry wait. Expired
leases require `lease_expired`; transient retries require remaining attempts.
Retry scheduling must be at or after the transition clock; completion and failure
preserve `available_at`. Completion requires a current prepared publication with
matching investigation, target and renderer, a valid exact payload hash, and a
rechecked frozen report hash and evidence fingerprint against the investigation.
Preparation IDs and unique identities cannot be replaced through INSERT OR REPLACE. Terminal jobs cannot change. The database emits exactly one
audit row per insert or update, including the terminating lease's owner. Failed
audit insertion aborts the transition. Direct extra audit inserts are rejected.

The existing publication table has no separate report hash or evidence fingerprint.
Its investigation foreign key and renderer header bind identity, but do not prove
that description text was rendered from the frozen report or evidence. This stage
does not change the renderer payload contract or claim that stronger guarantee.

Review inserts require a valid exact publication payload hash, a unique request ID, the latest event ID for that
publication (NULL initially), the frozen payload, canonical target, exact report
hash, renderer version, policy version, actor UID, principal, authentication
method and decision time. Renderer versions bind to the frozen payload's existing
`Case rendering format:` header. Initial decisions may approve or decline;
approvals may be revoked; declined or revoked decisions may approve or decline.
Review timestamps cannot precede their predecessor. Sequence, binding, current
head and prepared state checks apply to every review. Review records cannot be
updated, deleted or replaced.

The UID and principal columns persist assertions from a future trusted
authentication boundary. SQLite cannot authenticate a human from inserted
values. Likewise, trusted worker identity must be enforced by future atomic Store
operations qualified by lease owner and generation (and an unexpired lease), not
by SQLite authentication. SQL transition guards constrain persisted values; they
cannot identify the caller or stop an arbitrary database writer impersonating an owner. A caller-supplied username alone is insufficient; this stage introduces
no operator-facing insertion API or authentication service. The allowed method
names describe the future boundary's provenance, not proof that it ran.

Only the latest approved event permits a prepared publication to enter sending,
including direct SQL updates. The guard rechecks the payload digest, report hash,
target and renderer header. Renderer version identifies the frozen rendering
format; it is not an executable renderer selection or proof of rendering.
Review policy version is a nonempty recorded assertion, not a database-enforced
active-policy allowlist. A future trusted review boundary must choose and enforce
the applicable policy; changing its name alone does not invalidate an approval.
Existing publication transition, head, revision, immutability and audit guards
remain in force. Sending is a single claim; later reconciliation does not require
a new review. Migration creates no reviews and changes no historical publication
rows or audit rows. Old prepared publications need review before sending.

Initialization applies migrations and user_version changes within the existing
single immediate transaction. Reinitialization is safe; a schema-7 binary rejects
schema 8 through its existing version checks.

Offline contract tests can run without third-party dependencies:

```sh
PYTHONPATH=src python3 tests/test_schema8.py
```

The repository's complete suite still requires pytest. Existing publication tests
insert synthetic authenticated review records through parameterized SQL using a
test-only helper; no production authentication or approval bypass is added.

## Stage 6.2B: transactional Store queue operations

`Store` now exposes the following Python persistence API (implemented by the
`PreparationStore` mixin). No worker, polling coordinator, execution service,
operator review API, or network calls are introduced.

- `enqueue_case_preparation(investigation_id, target, max_attempts=3)` reads the
  persisted report, validates it using the existing evidence validator and case
  renderer, and freezes the exact JSON, SHA-256, evidence fingerprint, canonical
  destination and current renderer version. Partial reports, evidence gaps and
  inconsistent findings are rejected. Identical enqueue returns the original
  metadata, retaining its attempt budget; conflicting snapshots fail closed.
- `claim_case_preparation(lease_seconds=60)` returns one ready job including its
  frozen report, or `None`. The Store generates a fresh opaque owner token per
  claim and increments both generation and attempt count. Claims respect
  `available_at` and the frozen attempt budget (1–100).
- `renew_case_preparation(job_id, owner, generation, lease_seconds=60)` requires
  exact live ownership and monotonically extends the lease. Lease durations are
  bounded to 1–86400 integer seconds.
- `fail_case_preparation(job_id, owner, generation, failure=...)` requires an
  exact live lease. `transient` schedules retry after
  `60 * 2 ** (attempt_count - 1)` seconds if attempts remain, otherwise fails.
  `permanent` and `renderer_mismatch` fail immediately and never retry.
- `recover_case_preparations(limit=100)` explicitly recovers expired leases in
  bounded batches using `lease_expired`, the same backoff and attempt budget.
  It returns the number recovered. Recovery never extends expired ownership.
- `complete_case_preparation(job_id, owner, generation, payload=... OR
  publication_id=...)` accepts exactly one artifact input. It revalidates the
  frozen snapshot, persisted evidence and current renderer. Payloads must match
  the existing deterministic rendering. It uses the shared transaction-scoped
  publication helper with revision disabled, or adopts an existing matching
  current prepared publication. Publication creation, head, publication audit,
  association, completion and job audit share one rollback boundary. Ownership
  is rechecked after validation/preparation and before returning from the
  transaction. Existing publication controls remain authoritative.
- `show_case_preparation(job_id, snapshot=False)` returns metadata by default;
  frozen report retrieval requires explicit opt-in. `case_preparation_audit`
  supports `after_id=0, limit=100` keyset pagination. `eligible_case_preparations`
  returns metadata ordered like claims with `limit=100`. Limits accept integers
  1–1000. `case_preparation_stats()` returns fixed-size state counts and totals
  for eligible jobs and expired leases from one read snapshot. Aggregate counts
  cover the entire queue and may scan it; returned records are bounded.

All mutations run under `BEGIN IMMEDIATE`; competing connections serialize
selection and update. Owners are opaque fencing tokens, not authenticated human
identities. Every transition increments `audit_sequence`; Schema 8 triggers emit
one append-only audit event and abort the entire transaction if audit fails.
Terminal jobs cannot transition. Invalid ownership raises `StateError`; snapshot
conflicts raise `EvidenceConflict`; invalid inputs/eligibility raise `ValueError`
or `StateError`; database guards may raise `sqlite3.IntegrityError`. Failed calls
leave no partial persistence and require callers to classify failures explicitly.

The renderer is reused for local eligibility/artifact validation, not executed
by a new queue service. No automatic revisions, publication, remediation,
coordinator, timer or deployment is provided. Backoff is exponential across the
bounded attempt budget without a separate delay cap. SQL alone retains the
foundation's weaker rendering provenance contract; the stronger deterministic
payload check applies to these Store operations. Arbitrary database writers
remain outside the ownership/authentication boundary.

### Targeted 6.2B hardening

Both completion paths retain Schema 8's `preparation_completion` guard for the
current head, prepared state, investigation, target, report/evidence binding and
payload hash. Python additionally requires the exact canonical deterministic
payload; the SQL renderer-prefix check alone does not establish that property.
These association checks are not duplicated in Python. A matching payload from
an already-sent head still fails the prepared-state guard, including when the
shared publication helper returns an existing artifact.

Renewal, completion, failure and expiry recovery updates explicitly match the
leased state, owner and generation and require exactly one updated row. This
makes the mutation's ownership contract visible in SQL; it closes no demonstrated
race under the existing `BEGIN IMMEDIATE` serialization. Schema 8 transition
triggers remain authoritative for live versus expired lease timing and audits.
Tests cover concurrent identical enqueue, wrong-investigation adoption with an
identical payload, non-prepared artifacts through both completion paths, expiry
and recovery fencing, and rollback of an existing publication association.
