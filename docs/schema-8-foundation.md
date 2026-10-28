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
