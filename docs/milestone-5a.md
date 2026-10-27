# Milestone 5A: durable investigation queue

`coordination.InvestigationQueue` coordinates existing ingested alerts only. It does
not retrieve evidence, run investigations, save reports, or publish cases. Manual
multi-alert investigations and their persistence remain unchanged.

Migration 006 adds jobs, singleton automatic membership, attempts, and append-only
coordination audit. Automatic assignment is permanent, including after failure or
engine upgrades. A unique alert membership and request fingerprint prevent duplicate
jobs. Identity includes the existing engine-versioned `request_identity()` selection.
Migration 001–005 remain unchanged. Initialize an operator-approved database using
the existing `init-db` command to migrate it; no migration is automatic on queue use.

Eligibility requires an ingested alert in `triaged` state, retained `VALID` decision,
`INVESTIGATE` or `URGENT_INVESTIGATION` disposition, P1–P4 priority, no investigation
membership, and no previous automatic assignment. Ordering is priority, registration
(ingestion) time, then local alert ID. Each automatic job contains exactly one alert.
Preview runs in a read-only deferred transaction; enqueue selects and inserts under
one short `BEGIN IMMEDIATE` transaction. All queue operations validate schema version.

Lifecycle: `queued -> leased -> completed | failed | retry_wait`; due `retry_wait`
jobs can be leased again. Terminal jobs cannot transition. Claim increments both
attempt count and lease generation atomically and records an attempt. Renewal and
outcomes require matching owner and generation and a strictly unexpired lease.
Recovery handles leases at or past expiry, closes the attempt with `lease_expired`,
and schedules retry or terminal failure. Recovery is bounded and idempotent.
Workers from incompatible engine versions are rejected with typed `engine_mismatch`
and leave the job unchanged for operator review. Recovery can close expired jobs
regardless of engine version.

Only `transient` and `lease_expired` failures retry. `permanent` and `engine_mismatch`
are terminal when submitted as owned outcomes. Failures must use `FailureCode`, never
exception text. Attempt limits are 1–100 (default 3), lease duration 1–86400 seconds
(default 60), retry delay 1–86400 seconds (default 60), batch size 1–1000 (default 100).
Retry delay is fixed and explicitly supplied; no transport-failure classification is
introduced here. The Python API accepts an injected epoch-seconds clock for tests;
production hosts must use a consistent wall clock. Completion is a coordination-only
primitive: 5B must combine report persistence and completion in one fenced transaction
before introducing any executing worker. There is no completion CLI in 5A.

CLI commands (using the existing `SOC_DATABASE_PATH` configuration):

- `plan-investigations --limit 100`: read-only eligibility preview.
- `enqueue-investigations --limit 100 --max-attempts 3`: atomically assign backlog.
- `show-investigation-job --job-id ID`: job, selection, attempts, and audit.
- `list-investigation-jobs --limit 100`: bounded durable job inspection.
- `recover-investigation-jobs --limit 100 --retry-seconds 60`: recover expired leases.

Queue use requires no Elasticsearch or Kibana client. Claim/renew/outcome operations
are Python administration primitives only. SQLite serializes queue writers; all
network work and execution are deferred to a later milestone. Existing alert lifecycle,
evidence ledger, manual report persistence and publication approvals are untouched.
