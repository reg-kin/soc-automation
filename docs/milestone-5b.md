# Milestone 5B: bounded investigation execution

`run-investigation-worker` consumes the existing SQLite queue. It does not enqueue,
recover expired leases, prepare cases, or publish anything. The default invocation
processes at most one eligible job and exits immediately when none is available.

```text
soc-automation run-investigation-worker --once --provider fixture --evidence-dir /path/to/export
soc-automation run-investigation-worker --max-jobs 10 --provider elasticsearch
```

The fixture provider requires an evidence directory. Elasticsearch requires the
existing explicit `SOC_ELASTICSEARCH_*` configuration, exact-reference source index
allowlists, and read-only credentials. `SOC_DATABASE_PATH` must point to an initialized
schema 007 database. Run migrations deliberately against the intended database before
using the worker. No production migration or network validation was performed here.

The manual `investigate` command and worker share `service.construct_investigation`,
`investigation.build`, and `Store._save_investigation`. Analysis, evidence hashes,
immutable source identities, report snapshots, and duplicate detection use the same
implementation. Manual investigation still retrieves and validates current evidence
before attempting persistence, preserving its conflict detection behavior.

## Lifecycle and bounds

1. Claim one eligible job with a unique owner and incremented generation. Incompatible
   engine versions are finalized with `engine_mismatch` without retrieving evidence.
2. Look for an existing report by request fingerprint. Validate its engine, exact
   selected IDs, and persisted evidence ledger, then adopt it without overwriting it.
3. If no report exists, reject jobs already older than the age bound. Construct from
   immutable job selection using the existing evidence provider outside transactions.
4. Supervise construction, renewing the lease while retrieval blocks. Persist only
   through fenced completion; schedule retry or terminate without a report on failure.
5. Stop after the requested job count; do not wait for scheduled retries.

API defaults: 60-second leases, 10-second heartbeat intervals, 300-second execution
wait, 24-hour maximum age for starting/retrying jobs, and 60-second retry delay.
`max_jobs` is restricted to 1–1000. Timing and ownership parameters are injectable
through `InvestigationWorker`; the CLI exposes job count and retry delay. UTC epoch
seconds govern persisted lease expiry; a monotonic clock bounds execution waiting.

The supervising thread renews independently of the provider's HTTP timeouts and
internal retries. Construction runs in a daemon thread with no report persistence
operation. Deadline, interruption, lease loss, or database errors stop the run and
leave its current lease for explicit `recover-investigation-jobs` recovery. Python
cannot forcibly cancel an uncooperative blocking provider: its thread can finish
later, but its result has no path to persistence. No further jobs are started after
such an error. Database lock waits remain bounded by the configured SQLite timeout.

## Retrieval and partial reports

`Retrieval.code` exposes typed outcomes derived from fixed provider protocol codes,
never exception messages: success, missing, transport, rate limiting, server error,
authentication/authorization, TLS/configuration, invalid reference, evidence conflict,
and invalid evidence. Human-readable reasons retained in reports remain sanitized
provider diagnostics. `InvalidReference`, `RetrievalFailure`, and `EvidenceConflict`
provide structured exception boundaries.

Transport, rate limit, and retryable server failures schedule another attempt while
attempt and age bounds permit. These attempts persist no investigation or evidence.
At exhaustion, the existing builder's partial report and evidence gaps are retained
atomically, and the job becomes `failed`, never `completed`. Missing source documents,
missing references, and invalid context/timestamps retain existing partial semantics.
Permanent retrieval failures and conflicting source identities persist no report.
Permanent failures take precedence in mixed retrieval batches.

Exhaustion at the maximum attempt count records `transient`; other terminal partial
outcomes use the existing schema's coarse `permanent` terminal code. The report
retains the precise evidence gap reasons. No new retry or publication authorization
is inferred from either code.

## Persistence and races

Migration 007 adds a nullable foreign key from job to report and a trigger checking
report fingerprint, engine, exact selection, terminal state, and successful status.
Migrations 001–006 are unchanged. Initialization still migrates transactionally.

`InvestigationQueue.complete` uses one `BEGIN IMMEDIATE` transaction to verify job ID,
owner, generation, leased state, and unexpired lease; persist with existing evidence
rules (or validate adoption); finalize the current attempt; link the report and
transition the job; and append the coordination audit. Ownership is checked again
after persistence and expiry is checked after audit, before returning to commit.
Every exception, including interruption, rolls the transaction back.

Concurrent manual persistence with the same evidence returns the immutable winning
report through the shared duplicate path. Different evidence raises a typed conflict
and rolls back the entire worker transaction. Concurrent claims serialize through
SQLite, and stale generations cannot persist reports even after retrieval finishes.
A local administrator able to change the schema remains outside this fencing model.

The worker has no Kibana client, publication service, approval hash, case preparation,
or case reconciliation dependency. Existing publication remains explicitly approved
and independent. There is no daemon, scheduler, response execution, or Milestone 5C.
