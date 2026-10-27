# Milestone 5B independent correctness review

Reviewed the working implementation on `feature/milestone-5-investigation-coordination`
against baseline `f03e702`. Conclusions below come from source, schema, and tests;
the implementation report was not treated as proof.

## Verified invariants

- `Store._connection` starts `BEGIN IMMEDIATE` for writes and rolls back on
  `BaseException`. `InvestigationQueue.complete` checks owner, generation, leased
  state, engine, and lease expiry within that transaction. It rechecks after report
  persistence and checks expiry again after the coordination audit.
- Evidence, report, reference/alert memberships, alert transitions, report audit,
  attempt outcome, job link/state, and coordination audit share that transaction.
  Both audit-insertion failure tests and actual subprocess exits demonstrate rollback.
- Construction uses the shared manual investigation builder outside database
  transactions. Manual persistence retains evidence conflict checks and immutable
  winning reports. Duplicate persistence returns the existing snapshot.
- Transient retrieval failures persist no report/evidence while retry and age bounds
  permit another attempt. Attempt or age exhaustion can retain a partial report linked
  to a failed job. Missing evidence also produces a partial report. Permanent retrieval
  failures persist no report. CLI inspection exposes the nullable investigation link.
- Case rendering rejects partial reports before publication preparation. The worker
  execution path does not call publication preparation, publishing, approval, or
  reconciliation functions. Its Elasticsearch provider exposes exact-document reads.
- Adoption checks fingerprint, engine, exact selection, unchanged saved report, and
  evidence ledger. Complete reports complete the job; partial reports fail the job
  with a report link. Conflicting manual winners remain unchanged and cause failure
  without a worker report link. Identical evidence uses the existing winning report.
- Heartbeats renew leases while providers block. Expired owners and old generations
  cannot complete. Late daemon-thread results have no persistence path. Deadline,
  interruption, and database errors leave leases for explicit recovery.
- Initialization executes migration statements within one transaction. Migration 007
  adds the link and guards without changing migrations 001–006. Populated schema-6
  upgrade and injected failure preserve retained investigations, evidence, publication
  revisions/heads, and audit rows; integrity and foreign-key checks pass.

## Confirmed defects corrected

1. The execution supervisor checked its monotonic deadline before waiting, but could
   accept a ready result after the deadline. It now checks again after receiving the
   result, before returning it to the persistence path.
2. Migration 007 guarded report links only on UPDATE. INSERT could create a queued
   job with a non-null report link. A new insert trigger rejects any initial link;
   schema validation also requires that trigger.

## Regression coverage added or strengthened

- Ready provider result delivered after the execution deadline.
- Initial queued job insertion with a report link.
- CLI distinction between failed jobs with/without reports and partial publication
  rejection.
- Existing reports with incompatible engine or selected alerts.
- Manual partial-report winner racing a worker with different evidence.
- Populated schema-6 preservation, both successful upgrade and rollback then upgrade.
- Crash rollback of memberships and audits, followed by recovery and successful retry.

Existing tests additionally cover partial adoption, transient exhaustion/linkage,
lease expiry during persistence, stale generations, blocking-provider heartbeats,
manual complete-report races, immutable evidence conflicts, mixed retrieval batches,
concurrent workers, and both report/coordination audit insertion failures.

## Limits and acceptance

Python cannot forcibly stop an uncooperative provider thread. Supervisor waiting is
bounded and abandoned results cannot persist; provider threads may remain alive until
return or process exit. SQLite lock waits and commit latency are separate from the
construction deadline. Lease checks occur inside the transaction before SQLite commit.

Recovery is explicit; this milestone adds no scheduler or automatic recovery loop.
An incompatible retained report or unexpected execution/database exception leaves the
lease for recovery. Tests use synthetic providers and isolated databases; no live
services, production credentials, or live database were used.

Milestone 5B is ready for acceptance with the two corrections above. Milestone 5C
was not started. No commit or push was performed.

## Final validation

Using the existing `/tmp/soc-5b-venv/bin` environment on PATH:

- `python -m pytest -q`: 335 passed.
- `ruff check .`: passed.
- `ruff format --check .`: passed, 38 files already formatted.
- `git diff --check`: passed.
