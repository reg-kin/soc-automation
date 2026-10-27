# Milestone 5C-1 operational controls

Run these commands only against the intended local database, using an operator-owned
configuration. No units are installed or enabled by this milestone.

Before `init-db` on an existing database, stop writers and take a consistent SQLite
backup with the SQLite backup API or `sqlite3 /path/to/database '.backup /secure/backup.db'`.
Protect and verify the backup and rehearse restoration on a separate path. Copying only
the main file while WAL writers run is not a consistent backup. This milestone requires
schema 007 and adds no migration.

Inspect and enqueue in bounded batches:

```sh
soc-automation investigation-queue-health --limit 20
soc-automation plan-investigations --limit 10
soc-automation enqueue-investigations --limit 10 --max-attempts 3
soc-automation run-investigation-worker --once --provider elasticsearch
soc-automation run-investigation-worker --max-jobs 10 --provider elasticsearch
soc-automation show-investigation-job --job-id JOB_ID
```

Health is read-only, captures one UTC epoch timestamp, and uses one short SQLite
snapshot. `state_counts` always includes queued, leased, retry_wait, completed, failed.
`ready_queued` and `ready_retries` require availability at or before the timestamp
and attempts remaining. `delayed_retries` have future availability; `overdue_leases`
include equality at expiry. `linked_partial_reports` counts linked partial reports;
`failed_without_reports` counts failed jobs lacking a link. All counts cover the
whole queue. `oldest_pending_jobs` contains safe job metadata ordered by creation
time then ID, for queued, leased, retry_wait states. `pending_total`, `pending_limit`,
`pending_returned`, and `pending_truncated` describe the bound (1–1000, default 100).

Worker stdout remains a JSON array of outcomes; queue health is a JSON object.
Worker exit 0 means the bounded batch command completed, including an empty batch;
it does not mean all investigations succeeded. Inspect each outcome. Exit 1 means
command or bound failure; invalid option combinations exit 2. `--once` and `--max-jobs` conflict.
The worker never waits for delayed retries or recovers leases itself.

After a crash, deadline, or lease loss, inspect health and job audit, then explicitly run:

```sh
soc-automation recover-investigation-jobs --limit 100 --retry-seconds 60
```

Only leases expired at the recovery clock are recovered. Jobs with attempts remaining
enter delayed retry; exhausted jobs fail. Wait until `available_at`, then invoke another
bounded worker. Do not modify queue state with SQL. Restart by invoking the worker
again after reviewing/recovering expired leases; active leases remain fenced.

For failed jobs with an investigation link, use `show-investigation --investigation-id ID`
to review the partial report and evidence gaps. Partial reports are not completed
investigations and are not eligible for case preparation. Escalate permanent failures
without reports to the responsible operator: review fixed failure codes, source
availability, permissions and configuration through approved channels. Correct causes
before further work; there is no administrative reset/requeue operation here.

Before upgrading from engine 3.0 to the current engine 3.1, stop scheduled
invocations and new enqueue activity, take and verify the consistent backup described
above, and drain the queue using the old compatible engine. Inspect queue health and
individual jobs: a drain requires zero queued, retry_wait and leased jobs, including
future delayed retries and unexpired leases. Wait for retries to become eligible;
after expired leases are explicitly recovered, process their eligible retries with
the old engine. Review terminal failures separately before upgrading. An empty worker
batch alone does not prove the queue is drained.

A 3.1 worker claims an eligible 3.0 job and immediately records terminal
`failed` / `engine_mismatch`, without retrieving evidence or producing/linking a
report. The claim consumes an attempt and increments the lease generation; the
attempt ends with `engine_mismatch`, and coordination audit records `claimed` then
`failed`. This is terminal even with attempts remaining. Delayed legacy retries are
rejected only once eligible. Legacy leases must first expire and be explicitly
recovered; recovery records `lease_expired` and schedules a retry if attempts remain,
or fails an exhausted job. The worker does not recover leases itself.

Failed legacy jobs retain immutable alert membership. Recovery only handles expired
leases; it cannot revive a failed job. Planner/enqueue exclude alerts already belonging
to any job, including failed jobs. Upgrading does not make those alerts eligible for a
replacement job. There is no supported queue reset, replacement or administrative retry.
Never rewrite job identity, membership, attempts, audit or reports with SQL.

For an explicitly reviewed selection, the existing manual investigation command can
produce a separate 3.1 investigation using the processing alert UUIDs from
`show-investigation-job` (`selection`), not source document IDs:

```sh
soc-automation show-investigation-job --job-id JOB_ID
soc-automation investigate --alert-id PROCESSING_UUID --provider fixture --evidence-dir /approved/offline/evidence
soc-automation show-investigation --investigation-id NEW_INVESTIGATION_ID
soc-automation show-investigation-job --job-id JOB_ID
```

Repeat `--alert-id` for each deliberately selected alert. The existing read-only
Elasticsearch procedure uses `--provider elasticsearch` with approved configuration
instead of fixture/evidence-dir; it contacts Elasticsearch and requires the existing
read permissions. Use reviewed offline fixtures for an offline rehearsal. Manual
investigation is an operator decision, not automatic queue recovery. It does not
repair, replace, complete or relink the original failed job. That job remains failed
with its original membership, attempts and coordination history. The new report has
a distinct version-based identity; existing reports and globally pinned evidence
remain immutable. Changed evidence under a pinned source identity can still cause a
conflict; engine upgrades do not enable evidence replacement.

Rehearse the upgrade against a separate restored temporary database with offline
fixtures before touching the intended deployment. Capture read-only queue health,
job inspection (including attempts/audit), and any historical report before and after;
verify engine versions, distinct report IDs, the unchanged failed job and retained
historical records. Record the legacy job ID and new manual report ID in the approved
operator audit record because the queue does not link them. Protect report/selection
outputs as sensitive data. Use the integrity checks below on a consistent database;
inspect report status and evidence gaps rather than treating command exit 0 as success.

Structured JSON events go to stderr (or the journal); stdout stays machine-readable.
Events cover claim, completion, partial report, retry, failure, mismatch, lease-renewal
failure, deadline, and expired-lease recovery. Fields are allowlisted and typed:
job/worker/investigation IDs where applicable, generation, attempt, state, fixed code,
and monotonic execution duration for worker events. Recovery has no execution duration.
Logs are best-effort observations; immutable database coordination audit and attempts
are authoritative. Outcome and recovery events follow commit. A logging/process failure
can leave a committed transition without its corresponding log. Never collect evidence,
exception text, headers, credentials or full provider configuration into operational logs.

For integrity checks, stop writers and open the intended database read-only:

```sh
sqlite3 -readonly /path/to/database 'PRAGMA integrity_check; PRAGMA foreign_key_check;'
```

Expect `ok` and no foreign-key rows. Escalate failures and preserve the original and
backup; do not repair state manually. The existing foundation healthcheck remains
network-denied. Example worker units use a separate configuration containing only
SQLite settings and read-only Elasticsearch access; never supply Kibana publication
credentials. Review paths, permissions, CA access, and outbound restrictions locally.
Recovery remains a separate network-denied unit. Timers are optional and disabled
by default; their examples contain no installation target. No case preparation,
publication, remediation, or always-running daemon is introduced.

Both oneshot services have explicit wall-clock start timeouts (worker: one hour;
recovery: two minutes). A timeout can interrupt a batch; inspect committed queue
state before invoking it again. Each timer schedules from service inactivity, and
systemd does not start another instance of an already active service. Worker and
recovery may run concurrently: SQLite write transactions and lease generation/expiry
checks fence recovery and prevent a stale worker from committing a report.
