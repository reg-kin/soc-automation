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

Before an engine-version upgrade, stop scheduled invocations, back up, and drain or
review pending jobs with the old compatible engine. New workers reject incompatible
jobs with `engine_mismatch`. Never rewrite immutable job identity or reports to force
compatibility. Review a new selection through the supported planner when eligible.

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
