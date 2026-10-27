# Milestone 5C-2: end-to-end SOC integration validation

## Architecture

`tests/test_soc_integration.py` exercises the existing service, normalization,
triage, queue, worker, evidence provider, SQLite persistence and case renderer.
Each scenario creates a temporary `soc_automation.db`, applies the real migrations
through schema 007, and reopens Store objects across workflow boundaries. No
production code or migrations are changed. The suite-wide autouse fixture in
`tests/conftest.py` removes SOC configuration and blocks socket creation,
connection and DNS resolution. No credentials or live services are required.

The integration fixture additionally forbids Kibana client construction and case
creation, `publish_case`, publication claims (including approval hashes), and
publication outcome changes. Worker Store instances additionally forbid local
publication preparation, while explicit local preparation remains allowed and
uses only an offline target. Active workers must preserve an existing prepared
case and its publication audit.

## Synthetic evidence

Three Elastic Security alert hits have fixed source indices, document IDs,
October 2026 UTC timestamps, rule metadata, high severity, risk score 75, host,
user and process entities, and exact ancestor references. Source event documents
are written under SHA256(canonical `[index,id]`) fixture filenames. The real
FixtureEvidenceProvider retrieves these documents. Scripted providers return
fixed retrieval protocol failures or altered documents; a mutable clock controls
retry availability and lease expiry without sleeping.

Assertions independently hash canonical alert originals and retrieved documents,
check retained evidence bytes and hashes, request identity, alert membership,
exact reference rows, nonempty evidence and timeline, job/report linkage, attempts
and audit records read through reopened stores. The success path
prepares a frozen local case, verifies its payload hash and absent approval, and
checks that subsequent queue/worker execution preserves publication state.
SQLite triggers must reject payload and evidence updates.

## Execution

Use Python 3.11 or newer with the repository dev dependencies installed:

```sh
python -m pytest -q tests/test_soc_integration.py
python -m pytest -q
ruff check .
ruff format --check .
git diff --check
```

A disposable virtual environment outside the repository can supply the tools;
activate it before running these commands. Tests use pytest temporary directories
and never open the repository's live state database.

## Coverage and expected results

| Scenario | Expected result |
| --- | --- |
| Ingestion through local preparation | P2 urgent investigation, completed linked report, prepared case with no approval |
| Duplicate ingestion/enqueue, reopened stores, worker restart | Stable ingested rows, no extra jobs or reports, immutable evidence |
| Compatible manual report adoption | Existing report preserved and linked despite a provider that would fail if invoked |
| Transport, HTTP 429 and retryable HTTP 5xx protocol outcomes | Delayed retry; no report, evidence, memberships or report audit persisted early |
| Crash after claim and explicit lease recovery | Overdue lease visible, no implicit reclaim, recovery records expired attempt, next generation succeeds |
| Missing evidence and exhausted transient retries | Failed job links partial report; local case preparation rejects it |
| Authentication, authorization, TLS/configuration, disallowed reference, conflicting identity | Permanent terminal failure without report; allowlisted structured diagnostics |
| Changed retained source content | Conflicting request fails without replacing prior evidence |
| Lease expiry during retrieval and interruption inside final transaction | All report-related tables roll back, lease remains recoverable |
| Stale generation after recovery | Old generation cannot persist even with the same owner; replacement generation completes |
| Concurrent workers | Retrieval barrier requires three simultaneously leased jobs; three distinct owners each complete one attempt |
| Health and CLI | Counts, oldest pending order, delay and expiry visibility; valid JSON stdout; job failure exits 0, process error exits 1 |
| Publication boundary | No client, remote publication, approval submission or authorization mutation |

There are 16 integration test cases after parametrization. Existing focused
suites remain complementary: `test_worker.py` covers actual subprocess exits
before/during persistence and after audit insertion, heartbeat behavior, mixed
retrieval failures, and audit-trigger rollback; `test_operations.py` covers wider
structured-event contracts, health bounds and CLI validation. These are retained
rather than duplicated in the journey suite.

## Limitations

HTTP 429/5xx, transport, authentication and TLS failures are simulated at the
provider protocol boundary. Existing Elasticsearch tests exercise adapter
classification with fake transport. This validates no live TLS, endpoint access,
permissions, throughput, real deployment scheduling or Kibana publication.
Each queued investigation selects one alert; this module does not validate
multi-alert correlation or supported inference quality. Restart here means reopened
Store and worker instances; actual process crashes are covered by the focused
worker suite. The concurrency barrier has a bounded 10-second deadlock timeout;
retry and lease assertions use an injected clock rather than elapsed wall time.
Threaded concurrency and SQLite rollback tests do not establish production load
capacity or resilience to filesystem corruption or power loss. Fixed source
content and clocks make evidence and recovery deterministic; generated UUIDs,
report generation times and audit timestamps intentionally remain variable.

## Controlled deployment readiness

All four validation commands must pass before controlled deployment. Operators
must separately validate a nonproduction read-only Elasticsearch configuration,
index allowlists, TLS trust, least-privilege authentication, backup/restore,
lease and timeout sizing, disk capacity and monitoring thresholds. Review failed
jobs and partial reports explicitly; recovery must remain an explicit bounded
operation. Keep case publication separately authorized after human review of the
frozen payload. No service installation, enablement or publication is performed
by this milestone. Passing offline tests supports a controlled staging trial;
it does not by itself authorize production deployment.

## Recorded validation

Validated against baseline `fc83441` on
`feature/milestone-5-investigation-coordination` using Python 3.12 in a disposable
`/tmp` virtual environment:

- Dedicated integration module: 16 passed.
- Full suite after final review corrections: 384 passed in 15.44 seconds.
- `ruff check .`: passed.
- `ruff format --check .`: 42 files already formatted.
- `git diff --check`: passed.

Only this document and the dedicated integration module were added. No commit,
push, live database modification, credentials, remote service access or deployment
changes were performed. Existing `.codex/` and `certs/` were preserved.
