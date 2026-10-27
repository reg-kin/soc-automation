# SOC Automation

A modular Python service for persistent SOC alert processing. Milestones 1 and 2 provide local configuration, logging, state, audit history, offline Elastic alert ingestion, deterministic triage and priority, and administrative commands. The optional Stage A Elasticsearch adapter supports explicit read-only retrieval; all validation is offline. It executes no response actions and has no runtime third-party dependencies.

Python 3.11 or later is required. Development was verified on Ubuntu with Python 3.12.

## Install and verify

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Install without development tools using `python -m pip install .` in an isolated environment. The `soc-automation` command is installed into that environment's `bin` directory.

## Local usage

```bash
mkdir -m 700 -p "$PWD/state"
umask 077
export SOC_DATABASE_PATH="$PWD/state/soc_automation.db"
export SOC_LOG_LEVEL=INFO
export SOC_DATABASE_TIMEOUT_SECONDS=5
.venv/bin/soc-automation --help
.venv/bin/soc-automation check-config
.venv/bin/soc-automation init-db
.venv/bin/soc-automation healthcheck
```

Configuration comes exclusively from the environment; `.env.example` is documentation and is never loaded automatically. `SOC_DATABASE_PATH` is required, absolute, and must end in `soc_automation.db`; its parent directory must already exist. `SOC_LOG_LEVEL` defaults to `INFO` and accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. `SOC_DATABASE_TIMEOUT_SECONDS` defaults to 5 and accepts integers 1–60. Unknown `SOC_` variables, empty values, and malformed settings fail validation. Other environment variables are ignored. Optional Elasticsearch configuration is documented in [Milestone 4 Stage A](docs/milestone-4-stage-a.md).

Commands emit JSON events to stderr and exit 0 on success or 1 on configuration/database failure. Argument errors exit 2. `--help` needs no configuration. `check-config` validates configuration without opening a database. `init-db` creates or migrates a database transactionally and can be repeated safely. `healthcheck` requires an existing initialized database, validates schema objects, runs SQLite integrity and reference checks, and verifies transaction access. It never initializes state. Failures emit a generic event without exception text; inspect configuration and local database permissions when diagnosing failure.

With no `SOC_` variables, `check-config` exits 1 because `SOC_DATABASE_PATH` is required.
To validate local configuration without Elasticsearch, supply only an absolute database
path, for example `SOC_DATABASE_PATH="$PWD/state/soc_automation.db" soc-automation check-config`
(after creating the private `state` directory as above). This exits 0 without creating
or opening the database or contacting Elasticsearch. If any `SOC_ELASTICSEARCH_`
variable is supplied, the complete Elasticsearch configuration must be valid.

## Architecture and boundaries

- `config.py`: strict environment parsing.
- `logging.py`: structured UTC JSON events. Only allowlisted event codes, standard severity, and generated timestamps are emitted. All arbitrary messages, formatting arguments, exception details, and extra fields are redacted by omission. Never send credentials or alert contents to logging, even though this boundary drops them.
- `state.py`: SQLite persistence, versioned migration ownership, alert registration, lifecycle validation, and audit reads.
- `migrations/`: packaged, ordered SQL migrations; `PRAGMA user_version` tracks schema version. Future schema changes require a new migration and an increased supported version; newer databases are rejected.
- `ingestion.py`: bounded offline JSON parsing and typed normalisation.
- `triage.py`: deterministic, configurable activity classification, disposition and priority.
- `service.py`: ingestion orchestration and atomic batch semantics.
- `cli.py`: local administrative and offline processing entry point.

Offline alert ingestion and deterministic triage/priority assignment are implemented in Milestone 2; see [the Milestone 2 contract and review](docs/milestone-2.md). Milestone 3 supplies investigation orchestration. Elastic Security Cases integration and response policy/execution remain future responsibilities. Elastic Agent remains the telemetry source; Elastic Security owns detection and EQL correlation; Elastic Security Cases owns incident management. The existing production Elastic deployment and assurance/remediation platform are outside this repository's scope. There is no separate correlation engine, dashboard, workflow editor, Case system, or SOAR framework.

## Persistent processing contract

`Store.register_alert(source, source_alert_id, correlation_id=None)` creates an alert and its audit record in one transaction. The `(source, source_alert_id)` pair is unique: identifiers are scoped to their source. Duplicate calls return the original record, preserve its correlation identifier and timestamps, and do not add an audit event. A UUID correlation identifier is generated if omitted. Source and alert identifiers should be opaque references, never secrets or raw alert payloads.

`Store.transition(alert_id, new_state)` supports:

```text
registered -> triaged -> investigating -> completed
     |           |             |
     +-----------+-------------+----> failed
```

`completed` and `failed` are terminal. Unknown states, skipped steps, repeated states, backwards movement, and unknown alerts are rejected. These states describe local processing only; `completed` does not mean an Elastic Case has been closed. State changes persist UTC creation/update times and append audit entries with the alert's stable correlation identifier. Audit entries survive new processes and cannot be updated or deleted through ordinary SQL operations. Database triggers enforce transitions and audit insertion even for direct state SQL updates. SQL parameters bind external identifiers.

Each operation opens a short-lived connection, enables foreign keys and full synchronous writes, and uses `BEGIN IMMEDIATE` with commit/rollback. SQLite serializes writers; duplicate registration remains idempotent under concurrent callers. The initial journal mode uses SQLite's default rollback journal. Lock timeouts fail the operation without partial state; callers must explicitly decide whether to retry. Migration statements execute inside a single transaction, including the schema version change.

This is a trusted local database, not a tamper-proof audit store: a database owner can alter schema or remove the file. Protect its directory, use local storage, and back up the database with SQLite's backup API or while the service is stopped. Milestone 2 adds immutable raw alert evidence and versioned deterministic priority policy. Retries, leases, retention, automatic remediation, and operational integrations remain unimplemented. No security decision authorizes a response action.

## Eventual systemd deployment

`deploy/soc-automation.service` is a hardened example **oneshot health check**, not a continuously running ingestion service. It ends after checking the database. No daemon is implemented in this milestone.

Deployment preparation (performed by an administrator) must create an unprivileged `soc-automation` system account/group without a login shell, install the package into `/opt/soc-automation/.venv`, and create `/etc/soc-automation/environment` using `.env.example`. Keep application code administrator-owned and configuration permissions restricted. Create `/var/lib/soc-automation` owned by the service account with mode 0700, then run `init-db` as that account with the same environment and umask 0077 before starting the unit. Copy the example unit to `/etc/systemd/system/soc-automation.service` and reload systemd when ready. Nothing in this repository automatically provisions accounts, installs units, or starts services.

The unit runs as `soc-automation`, sets umask 0077, restricts filesystem access, removes capabilities, and denies IP networking. SQLite files inherit restricted creation permissions when these deployment instructions are followed. Existing file permissions are the administrator's responsibility. No production systems are needed for deployment validation or tests.

## License

Apache-2.0; see `LICENSE`.

Milestone 3 adds offline exact-reference evidence retrieval and deterministic investigations.
See [the Milestone 3 contract and CLI examples](docs/milestone-3.md).

Milestone 4 Stage A adds a bounded read-only Elasticsearch adapter, verified only
with mocked HTTP. See [configuration, privileges and CLI persistence semantics](docs/milestone-4-stage-a.md).
