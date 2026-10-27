# Milestone 2: offline ingestion, triage and priority

## Milestone 1 review

The review covered `config.py`, `state.py`, migration 001, `logging.py`, `cli.py`, deployment examples and all 32 existing foundation tests before implementation. No confirmed defect required a foundation rewrite.

- Configuration is environment-only, rejects unknown `SOC_` variables, requires the expected absolute database filename, bounds lock timeout and allowlists logging levels. New per-invocation ingestion limits and policy use CLI arguments; the existing environment contract stays intact. The Settings constructor is a trusted Python API; environment validation happens in `from_env`.
- Each connection enables foreign keys and FULL synchronous writes. `BEGIN IMMEDIATE` serializes writers; statement-by-statement migrations and schema version changes commit atomically. A failed trigger rolls back registration and audit together. Reads also reserve the writer lock: this is a throughput constraint for future integration, not a correctness defect for this local workload. Lock timeouts fail without automatic retry.
- Existing `(source, source_alert_id)` uniqueness and UUID processing IDs are stable across restarts. Elasticsearch `_id` alone is insufficient because it is index-scoped. The new adapter hashes canonical JSON `[source_index, document_id]` into the existing source identifier slot, using source `elastic_security`. The exact index and document ID remain separately persisted. A missing index on explicitly identified unwrapped input is represented by JSON null, distinct from every index string. Legacy registrations remain unchanged and are not automatically reinterpreted as Elastic documents.
- Database triggers enforce lifecycle and append-only lifecycle audit. The original audit table requires an existing alert and cannot represent input rejection; migration 002 adds a separate ingestion audit without weakening migration 001.
- Allowlisted logs suppress raw exceptions, credentials and submitted data. Evidence needs a separate restricted storage boundary; it must not flow into logs or ordinary CLI output.
- Existing tests already block socket creation and name resolution. The additive tests use that same fixture. The CLI retains all administrative commands and exit conventions.
- Schema checks verify version and required object names, not full SQL definitions. SQLite is a trusted local store, not a tamper-proof security boundary. Owner-level schema replacement is outside the threat model.

## Input contract and Elastic 8.19.x assumptions

Reference: [Elastic Security 8.19 alert schema](https://www.elastic.co/guide/en/security/8.19/alert-schema.html). `@timestamp` describes alert creation or most recent update; it is not necessarily the original event time. `kibana.alert.original_time`, if supplied, remains in the original. Non-ECS alert fields are version-sensitive. This adapter accepts exported `_source` documents, not search `fields` arrays; future live retrieval requires its own adapter and verification against the deployed version.

Accept one hit `{ "_index": "...", "_id": "...", "_source": {...} }`, a JSON array of hits, or a search response with `hits.hits`. An unwrapped document requires `--source-id` (or the explicit `source_id` Python argument); that identifier can only be used with one document per call. A collection of unwrapped documents must be submitted in individual calls with explicit identities. Wrapper identity and an explicit identifier cannot be combined. Index and identifier must be nonempty strings, at most 512 characters, without control characters.

Every document requires a timezone-bearing ISO 8601 `@timestamp`. All other detection fields are optional. Optional null values are treated as unavailable; an empty ancestors list is a known empty collection, while missing/null ancestors become `None`. No missing context is inferred from other events. Present severity must be `low`, `medium`, `high` or `critical`; present risk score must be a finite number in 0–100 (booleans are rejected). Rule ID/name, entity identifiers, context containers and ancestor containers have explicit type checks. PID must be a nonnegative integer. Unknown fields remain in evidence and are not interpreted as trusted instructions.

Dotted and nested ECS fields are supported. Conflicting representations of fields consumed by normalisation are rejected. `rule_id` uses `kibana.alert.rule.rule_id`, not the saved-object `uuid`; all rule fields remain in the original document. Relevant host/user IDs and names, process entity ID/PID, and host/user/process/event context are retained, with explicit nulls for unavailable values. Ancestors remain individual objects in their supplied order. Both one object and an array are accepted, with a single object normalised to a one-element list. Optional known reference members are type checked; extra reference members are preserved.

EQL output is accepted with the same contract and retained as generated by Elastic. Ancestors are references, not retrieved event evidence. A sequence alert need not embed the full sequence; no sequence reconstruction or correlation engine exists here. Ancestor count, rule name and host name never prove compromise or benign activity.

Defaults: 4 MiB total input, 256 KiB canonical JSON per alert, 100 records per batch, and maximum JSON nesting depth 32. CLI options configure the first three; Python `Limits` also configures depth. Limits must be positive integers with a hard upper bound of 16 MiB/16,777,216 per setting. CLI reads at most the total limit plus one byte, including for policy files (policy limit 256 KiB). Duplicate JSON keys, malformed UTF input, nonfinite numbers, excess depth, empty batches and unexpected top-level values are rejected. Per-alert size counts canonical UTF-8 JSON including the wrapper; escaped Unicode can expand relative to input and is subject to that limit. No filesystem references or URLs inside submitted JSON are followed.

## Design and decision contract

`ingestion.parse` validates bounded JSON and collection shape. `ingestion.normalize` is a pure function returning a typed `NormalizedAlert` plus canonical original JSON. `triage.decide` is independently callable with an explicit `Policy`. `service.ingest` orchestrates them and `Store.ingest_batch` persists prepared records. Python callers should use `service.ingest` for untrusted input; `Store.ingest_batch` is the internal transaction boundary for validated data.

The preserved original is semantically identical JSON, including wrapper metadata and all rule/context fields, rather than the exact input bytes or whitespace. Its SHA-256 is the durable `original_ref`; the original and normalised JSON live in the same database row. Retrieve evidence explicitly with `Store.show_alert(id, evidence=True)`. Ordinary CLI summaries omit raw evidence, source names, policy configuration and arbitrary policy-version strings. Database backups and file permissions must protect the original, which can contain sensitive event data. Retain the existing deployment directory mode 0700 and umask 0077 guidance. No heuristic evidence redaction destroys investigation data.

Validity, activity, disposition and priority are separate persisted fields. Malformed input is rejected before registration, rather than creating a valid-looking triage record. Valid input has validity `VALID`. Activity is `APPROVED_TEST` only if its exact rule ID matches operator-controlled `approved_test_rule_ids`; otherwise it is `UNKNOWN`. The alert itself cannot assert trust using a flag or tag. Treat policy files as trusted, access-controlled configuration; approval applies to that exact rule ID across the offline input scope. There is no automatic authorised-activity inference.

Disposition precedence:

1. Approved test policy match: `TEST_ONLY`, retaining independently calculated priority.
2. P1/P2: `URGENT_INVESTIGATION`, including when entity evidence is absent.
3. P3/P4 with no entity identifiers: `MANUAL_REVIEW`.
4. Otherwise: `INVESTIGATE`.

These are routing decisions, not investigation findings. No evidence results in automatic exoneration. No decision authorises response actions.

## Priority policy

Lower numeric priority is more urgent. Defaults are P1 immediate operational attention, P2 elevated attention, P3 normal investigation queue, P4 lower queue priority. These are local queue categories, not an SLA or proof of compromise.

- Severity maps critical/high/medium/low to P1/P2/P3/P4.
- Risk scores >=90/70/40 map to P1/P2/P3; scores below 40 map to P4. Thresholds are inclusive.
- Operator-supplied `asset_criticality` maps exact host ID/name to critical/high/medium/low and uses the severity mapping. `asset_priorities` optionally supplies exact host priorities directly. Missing inventory contributes no candidate.
- The most urgent candidate from severity, risk, and all matching asset entries wins, including conflicting host ID/name inventory entries.
- If all candidates are missing, use P3 (`default_priority`). Missing risk is not zero, and missing severity is not low.
- Finally, an exact rule match in `rule_overrides` replaces that priority, allowing an explicit escalation or de-escalation. This does not classify activity as a test.

Policy JSON can override `version`, `approved_test_rule_ids`, `asset_criticality`, `asset_priorities`, `rule_overrides`, `severity_priorities`, `risk_thresholds` and `default_priority`. Unknown configuration keys fail. Severity mappings must cover exactly four levels; risk thresholds must be three descending values within 0–100. Decisions store policy version, full snapshot, SHA-256 policy fingerprint and fixed rationale codes. Version alone is not assumed to uniquely identify configuration.

Example trusted policy:

```json
{
  "version": "offline-1",
  "approved_test_rule_ids": ["approved-offline-test"],
  "asset_criticality": {"asset-001": "critical"},
  "rule_overrides": {"offline-rule-002": "P2"}
}
```

## Persistence, migration and repeat execution

Run `init-db` to migrate an existing version 1 database. Migration `002_initial.sql` sets schema version 2 and adds `ingested_alerts` and `ingestion_audit`, plus update/delete prevention triggers for evidence/decisions and ingestion audit. Migration 001 and legacy registration/lifecycle contracts are unchanged. Migration resource names retain the existing numbered `_initial.sql` loader convention. Failed migrations preserve the prior schema and version.

A batch is atomic: validate all input first, then register all alerts, evidence, decisions, lifecycle transitions and ingestion/triage audit within one `BEGIN IMMEDIATE` transaction. One invalid document rejects the whole batch, and no alert from that batch is committed. A separate transaction appends one redacted rejection event with no input contents or identifiers. A conflict found during persistence rolls back the entire batch before that rejection is recorded. Database errors roll back processing; if the database is unavailable or refuses audit writes, durable auditing cannot be guaranteed and the command fails.

Repeated identical identity/content returns the existing alert and decision, even under changed policy or after restart. It adds a `duplicate` ingestion audit event without creating additional alert/evidence/decision rows or lifecycle events. A changed document under an existing identity is rejected, including an updated alert timestamp. Nothing silently replaces prior evidence or decisions. Future evidence revisions or policy reevaluation require a separately designed, versioned workflow; Milestone 2 does not implement one. Repeated `triage` returns the decision atomically persisted at ingestion and does not reevaluate or mutate it. Legacy registrations without ingested evidence cannot be triaged by these new commands.

## Offline CLI and Python use

```sh
export SOC_DATABASE_PATH=/absolute/private/directory/soc_automation.db
soc-automation init-db
soc-automation ingest --file tests/fixtures/standard.json
soc-automation ingest --file tests/fixtures/approved_test.json --policy tests/fixtures/test_policy.json
soc-automation show-alert --alert-id UUID_FROM_INGEST
soc-automation triage --alert-id UUID_FROM_INGEST
soc-automation ingest --file unwrapped.json --source-id explicit-offline-identifier
soc-automation ingest --file batch.json --max-input-bytes 1048576 --max-alert-bytes 131072 --max-batch-size 20
```

Ingest/show/triage print structured JSON to stdout; failures return 1 and emit only the existing fixed `command_failed` logging event. Argparse usage errors return 2. `check-config`, `init-db`, and `healthcheck` remain available.

```python
from soc_automation.service import ingest
from soc_automation.triage import Policy

# store is an initialized soc_automation.state.Store
results = ingest(store, supplied_json_bytes, policy=Policy())
evidence = store.show_alert(results[0]["alert_id"], evidence=True)
```

## Validation and limitations

All fixtures are synthetic and use example entities without real credentials or personal information. `standard`, `eql` (multiple ancestors), `single_ancestor`, `minimal`, `approved_test`, `high_incomplete`, and `malformed` cover exported document shapes. Tests also construct duplicate input, mixed-validity batches, conflicting priorities, malformed field types, excessive sizes/depth, policy failures, persistence failure, process restarts, concurrent ingestion, migration rollback and CLI redaction cases. The autouse socket-blocking fixture applies to every test; subprocess checks invoke only fixed local Python code.

Validation commands (existing development environment):

```sh
/tmp/soc-foundation-venv/bin/python -m pytest -q tests/test_foundation.py
/tmp/soc-foundation-venv/bin/python -m pytest -q tests/test_ingestion.py
/tmp/soc-foundation-venv/bin/python -m ruff check src tests
/tmp/soc-foundation-venv/bin/python -m ruff format --check src tests
```

No live Elastic integration, enrichment, event retrieval, Cases operations, response actions, AI, additional service, or separate assurance platform changes are included. SQLite writer serialization, local policy trust, restricted evidence access, and lack of revision/reevaluation support remain explicit constraints. The offline ingestion boundary is ready to inform Milestone 3; live adapters, retrieval permissions, retries and any investigation orchestration still require that milestone's requirements and validation. Milestone 3 has not been implemented.

## Completion record

Final validation on the development workspace:

- Foundation: 32 existing tests passed unchanged.
- Milestone 2: 51 tests passed, including CLI, migrations, atomicity, persistence and concurrency.
- Combined `python -m pytest -q`: **83 passed**.
- `python -m ruff check .`: passed.
- `python -m ruff format --check .`: passed (15 Python files, including existing build copies).
- Separate installed executable invocations against a temporary database passed: init, standard and EQL fixture ingestion, repeated ingestion, show-alert, triage and healthcheck. The temporary database was removed afterward.

Modified files: `README.md`, `src/soc_automation/cli.py`, `src/soc_automation/state.py`.

Created files: `src/soc_automation/ingestion.py`, `src/soc_automation/triage.py`, `src/soc_automation/service.py`, `src/soc_automation/migrations/002_initial.sql`, `tests/test_ingestion.py`, `tests/fixtures/{standard,eql,single_ancestor,minimal,approved_test,high_incomplete,malformed,test_policy}.json`, and `docs/milestone-2.md`.

The original foundation tests, configuration module, logging module, initial migration and deployment files were preserved. No changes were committed. No production endpoint, Elastic Case, response action, separate assurance platform or service installation/start was involved.
