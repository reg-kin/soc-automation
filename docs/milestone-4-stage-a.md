# Milestone 4 Stage A: offline Elasticsearch adapter

## Interface review (before implementation)

Reviewed pyproject, README, Milestone 2/3 contracts, configuration, ingestion,
evidence, investigation, service, state, CLI, all three migrations and test suites.
Runtime dependencies are empty. Settings rejects unknown SOC_ variables and uses
an environment-only configuration boundary. CLI errors omit exception text.
Ingestion accepts hit envelopes and preserves original JSON, uses index-scoped
identity, validates timestamps and optional metadata, then applies triage policy.
EvidenceProvider returns ordered Retrieval objects (found/missing/failed), with
exact Reference identity and a 262144-byte validation ceiling. Investigation
already deduplicates references and records partial evidence; it must be reused.
SQLite schema version 3 provides immutable evidence and reports, conflict checks,
transactional persistence and audit. No migration or engine change is needed.
Fixture provider and existing CLI commands must remain compatible. Tests block
sockets and DNS globally. New transport tests must mock HTTP, never disable that guard.

## Adapter architecture and interfaces

`elasticsearch.ElasticsearchProvider(ElasticsearchSettings)` implements the existing
`retrieve(Reference) -> Retrieval` and `retrieve_many(list[Reference]) -> list[Retrieval]`
contract. `fetch_alert(Reference) -> dict` returns the unchanged hit envelope after
exact identity and existing ingestion validation. It never persists or triages.
Call `service.ingest(store, encode(hit).encode(), policy=...)` explicitly to ingest
and apply existing triage. No new engine, migrations or third-party dependencies.
Python's maintained standard-library `http.client` supports separate connection
and socket read timeouts, bounded reads, verified TLS and deterministic mocking.
Only GET `/{exact-index}/_doc/{exact-id}` is issued; path segments are encoded.
No search, discovery, pagination, redirects, polling, proxy environment handling,
concurrency, mget or write API is implemented. Standard `_index`, `_id`, `_source`
hits work without optional Elasticsearch metadata. Additional metadata is retained.
Batches are sequential exact reads; deduplication avoids duplicate HTTP calls and
returns ordered results including duplicates. Each missing/failing member remains
independently visible, so successful evidence survives partial retrieval.

## Authentication, TLS and configuration

All integration variables use prefix `SOC_ELASTICSEARCH_`. Settings are optional
for existing offline commands; supplying any integration variable requires a
complete valid configuration. Unknown SOC_ variables continue to fail closed.
Secrets stay in memory and are excluded from settings repr, logs and CLI output.
Transport exceptions and HTTP bodies are never interpolated into diagnostics.
No request objects or Authorization headers are logged or written to SQLite.
Raw alert/evidence persistence continues to contain original document data and
must be protected by existing local filesystem access controls.

| Suffix | Default | Contract |
| --- | --- | --- |
| URL | required | HTTPS origin, optional port; no credentials, path prefix, query or fragment |
| API_KEY | required | Base64 ASCII `id:api_key`, without `ApiKey ` prefix; nonempty components, maximum 8192 encoded characters |
| ALERT_INDICES | required | Comma-separated permitted concrete alert indices or bounded patterns |
| SOURCE_INDICES | required | Comma-separated permitted concrete source indices or bounded patterns |
| CA_PATH | system trust | Absolute existing readable PEM CA file; parsed before requests |
| CONNECT_TIMEOUT | 5 | Integer seconds, 1–60 |
| READ_TIMEOUT | 10 | Integer seconds, 1–120 per blocking socket read |
| MAX_DOCUMENTS | 100 | Integer 1–100 input references per batch, counting duplicates |
| MAX_RESPONSE_BYTES | 1048576 | Integer 1–16777216, enforced by bounded read plus one sentinel byte |
| MAX_DOCUMENT_BYTES | 262144 | Integer 1–262144, canonical complete hit bytes, matching evidence engine ceiling |
| RETRIES | 2 | Integer 0–3 additional attempts per unique reference |
| BACKOFF | 1 | Integer 0–5 seconds; delays are base multiplied by 2 to attempt number |

Indices permit lowercase letters, digits, dots, underscores, hyphens and `*`/`?`
patterns after a literal first character. Bare `*`, empty lists, traversal and
comma-separated API targets are rejected. At most 100 patterns per list. Prefer
exact physical indices; patterns are local authorization checks only and are
never sent as search targets. Use narrowly scoped patterns, e.g.
`logs-endpoint.events.process-test-*`, when rollover requires them. References
retain the existing strict safe-character contract; unsupported identifiers fail
rather than being rewritten. No field names or missing evidence are fabricated.
HTTPS and certificate/hostname verification are mandatory even for loopback.
There is no insecure flag and no certificate-warning suppression.

## Read-only permissions model

Future API keys require index privilege **`read`** on only the explicitly permitted
alert and ancestor source index names/patterns. Cluster privileges: **none**.
Application/Kibana privileges: **none**. No `monitor`, `manage`, `all`, `write`,
`create_index`, `manage_api_key` or `view_index_metadata` privilege is required
for these exact-document GETs. If the selected physical alert indices are treated
as restricted indices by the deployment, an administrator must explicitly enable
`allow_restricted_indices: true` for only that narrow alert index entry; never
apply that setting to a broad wildcard. The source entry should retain false.
The API key creator's own permissions also constrain the key. Stage B must verify
this model against the actual deployment's restricted-index classification and
security policy; Stage A creates no key and makes no permission probes.

## CLI and persistence

Set configuration through a protected process environment. Never put keys in
command arguments or version control. Examples use symbolic index/ID values:

```bash
soc-automation check-config
soc-automation fetch-alert --index INDEX --id DOCUMENT_ID
soc-automation investigate --alert-id LOCAL_ALERT_ID --provider elasticsearch
soc-automation investigate --alert-id LOCAL_ALERT_ID --evidence-dir FIXTURE_DIRECTORY
```

`fetch-alert` prints identity, validated status and `persisted: false`; it does
not open/create the database and does not print source content. The Python API
provides the hit for explicit ingestion via existing service APIs. No implicit
fetch-to-ingest CLI behavior is added. `investigate` selects already ingested
local alert IDs (repeat `--alert-id` for several), retrieves source evidence and
**persists** the existing full report/evidence/audit and lifecycle changes in
SQLite. It prints the existing full investigation report, including evidence;
use restricted output handling. The existing fixture default and report output
remain compatible. Evidence-directory and Elasticsearch options cannot be mixed.
The CLI retains exit codes 0 success, 1 operational/configuration failure, 2
argument failure, and generic allowlisted failure logs without exception details.

## Error semantics and bounds

A 404 is `missing/document_missing`; authentication (401), authorization (403),
rate limiting (429), 500/502/503/504, other HTTP errors (including redirects),
connection/read timeouts, TLS failures, malformed JSON, invalid structure,
identity mismatches, encoding and size failures are `failed`, never missing.
Reasons are fixed safe codes. Alert retrieval raises ElasticsearchError for
missing/failed reads; source retrieval returns per-reference gaps. Existing
normalization errors remain InputError. Only rate limiting, listed server errors,
timeouts and transport failures retry. TLS, authentication, identity, parsing,
size and missing-document failures do not retry. Retry-After is not used;
backoff is deterministic and bounded (maximum 35 seconds total delay per document).
Connections close on each attempt. Compressed responses are rejected to avoid
unbounded decompression. Error bodies are not read. There is no unbounded query
or pagination. Socket read timeouts are inactivity limits, not an overall wall
clock deadline; a slow continuously responding peer may take longer.

## Offline validation

The existing socket/DNS blocking fixture remains active for the complete suite.
Synthetic responses cover exact hits, optional metadata absence, three EQL alerts,
multiple source indices, missing documents, identity mismatches, absent source,
malformed/duplicate JSON, partial results, duplicates, every required HTTP failure,
TLS failures, connection/read timeouts and response/document limits. Mocked calls
assert GET-only behavior, headers, verification, timeout settings, closure and
retry/backoff bounds. Integration tests use the existing ingestion/investigation
services. An installed console-entry-point subprocess uses mocked HTTPS and a
network guard to verify fetch output and absence of database creation.

Validation environment: existing `/tmp/soc-foundation-venv`; no repository `.venv`
was present. Commands (from repository root):

```bash
/tmp/soc-foundation-venv/bin/python -m pytest -q
/tmp/soc-foundation-venv/bin/ruff check .
/tmp/soc-foundation-venv/bin/ruff format --check .
```

Results: **149 passed** (99 existing plus 50 added); Ruff lint and formatting pass.
No Elasticsearch/Kibana endpoint, production host or development endpoint was
contacted. No services were started, keys managed or Git commits created.

## Limitations and Stage B prerequisites

Stage A is an offline implementation for Elasticsearch 8.x, including the observed
8.19.20 target; live deployment compatibility is not claimed. It does not discover
alerts, resolve aliases to physical ancestors, retrieve search fields without
_source, expand EQL stages, infer causal links, or implement Cases/response actions.
No overall batch deadline, connection pool or automatic Retry-After handling.
Existing evidence immutability rejects changed source evidence on repeat runs.
Before separately authorized Stage B work, administrators must supply narrowly
scoped key privileges, approved exact indices, reachable approved HTTPS origin,
trusted CA chain and synthetic/nonproduction validation plan. Verify physical
alert/source identities, restricted-index behavior, key scope, rollover patterns,
CA ownership and document bounds against deployment policy. Existing hardened
systemd example denies networking and would need an explicitly reviewed deployment
change. Stage B has not begun.
