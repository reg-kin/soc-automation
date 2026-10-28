# Milestone 4 Stage C: Elastic Security Cases

Target contract: Kibana 8.19.20, default space, owner `securitySolution`.
Implementation and acceptance testing are local only. No live target validation was performed.

**Current restriction (Milestone 6.3B-1):** the `publish-case` CLI cannot initiate
publication. It lacks trusted active-policy composition and fails closed, even
with approval records and explicit authorization flags. The publication examples
below describe the transport contract, not an enabled CLI workflow. Preparation,
review, and reconciliation of previously claimed uncertain outcomes remain
available. Schema 10 migration installs no policy. Do not add a permissive default
or use manually inserted approvals to bypass the gate; see
[trusted installation and rotation](internal-approval.md).

## Architecture

`cases.py` rebuilds the investigation using immutable saved alert and evidence documents.
It checks completed status, absence of gaps, exact reference identities, canonical SHA-256
hashes, schema/engine versions and equality of all derived facts, timelines, associations
and uncertainties. The evidence snapshot is also checked against the SQLite evidence ledger.
The renderer projects explicit approved fields into deterministic JSON in the description;
complete raw documents are excluded. Oversize descriptions (>30,000 characters) or titles
(>160 characters) are rejected, never truncated. Severity uses the highest stored triage
priority: P1 critical, P2 high, P3 medium, P4 low.

`kibana.py` uses standard-library HTTPS with certificate/hostname verification, bounded
response reads, connect/read timeouts, independent API key and `kbn-xsrf`. It exposes only
create, find and get. It never retries or follows redirects. The creation payload uses the
none connector and `syncAlerts: false`; it attaches no alerts and changes no alert status.
The v8 API contract is documented at:
https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-createcasedefaultspace

Migration 004 adds `case_publications` and append-only `case_publication_audit` without
changing investigation tables. A unique investigation/target pair freezes the payload and
SHA-256 before approval. SQL guards enforce immutable identity/content, matching approval
and transitions: prepared → sending → published or uncertain; uncertain → published.
A crashed sending attempt remains sending and is eligible only for reconciliation.
Audit insertion and every state change share one SQLite transaction, including remote
ID/version receipt storage. An audit write failure rolls back the receipt transition.
The atomic prepared-to-sending claim commits before HTTP. No HTTP request holds a database
transaction. Concurrent callers cannot send twice. Published calls are idempotent.

## Configuration and permissions

Use independent `SOC_KIBANA_URL` (HTTPS origin only) and `SOC_KIBANA_API_KEY` (base64 encoded
`id:key`, without `ApiKey ` prefix). `SOC_KIBANA_SPACE` defaults to `default`; other spaces
are rejected. Optional settings:

| Variable | Default | Bounds |
| --- | --- | --- |
| SOC_KIBANA_CONNECT_TIMEOUT | 5 | 1–60 seconds |
| SOC_KIBANA_READ_TIMEOUT | 10 | 1–120 seconds |
| SOC_KIBANA_MAX_RESPONSE_BYTES | 1048576 | 1–16777216 bytes |
| SOC_KIBANA_CA_PATH | system trust | absolute existing CA bundle |

Unknown SOC variables are rejected. Keys are excluded from settings representations.
Logs contain fixed event codes, never remote bodies, headers, credentials or exceptions.
Ledger and audit contain no authentication material. Review artifacts contain investigation
identifiers and selected context: protect the database and review output accordingly.
Existing Elasticsearch settings and read-only adapter remain independent.

Provision a separate operator-managed API key scoped to the default space with Security
Cases `All` privileges, required by the Kibana create API. Reconciliation needs Cases read
access. Do not grant index-write, detection-management, connector execution or alert update
privileges for this integration. Kibana's Cases `All` privilege also permits operations this
client does not expose; enforce organizational controls on key use. No credentials are
provisioned by this repository.

## Operator workflow

Initialize/migrate a backed-up local database with `soc-automation init-db`, then:

```text
soc-automation prepare-case --investigation-id ID
soc-automation show-case-publication --publication-id ID
soc-automation publish-case --publication-id ID --approve-payload-sha256 HASH --authorize-case-creation
soc-automation show-case-publication --publication-id ID
```

Review the complete frozen `payload_json`, target and `payload_sha256` returned by prepare
or show. Use that exact hash in publish only after approving the content and destination.
Preparation does not create an HTTP client or send network requests. The hash covers the
canonical creation payload. The target is separately frozen and must match client settings.
Service authorization is enforced independently of CLI flags. Missing authorization or a
mismatched hash leaves the prepared record untouched. Publication to an already published
identity returns its stored receipt without another POST.

## Recovery and limitations

On any failed POST or malformed/mismatched receipt, the state becomes uncertain. On process
interruption it may remain sending. Never reset either state or resend the POST. Run:

```text
soc-automation reconcile-case --publication-id ID
```

Reconciliation searches by a deterministic publication tag and owner. It requires exactly
one result and GET-verifies identity and every frozen payload field before storing the
remote ID/version atomically. Zero results, multiple results, unavailable reads or modified
remote content fail closed; keep the record and investigate manually. A unique search does
not constitute server-side exactly-once delivery. Tags can be changed and indexing can lag.
No automatic retry or operator resend path is provided. There is no update/delete support,
connector push, alert attachment, raw-document upload or automatic publication trigger.
Required custom fields configured on a target may cause creation rejection; no live target
configuration has been inspected. TLS/API behavior against the precise deployed patch
version remains unverified outside mocks.

## Acceptance tests

Run `pytest -q`, `ruff check src tests`, and `ruff format --check src tests` in a development
environment. Tests clear inherited SOC configuration and block sockets/DNS globally. HTTP
uses mocked HTTPS connections; all database migrations use temporary SQLite databases.
Coverage includes evidence tampering, unsupported causal claims, incomplete reports,
deterministic preparation, limits, severity projection, independent authentication, TLS,
redirect rejection, invalid paths, authorization, concurrent claims, repeated publication,
timeouts, malformed/oversize responses, crash recovery, zero/one/multiple search matches,
receipt mismatch, atomic receipt/audit rollback, migration failure rollback and existing
ingestion/investigation regression contracts. No production service is needed.

## Readable reports and offline revisions (schema 5)

`cases.RENDERER_VERSION = soc-case/2` identifies the rendering contract. Changes
that affect payload text require a new renderer version. Rendering validates and
rebuilds saved evidence before producing Markdown with seven sections: summary,
chronology, findings, supported inferences, limitations, unresolved questions,
and provenance. Titles use observed event actions (or categories) and event count.
No detection-rule names are interpreted as confirmed attack stages. Explicit
synthetic metadata is labeled; a synthetic index name is attributed to the index
rather than treated as proof of real activity. Source identifiers and SHA-256
hashes remain in provenance. Missing attributes remain unknown. Large reports
fail closed instead of dropping provenance: title <=160 and description <=30,000
characters, following the [Kibana Cases API limits](https://www.elastic.co/docs/api/doc/kibana/operation/operation-updatecasedefaultspace).

Migration 005 replaces the investigation/target uniqueness constraint with an
immutable publication history and a `publication_heads` table selecting one
current revision per investigation/target. Existing publication rows and audit
entries are copied without changing values. Supersession is represented by the
head, never by modifying an old publication. SQL guards prohibit backward head
movement, deleting heads, claiming a superseded row, or moving a head after any
revision has left `prepared`. Markers are deterministic hashes of the renderer
version, investigation ID and description; a unique target/marker index prevents
reuse within a revision history. A revision with an identical payload returns
the current artifact, while resurrecting an older marker is rejected.

Initialize the database to apply the migration, then prepare offline:

```sh
soc-automation init-db
soc-automation prepare-case --investigation-id INVESTIGATION_ID --new-revision
soc-automation show-case-publication --publication-id NEW_PUBLICATION_ID
```

Preparation requires only the existing target URL/space settings, saved evidence
and local database; it constructs no authenticated client and makes no network
requests. Without `--new-revision`, a different frozen payload remains an error.
No new revision is permitted after `sending`, `uncertain` or `published`, because
a remote case may already exist. Reconcile uncertain sends; never retry creation.
Publication still requires the exact new payload SHA-256 and explicit operator
case-creation authorization. Old approvals do not transfer. Concurrent preparation
and claims serialize under SQLite `BEGIN IMMEDIATE`; only the current revision
can claim `sending`.

### Offline preparation verification (2026-10-27)

For investigation `inv-9f3c116cd260dc71581e074037f92b2d5822d292832d59f5c56ea7c347a96476`:

- Original publication `168d46c0-0a83-428e-8938-ab4872442e04` and its audit
  entries were compared before/after migration and revision preparation: identical.
- New current publication: `04020086-5489-4a18-a83a-0c8d21e8803a`.
- New payload SHA-256:
  `ef327f65ceb0d9d7a16caa025b92b762377baeb42715afbf8549df7a50f2d742`.
- Title: `SOC: authentication, file, process (3 events)`; description: 2,656 characters.
- Investigation, evidence, alert and audit table contents were hashed before/after:
  identical. Foreign key check passed.
- Old revision claim was refused. New revision claim succeeded only in a disposable
  database backup. The real revision remains `prepared`, without approval or any
  remote request. Preparation ran with socket creation forbidden.

### Read-only adapter diagnostic

`reconcile-case` is recovery for `sending` or `uncertain` publications; a
`prepared` publication is rejected locally with `Publication has not been sent`.
The CLI intentionally reduces this exception to `command_failed`. It is not a
connectivity test. Reconciliation can store a receipt and change local state
when successful, although its Kibana requests are read-only.

For an independent diagnostic, with the existing `SOC_KIBANA_API_KEY` exported:

```sh
SOC_KIBANA_URL=https://kibana.example.com SOC_KIBANA_SPACE=default soc-automation validate-kibana
```

This command needs no database setting and never opens a Store. It sends exactly
one GET to `/api/cases/_find?owner=securitySolution&page=1&perPage=1`, using the
adapter's verified HTTPS context, API-key header, bounded read and timeouts.
It requires HTTP 200 and validates Cases pagination, total, case IDs and owner.
It outputs fixed success fields, excluding credentials and case content; failures
use the existing fixed `command_failed` log and exit code 1. There are no retries,
redirects, publication operations, or write requests. Optional `SOC_KIBANA_CA_PATH`
continues to select a trusted CA bundle; TLS verification cannot be disabled.

`contract_target: 8.19.20` identifies the intended API contract, not a detected
server version. `server_version_verified: false` is explicit: this Cases-only
probe does not query server metadata. A successful operator run on the known
8.19.20 deployment validates the exercised read/search behavior, not case
creation, every Cases endpoint, or other features. Local mock tests do not
establish deployed connectivity, trust, authentication, or patch compatibility.
No live request was made during diagnostic implementation.
