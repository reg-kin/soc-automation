# Durable case preparation discovery (6.2C-1)

Schema 009 adds `case_preparation_discovery`, keyed by canonical Kibana target
and renderer version. It stores an immutable initial `historical_high_water`,
`historical_cursor`, `live_cursor`, and a shared compare-and-swap `revision`.
Historical progress stays in [0, high-water]; live progress starts at high-water.
Database checks and triggers enforce identity, boundary, monotonic progress,
one-lane updates, revision increments, and deletion protection.
Migrations 001–008 are unchanged. Initialization upgrades transactionally;
failed upgrades roll back DDL and user_version. Older binaries reject schema 9.
There is no destructive downgrade migration.

## Store interface

- `initialize_case_preparation_discovery(target, renderer_version=None)` captures
  the current maximum investigation persistence audit ID once. Repeated calls
  preserve the existing boundary and progress.
- `case_preparation_discovery_checkpoint(target, renderer_version=None)` reads
  existing progress or returns None.
- `preview_case_preparation_discovery(target, lane=..., limit=100,
  renderer_version=None)` inspects the next page without mutation. With no
  checkpoint it uses a virtual initial boundary in the read snapshot.
- `advance_case_preparation_discovery(target, lane=..., expected_revision=...,
  limit=100, renderer_version=None)` resolves a page and atomically advances
  its lane, returning the resulting checkpoint and per-record preparation IDs.

`None` selects the current renderer; unsupported renderers are rejected.
Lanes are `historical` and `live`. Limits are integer 1–1000, excluding bool.
Revisions are nonnegative signed SQLite integers, excluding bool. There is no
public arbitrary cursor setter: cursors come from bounded queries and persisted
constraints. Each response includes checkpoint, lane, records, and next_cursor.
Records expose audit ID, investigation ID, and eligibility, without report text,
rendered payload, or validation exception text.

## Ordering and transactions

Pages scan investigation_audit by `id > cursor AND id <= boundary ORDER BY id
LIMIT limit`, including failure and duplicate events. Eligibility comes from
the persisted report, evidence ledger validation, and existing case renderer,
never the audit event name. Events without an investigation resolve as ineligible.
A non-null investigation ID without a persisted report aborts as a persistence
failure. Explicit partial/gapped report, evidence mismatch, and renderer rule
rejections resolve as ineligible. Duplicate events remain separately ordered and reuse the
same idempotent preparation job. Ineligible records consume the page budget,
so entirely ineligible pages still advance. Empty pages advance to their snapshot
boundary; callers need not infer completion from eligible counts.

Initialization and advancement use BEGIN IMMEDIATE. Advancement checks the
expected revision, validates each record, enqueues eligible records through the
same internal implementation as enqueue_case_preparation, then updates the cursor
with a revision predicate. All writes commit together. Stale revisions fail before
resolution. Only typed `ReportIneligible` and `ReportEvidenceIneligible` rejections are skipped.
Unexpected exceptions roll back the entire page, including JSON decoding failures,
missing alert rows, and unclassified StateError, ValueError, KeyError, TypeError,
IndexError, or renderer dependency failures. The renderer no longer wraps broad
application exceptions as eligibility rejections. Structurally malformed reports
fail closed unless an explicit eligibility rule already rejects them. A crash after commit
leaves both jobs and progress durable; a separately committed enqueue followed by
replay returns the original job. Historical and live calls share a revision, so
competing lanes also require a fresh checkpoint after a conflict.

Preview and checkpoint reads use mode=ro and a read transaction. They cannot
create a file, migrate schema, initialize checkpoints, or enqueue jobs. Missing
or unsupported databases fail. A virtual preview boundary is advisory until
explicit checkpoint initialization captures the durable boundary.

## Query performance and limits

EXPLAIN QUERY PLAN verifies an INTEGER PRIMARY KEY range scan on the audit and
primary-key lookup on investigations, without a temporary sort. No additional
index is justified for this access pattern. At most limit audit rows are loaded;
validation/rendering cost still scales with the size of each persisted report.
The live snapshot boundary prevents concurrent appends from extending a page.

This foundation has no coordinator loop, CLI, network activity, approval,
publication, new queue, or deployment behavior. Advancement uses the existing
enqueue default attempt budget of three. Ineligible immutable reports are skipped
for this target/renderer; reconsideration under a future renderer requires a new
version checkpoint and compatible renderer implementation. Direct database writes
are outside the Store's safe resolution protocol; cursor triggers cannot prove
that application validation ran.

## Audit filtering assessment

The current writer atomically emits `completed` for every newly persisted report
(including partial reports), `duplicate` for an existing immutable report, and
`failed` without a report. Filtering to `completed` would therefore cover reports
created by this writer, but would remove duplicate replay records and change page
semantics. Discovery retains the bounded audit-ID scan across all events. No SQL
filter or migration change is needed. Audit event completion alone never proves
case eligibility.
