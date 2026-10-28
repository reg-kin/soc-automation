# Operator discovery and frozen review (Milestone 6.3A)

These commands use schema 10, open the existing database with SQLite `mode=ro`,
validate its schema, and read within one transaction per invocation. They do not
initialize or migrate the database, construct transport clients, persist rendered artifacts,
record decisions, publish cases, or update preparation records. Set
`SOC_DATABASE_PATH` to an absolute path named `soc_automation.db`, as for existing
commands. No Kibana credentials are required.

```sh
soc-automation list-case-publications
soc-automation list-case-publications --review-status unreviewed --limit 50
soc-automation list-case-publications --target configured
soc-automation list-case-publications --target https://example.test/default/securitySolution
soc-automation list-case-publications --limit 50 --cursor TOKEN
soc-automation review-case-publication --publication-id ID
```

`--target configured` uses the existing `SOC_KIBANA_URL` and `SOC_KIBANA_SPACE`
configuration through the credential-free target settings. Explicit targets must
already be canonical HTTPS targets in the supported default space. Without the
option, discovery covers all targets. Review uses the stored target and needs no
destination configuration.

## Discovery JSON contract

Success emits one sorted-key JSON object and exits 0:

```json
{"next_cursor": null, "publications": []}
```

Each publication entry has `id`, `investigation_id`, `target`, `state`,
`payload_sha256`, `created_at`, `review_status`, and `is_current_head`.
Only current heads in the `prepared` state appear. Superseded and sent
publications are excluded. No payload, report, evidence body, or actor data is
returned. Review status means the latest persisted decision, or `unreviewed` when
no decision exists. `--review-status` accepts `unreviewed`, `approved`, `declined`,
and `revoked`; omission includes all four.

`--limit` defaults to 100 and accepts integers 1–1000. Results use ascending
publication insertion sequence, not timestamps or random UUID order. A non-null
`next_cursor` resumes after the last returned entry, retaining the initial
insertion ceiling; subsequent insertions cannot enter that traversal. The cursor
is opaque, versioned, bounded, and bound to the exact target and status filters.
Reuse those filters on every page; page size may change. A null cursor marks the
end. Cursors are validated continuation positions, not authenticated capabilities.

Each page has its own consistent transaction snapshot. Decisions, head replacements,
and publication state transitions committed between pages can remove entries or
change their metadata. Pagination does not retain a database transaction across
CLI invocations and does not promise a historical cross-page snapshot.

## Review JSON contract

Success emits one sorted-key JSON object and exits 0. It includes all stored
publication columns (`id`, `investigation_id`, `target`, `payload_json`,
`payload_sha256`, `approval_sha256`, `state`, `remote_case_id`, `remote_version`,
`created_at`) plus:

- `is_current_head`: whether this publication is still the destination head.
- `payload`: decoded frozen payload; `payload_json` preserves the exact stored text.
- `payload_sha256_verified`: true after hashing the exact UTF-8 stored text.
- `report_json`, `report`: exact persisted investigation report text and decoded object.
- `verification_method`: `hash_binding` for records with preparation or review bindings,
  or `deterministic_evidence` when both are absent.
- `report_sha256`: computed hash of the exact UTF-8 persisted report text, always returned
  as an identifier.
- `report_sha256_verified`: true only for `hash_binding`, after verifying independently
  persisted report hash bindings; false for `deterministic_evidence`.
- `report_hash_sources`: `preparation`, `review`, or both for bound records; an empty
  array for deterministic evidence verification.
- `renderer_version`: identity read from the frozen description and checked against bindings;
  deterministic evidence verification additionally requires the supported `RENDERER_VERSION`.
- `review_status`, `latest_review`: latest decision or `unreviewed` and null.
- `review_history`: complete persisted event rows in ascending event ID order, including
  identity, actor, policy, timestamp, reason, and frozen artifact bindings.
- `audit`: complete publication transition rows in ascending audit ID order.

Review accepts historical and sent publication IDs as well as prepared heads.
It verifies exact payload/report hashes, report identity and evidence ledger,
completed preparation bindings, every review's frozen bindings and decision chain,
and the publication transition sequence and final state. Duplicate JSON keys,
non-finite JSON constants, and non-object artifacts are rejected. No stored text
is normalized or rewritten. Only unbound publications are rerendered in memory for comparison. Review histories are complete for
one publication; the listing limit does not truncate them.

Missing/corrupt/inconsistent/unverifiable records and invalid runtime configuration
exit 1 with the existing generic `command_failed` log and no JSON result. Raw
exception messages are not emitted. Argument misuse exits 2 through argparse.
New options are rejected on unrelated commands; review requires a publication ID.
Existing commands retain their behavior.

## Integrity boundary and limitations

Schema 10 retains schema 9's full report hash in preparation jobs and review events, but not
in a publication or investigation row itself. Review uses two verification methods:

- `hash_binding`: every linked preparation must be completed and match the exact
  stored report bytes, evidence fingerprint, investigation, target, and renderer.
  Every review event must match the frozen payload/report hashes, target, renderer,
  and decision chain. These checks retain the existing independent report-byte
  hash verification semantics. Bound artifacts are not rerendered, so historical
  renderer versions remain reviewable when their bindings verify.
- `deterministic_evidence`: only when neither binding exists, the stored renderer
  must match the supported version. Within the same read-only transaction, review
  reconstructs the expected payload from the persisted report, alerts, and evidence
  using the preparation renderer and eligibility rules. The complete decoded frozen
  payload must match using canonical JSON serialization, including all fields.
  Noncanonical whitespace and key order are accepted; the exact stored
  `payload_json` remains unchanged and its byte hash is still checked.

Deterministic consistency is not independent report-byte hash verification. The
computed `report_sha256` identifies the report bytes read, but no independent
persisted binding verifies that hash. Report whitespace and any differences allowed
by the renderer's deterministic rules cannot be claimed as independently verified.
Missing evidence, ineligible reports, unsupported renderers, rendering failures, and
payload mismatches fail closed. An existing corrupt, mismatched, or incomplete
binding always fails; deterministic reconstruction is never a fallback for it.
No checksums, decisions, artifacts, or investigation data are backfilled or changed.
Neither method grants approval or changes the publication approval guard.
Existing `show-case-publication` retains its previous, less comprehensive contract.

Checksums detect disagreement with stored bindings; they do not authenticate a
database against a privileged actor who can rewrite artifacts and all bindings.
Stored artifact content is operator review material and is returned verbatim.
This milestone adds no decision recording, authentication, or publication behavior.

The subsequent [internal approval engine](internal-approval.md) reuses this verifier
on its transaction's connection. The read-only commands and their output remain
unchanged. Review hash sources describe integrity bindings, not approval
provenance: only a verified completed preparation binding qualifies for approval.

## Temporary publication restriction

`publish-case` cannot initiate publication until secure policy loading is
implemented. The CLI does not compose a trusted active policy; authorization flags
and a durable review approval are insufficient. It fails closed before external
case creation. There is no permissive default, policy argument, or rotation CLI.
Preparation and these read-only commands remain available. Reconciliation of
previously claimed uncertain outcomes keeps its existing behavior. Administrators
should initialize schema 10 using the existing migration workflow; migration does
not install policy or authorize publication. See [policy installation and rotation](internal-approval.md).
