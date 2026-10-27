# Milestone 5C-3: live validation record

## Scope and provenance

This record captures operator-verified results from 2026-10-27 UTC on an isolated
isolated test server. It complements the [offline integration validation](milestone-5c-integration.md)
and [operational guidance](milestone-5c-operations.md). The documentation update
did not independently rerun validation or access databases or live services.

The run used engine **3.0**, with a read-only connection to the SOC Elasticsearch
test instance through an established SSH tunnel. The source was a historical
synthetic Elastic Security correlation alert. Validation used a fresh isolated
SQLite database; the earlier failed validation database was preserved, and the
operational SQLite database was not used.

## Observed results

| Item | Recorded result |
| --- | --- |
| Local alert ID | `ENGINE30_ALERT_ID` |
| Job ID | `ENGINE30_JOB_ID` |
| Investigation ID | `ENGINE30_INVESTIGATION_ID` |
| Job outcome | Completed on the first attempt |
| Coordination audit | `enqueued`, `claimed`, `completed` |
| Investigation status | `completed` |
| Retrieved evidence | 1; all retrieved evidence marked `found` |
| Evidence gaps | 0 |
| Final queue | 1 completed, 0 failed, 0 pending, 0 overdue leases, 0 delayed retries |

No Kibana Cases publication or remediation occurred.

## Version boundary and limitations

Engine 3.1 was subsequently implemented in the engine 3.1 upgrade. Its reported
offline validation is 476 passing tests, including upgrade compatibility regression
coverage. These offline results are separate from this live run: **engine 3.1 was
not exercised by this live validation**.

The observed result establishes completion for this single historical synthetic
alert under engine 3.0 in the isolated test environment. It does not establish
engine 3.1 live behavior, production readiness, broader evidence coverage, Kibana
Cases publication, or remediation behavior.
