# Milestone 5C-3: live validation record

## Scope and provenance

This record captures operator-verified engine 3.0 and 3.1 results from 2026-10-27 UTC on an isolated
isolated test server. It complements the [offline integration validation](milestone-5c-integration.md)
and [operational guidance](milestone-5c-operations.md). The documentation update
did not independently rerun validation or access databases or live services.

The run used engine **3.0**, with a read-only connection to the SOC Elasticsearch
test instance through an established SSH tunnel. The source was a historical
synthetic Elastic Security correlation alert. Validation used a fresh isolated
SQLite database; the earlier failed validation database was preserved, and the
operational SQLite database was not used.

## Engine 3.0 observed results

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

## Engine 3.1 live validation

Engine **3.1** live validation **passed for this single historical synthetic
alert** on 2026-10-27 UTC. The run used the same historical synthetic Elastic
Security alert on the isolated isolated test server, with read-only access
to Elasticsearch through an SSH tunnel.

| Item | Recorded result |
| --- | --- |
| Engine version | `3.1` |
| Database | `/path/to/isolated-validation/soc_automation.db` |
| Local alert ID | `ENGINE31_ALERT_ID` |
| Job ID | `ENGINE31_JOB_ID` |
| Investigation ID | `ENGINE31_INVESTIGATION_ID` |
| Job outcome | Completed on the first attempt |
| Coordination audit | `enqueued`, `claimed`, `completed` |
| Investigation status | `completed` |
| Retrieved evidence | 1; all retrieved evidence marked `found` |
| Evidence gaps | 0 |
| Final queue | 1 completed, 0 failed, 0 pending, 0 overdue leases, 0 delayed retries |

No Kibana Cases publication or remediation occurred. Earlier validation databases
and the operational database were not modified by this validation workflow.

## Version boundary and limitations

Engine 3.1 was subsequently implemented in the engine 3.1 upgrade. Its reported
offline validation is 476 passing tests, including upgrade compatibility regression
coverage. These offline results are separate from the live validation records
above. The original live run exercised engine 3.0; the subsequent live run
exercised engine 3.1 and passed for the same single historical synthetic alert.

The observed result establishes completion for this single historical synthetic
alert under each of engines 3.0 and 3.1 in the isolated test environment. It does
not establish production readiness, broader alert or evidence coverage, Kibana
Cases publication, or remediation behavior.
