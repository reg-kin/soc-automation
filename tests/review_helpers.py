"""Synthetic trusted review persistence for offline publication tests."""

from uuid import uuid4

from soc_automation.state import Store


def approve(store, publication_id):
    with store._connection() as conn:
        conn.execute(
            "INSERT INTO case_review_events(publication_id,request_id,decision,"
            "previous_event_id,payload_sha256,target,report_sha256,renderer_version,"
            "review_policy_version,actor_uid,actor_principal,authentication_method,decided_at) "
            "SELECT p.id,?,'approved',(SELECT max(id) FROM case_review_events WHERE "
            "publication_id=p.id),"
            "p.payload_sha256,p.target,sha256_text(i.report_json),'soc-case/2','test-policy/1',"
            "1000,'synthetic:test-operator','os_peer_credentials','2026-01-01T00:00:00Z' "
            "FROM case_publications p JOIN investigations i ON i.id=p.investigation_id "
            "WHERE p.id=?",
            (str(uuid4()), publication_id),
        )


class LegacyClaimStore(Store):
    """Historical trigger-level harness only; never imported by production code.

    Existing synthetic approvals predate active policy and preparation provenance.
    Keep those database/service regressions isolated from the production gate.
    New approval tests must use the real Store.
    """

    def _check_publication_policy(self, conn, publication_id):
        pass
