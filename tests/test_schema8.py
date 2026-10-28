"""Schema 8 contracts using synthetic records and temporary databases only.

Also runnable with unittest when pytest is unavailable.
"""

import hashlib
import sqlite3
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import soc_automation.state as state
from soc_automation.state import StateError, Store


class Schema8Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "state.db")
        self.store.initialize()
        with self.store._connection() as c:
            c.execute("INSERT INTO investigations VALUES('inv','fingerprint','{}',?)", ("e" * 64,))
        self.report_hash = hashlib.sha256(b"{}").hexdigest()
        self.pub = self.publication("one")

    def publication(self, marker, revise=False):
        return self.store.prepare_publication(
            "inv",
            "https://example.test/default/securitySolution",
            {"tags": [marker], "description": "Case rendering format: soc-case/2\n\nSynthetic"},
            revise=revise,
        )

    def review(self, decision="approved", **overrides):
        with self.store._connection() as c:
            prior = c.execute("SELECT max(id) FROM case_review_events").fetchone()[0]
            values = dict(
                publication_id=self.pub["id"],
                request_id=f"req-{prior}-{decision}",
                decision=decision,
                previous_event_id=prior,
                payload_sha256=self.pub["payload_sha256"],
                target=self.pub["target"],
                report_sha256=self.report_hash,
                renderer_version="soc-case/2",
                review_policy_version="test/1",
                actor_uid=1000,
                actor_principal="test:operator",
                authentication_method="os_peer_credentials",
                decided_at="2026-10-01T00:00:00Z",
            )
            values.update(overrides)
            values.setdefault("id", None)
            c.execute(
                "INSERT INTO case_review_events (id,publication_id,request_id,decision,"
                "previous_event_id,payload_sha256,target,report_sha256,renderer_version,"
                "review_policy_version,actor_uid,actor_principal,authentication_method,decided_at) "
                "VALUES (:id,:publication_id,:request_id,:decision,:previous_event_id,"
                ":payload_sha256,:target,:report_sha256,:renderer_version,:review_policy_version,"
                ":actor_uid,:actor_principal,:authentication_method,:decided_at)",
                values,
            )

    def job(self, **overrides):
        values = dict(
            id="job",
            investigation_id="inv",
            target=self.pub["target"],
            renderer_version="soc-case/2",
            report_json="{}",
            report_sha256=self.report_hash,
            evidence_fingerprint="e" * 64,
            created_at=1,
            available_at=0,
            max_attempts=2,
        )
        values.update(overrides)
        with self.store._connection() as c:
            values.setdefault("state", "queued")
            c.execute(
                "INSERT INTO case_preparation_jobs (id,investigation_id,target,renderer_version,"
                "report_json,report_sha256,evidence_fingerprint,created_at,available_at,"
                "max_attempts,state) VALUES (:id,:investigation_id,:target,:renderer_version,"
                ":report_json,:report_sha256,:evidence_fingerprint,:created_at,:available_at,"
                ":max_attempts,:state)",
                values,
            )

    def sql(self, statement, args=()):
        with self.store._connection() as c:
            c.execute(statement, args)

    def claim_job(self):
        self.sql(
            "UPDATE case_preparation_jobs SET state='leased',attempt_count=1,"
            "lease_generation=1,lease_owner='operator',lease_until=coordination_now()+60,"
            "audit_sequence=1 WHERE id='job'"
        )

    def test_fresh_repeat_and_missing_objects(self):
        self.store.initialize()
        self.store.healthcheck()
        with self.store._connection() as c:
            self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 8)
        self.sql("DROP INDEX case_review_publication")
        with self.assertRaises(StateError):
            self.store.healthcheck()

    def test_approval_single_claim_and_immutability(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.claim_publication(self.pub["id"], self.pub["payload_sha256"])
        self.review()
        for statement in [
            "UPDATE case_review_events SET actor_uid=0",
            "DELETE FROM case_review_events",
        ]:
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql(statement)
        self.assertTrue(self.store.claim_publication(self.pub["id"], self.pub["payload_sha256"]))
        self.assertFalse(self.store.claim_publication(self.pub["id"], self.pub["payload_sha256"]))
        with self.assertRaises(sqlite3.IntegrityError):
            self.review("revoked")
        self.store.publication_outcome(self.pub["id"])
        self.store.publication_outcome(self.pub["id"], {"id": "remote", "version": "1"})
        self.assertEqual(self.store.show_case_publication(self.pub["id"])["state"], "published")

    def test_invalid_reviews_and_revocation(self):
        for change in [
            dict(decision="revoked"),
            dict(target="other"),
            dict(payload_sha256="a" * 64),
            dict(report_sha256="a" * 64),
            dict(authentication_method="username"),
            dict(actor_uid="username"),
            dict(previous_event_id=100),
            dict(renderer_version="other"),
        ]:
            with self.subTest(change=change), self.assertRaises(sqlite3.IntegrityError):
                self.review(**change)
        self.review()
        with self.assertRaises(sqlite3.IntegrityError):
            self.review(request_id="another")
        self.review("revoked")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.claim_publication(self.pub["id"], self.pub["payload_sha256"])
        self.review("approved")
        self.assertTrue(self.store.claim_publication(self.pub["id"], self.pub["payload_sha256"]))

    def test_stale_head_and_foreign_keys(self):
        self.review()
        old = self.pub
        self.pub = self.publication("two", revise=True)
        self.assertFalse(self.store.claim_publication(old["id"], old["payload_sha256"]))
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.claim_publication(self.pub["id"], self.pub["payload_sha256"])
        for args in [
            ("missing", "target", self.pub["id"]),
            ("inv", "other", self.pub["id"]),
            ("inv", "target", "missing"),
        ]:
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql("INSERT INTO publication_heads VALUES(?,?,?)", args)
        with self.assertRaises(sqlite3.IntegrityError):
            self.job(investigation_id="missing")

    @patch.object(state.time, "time", new=lambda: 100)
    def test_jobs_and_atomic_audit(self):
        for change in [
            dict(state="bogus"),
            dict(state="completed"),
            dict(report_sha256="a" * 64),
            dict(evidence_fingerprint="wrong"),
            dict(max_attempts=0),
        ]:
            with self.subTest(change=change), self.assertRaises(sqlite3.IntegrityError):
                self.job(**change)
        self.job()
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql("UPDATE case_preparation_jobs SET state='failed'")
        self.claim_job()
        self.sql(
            "UPDATE case_preparation_jobs SET state='retry_wait',lease_owner=NULL,"
            "lease_until=NULL,failure_code='transient',available_at=coordination_now(),audit_sequence=2"
        )
        self.sql(
            "UPDATE case_preparation_jobs SET state='leased',attempt_count=2,"
            "lease_generation=2,lease_owner='operator2',lease_until=coordination_now()+60,"
            "failure_code=NULL,audit_sequence=3"
        )
        self.sql(
            "UPDATE case_preparation_jobs SET state='completed',lease_owner=NULL,"
            "lease_until=NULL,publication_id=?,audit_sequence=4",
            (self.pub["id"],),
        )
        for statement in [
            "DELETE FROM case_preparation_jobs",
            "UPDATE case_preparation_jobs SET target='x'",
            "UPDATE case_preparation_jobs SET audit_sequence=5",
            "DELETE FROM case_preparation_audit",
            "UPDATE case_preparation_audit SET owner='x'",
            "INSERT INTO "
            "case_preparation_audit(job_id,event,generation,owner,occurred_at) "
            "VALUES('job','completed',2,'operator2',1)",
        ]:
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.sql(statement)
        with self.store._connection() as c:
            self.assertEqual(
                [r[0] for r in c.execute("SELECT event FROM case_preparation_audit ORDER BY id")],
                ["enqueued", "claimed", "retry_wait", "claimed", "completed"],
            )

    def test_audit_failure_rolls_back_transition(self):
        self.job()
        self.sql(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON case_preparation_audit "
            "WHEN NEW.event='claimed' BEGIN SELECT RAISE(ABORT,'test'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.claim_job()
        with self.store._connection() as c:
            self.assertEqual(
                c.execute("SELECT state FROM case_preparation_jobs").fetchone()[0], "queued"
            )
            self.assertEqual(
                c.execute("SELECT count(*) FROM case_preparation_audit").fetchone()[0], 1
            )

    def test_lease_renewal_expiry_and_retry_budget(self):
        self.job()
        with patch.object(state.time, "time", return_value=100):
            self.claim_job()
            self.sql("UPDATE case_preparation_jobs SET lease_until=200,audit_sequence=2")
        with patch.object(state.time, "time", return_value=201):
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql(
                    "UPDATE case_preparation_jobs SET state='failed',lease_owner=NULL,"
                    "lease_until=NULL,failure_code='permanent',audit_sequence=3"
                )
            self.sql(
                "UPDATE case_preparation_jobs SET state='retry_wait',lease_owner=NULL,"
                "lease_until=NULL,failure_code='lease_expired',available_at=300,audit_sequence=3"
            )
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql(
                    "UPDATE case_preparation_jobs SET state='leased',lease_owner='next',"
                    "lease_until=400,attempt_count=2,lease_generation=2,failure_code=NULL,audit_sequence=4"
                )
        with patch.object(state.time, "time", return_value=301):
            self.sql(
                "UPDATE case_preparation_jobs SET state='leased',lease_owner='next',"
                "lease_until=400,attempt_count=2,lease_generation=2,failure_code=NULL,audit_sequence=4"
            )
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql(
                    "UPDATE case_preparation_jobs SET state='retry_wait',lease_owner=NULL,"
                    "lease_until=NULL,failure_code='transient',audit_sequence=5"
                )
            self.sql(
                "UPDATE case_preparation_jobs SET state='failed',lease_owner=NULL,"
                "lease_until=NULL,failure_code='transient',audit_sequence=5"
            )
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql("UPDATE case_preparation_jobs SET available_at=500,audit_sequence=6")

    def test_sequence_and_audit_forgery_rejected(self):
        self.review()
        with self.assertRaises(sqlite3.IntegrityError):
            self.review("revoked", id=-1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.review("revoked", decided_at="2025-01-01")
        self.review("revoked")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(
                "INSERT OR REPLACE INTO case_review_events "
                "SELECT id,publication_id,request_id,decision,previous_event_id,payload_sha256,"
                "target,report_sha256,renderer_version,review_policy_version,actor_uid,"
                "actor_principal,authentication_method,decided_at,reason_code FROM "
                "case_review_events "
                "WHERE id=1"
            )
        self.job()
        self.claim_job()
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(
                "INSERT INTO case_preparation_audit(job_id,event,generation,owner,occurred_at) "
                "VALUES('job','renewed',1,'operator',1)"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(
                "UPDATE case_preparation_jobs SET state='completed',lease_owner=NULL,"
                "lease_until=NULL,publication_id='missing',audit_sequence=2"
            )

    def test_transition_field_preservation_and_stale_generation(self):
        self.job()
        with patch.object(state.time, "time", return_value=100):
            for extra in [",available_at=99", ",lease_generation=0", ",attempt_count=2"]:
                with self.subTest(extra=extra), self.assertRaises(sqlite3.IntegrityError):
                    self.sql(
                        "".join(("UPDATE case_preparation_jobs SET state='leased',attempt_count=1,"
                                 "lease_generation=1,lease_owner='operator',lease_until=160,"
                                 "audit_sequence=1", extra))
                    )
            self.claim_job()
            for assignments in [
                "lease_owner='other',lease_until=200",
                "lease_until=200,available_at=50",
                "lease_until=150",
                "state='retry_wait',lease_owner=NULL,lease_until=NULL,"
                "failure_code='transient',available_at=99",
                "state='retry_wait',lease_owner=NULL,lease_until=NULL,"
                "failure_code='lease_expired',available_at=200",
                "state='failed',lease_owner=NULL,lease_until=NULL,"
                "failure_code='permanent',available_at=200",
                "state='completed',lease_owner=NULL,lease_until=NULL,"
                "publication_id='missing'",
                "lease_until=200,lease_generation=2,attempt_count=2",
            ]:
                with (self.subTest(assignments=assignments),
                      self.assertRaises(sqlite3.IntegrityError)):
                    self.sql("".join(("UPDATE case_preparation_jobs SET audit_sequence=2,",
                                      assignments)))
            self.sql("UPDATE case_preparation_jobs SET lease_until=200,audit_sequence=2")
            self.sql("UPDATE case_preparation_jobs SET lease_until=250,audit_sequence=3")
        with patch.object(state.time, "time", return_value=250):
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql("UPDATE case_preparation_jobs SET lease_until=300,audit_sequence=4")
        with self.store._connection() as c:
            row = dict(c.execute("SELECT * FROM case_preparation_jobs").fetchone())
            self.assertEqual((row["available_at"], row["lease_generation"], row["lease_owner"]),
                             (0, 1, "operator"))
            self.assertEqual([r[0] for r in c.execute(
                "SELECT event FROM case_preparation_audit ORDER BY id"
            )], ["enqueued", "claimed", "renewed", "renewed"])

    def test_manual_audit_rows_and_transaction_rollback(self):
        self.job()
        for event, generation, owner in [
            ("enqueued", 0, None), ("claimed", 0, "operator"),
            ("renewed", 0, "operator"), ("failed", 0, "operator"),
        ]:
            with self.subTest(event=event), self.assertRaises(sqlite3.IntegrityError):
                self.sql(
                    "INSERT INTO case_preparation_audit"
                    "(job_id,event,generation,owner,occurred_at) VALUES('job',?,?,?,1)",
                    (event, generation, owner),
                )
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            with self.store._connection() as c:
                c.execute(
                    "UPDATE case_preparation_jobs SET state='leased',attempt_count=1,"
                    "lease_generation=1,lease_owner='operator',lease_until=coordination_now()+60,"
                    "audit_sequence=1"
                )
                raise RuntimeError("rollback")
        with self.store._connection() as c:
            self.assertEqual(tuple(c.execute(
                "SELECT state,audit_sequence FROM case_preparation_jobs"
            ).fetchone()), ("queued", 0))
            self.assertEqual(
                c.execute("SELECT count(*) FROM case_preparation_audit").fetchone()[0], 1
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(
                "INSERT OR REPLACE INTO case_preparation_jobs SELECT * FROM case_preparation_jobs"
            )

    def test_direct_publication_updates_require_latest_approval(self):
        statement = (
            "UPDATE case_publications SET state='sending',approval_sha256=payload_sha256 WHERE id=?"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(statement, (self.pub["id"],))
        self.review("declined")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(statement, (self.pub["id"],))
        self.review("approved", review_policy_version="future-policy/99")
        self.review("revoked")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(statement, (self.pub["id"],))
        self.review("approved")
        for change in ["state='published',remote_case_id='r',remote_version='v'",
                       "state='uncertain'", "state='sending',payload_sha256='" + "a" * 64 + "'"]:
            with self.subTest(change=change), self.assertRaises(sqlite3.IntegrityError):
                self.sql("".join(("UPDATE case_publications SET approval_sha256=payload_sha256,",
                                  change)))
        self.sql(statement, (self.pub["id"],))

    def test_completion_rejects_corrupt_payload_digest_and_wrong_renderer(self):
        self.job()
        self.claim_job()
        old = self.pub
        self.pub = self.store.prepare_publication(
            "inv", old["target"],
            {"tags": ["other-renderer"], "description": "Case rendering format: other/1\n"},
            revise=True,
        )
        completion = (
            "UPDATE case_preparation_jobs SET state='completed',lease_owner=NULL,"
            "lease_until=NULL,publication_id=?,audit_sequence=2"
        )
        for publication_id in [old["id"], self.pub["id"]]:
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql(completion, (publication_id,))
        # Schema 7 allowed caller-supplied digests. Keep such records but do not
        # accept a corrupt digest as new completion or approval provenance.
        self.sql(
            "INSERT INTO case_publications VALUES('corrupt','inv',?,?,?,NULL,"
            "'prepared',NULL,NULL,'time')",
            (old["target"], '{"tags":["corrupt"],"description":'
             '"Case rendering format: soc-case/2\\n"}', "a" * 64),
        )
        self.sql("UPDATE publication_heads SET publication_id='corrupt'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql(completion, ("corrupt",))
        self.pub = self.store.show_case_publication("corrupt")
        with self.assertRaises(sqlite3.IntegrityError):
            self.review()

    def legacy(self):
        path = Path(self.temp.name) / "legacy.db"
        store = Store(path)
        with patch.object(state, "SCHEMA_VERSION", 7), patch.object(Store, "_validate"):
            store.initialize()
        with store._connection() as c:
            c.execute("INSERT INTO investigations VALUES('inv','fp','{}',?)", ("e" * 64,))
            for status in ["prepared", "sending", "uncertain", "published"]:
                c.execute(
                    "INSERT INTO case_publications VALUES(?,?,?, "
                    "?,?,NULL,'prepared',NULL,NULL,'time')",
                    (status, "inv", status, '{"tags":["synthetic"]}', "a" * 64),
                )
                c.execute("INSERT INTO publication_heads VALUES(?,?,?)", ("inv", status, status))
                if status != "prepared":
                    c.execute(
                        "UPDATE case_publications SET "
                        "state='sending',approval_sha256=payload_sha256 WHERE id=?",
                        (status,),
                    )
                if status == "uncertain":
                    c.execute(
                        "UPDATE case_publications SET state='uncertain' WHERE id=?", (status,)
                    )
                if status == "published":
                    c.execute(
                        "UPDATE case_publications SET "
                        "state='published',remote_case_id='r',remote_version='v' WHERE id=?",
                        (status,),
                    )
        return store

    def test_populated_upgrade_and_old_binary(self):
        store = self.legacy()
        with store._connection() as c:
            before = [tuple(r) for r in c.execute("SELECT * FROM case_publications")]
            audit = [tuple(r) for r in c.execute("SELECT * FROM case_publication_audit")]
        store.initialize()
        store.initialize()
        with store._connection() as c:
            self.assertEqual(
                before, [tuple(r) for r in c.execute("SELECT * FROM case_publications")]
            )
            self.assertEqual(
                audit, [tuple(r) for r in c.execute("SELECT * FROM case_publication_audit")]
            )
            self.assertEqual(c.execute("SELECT count(*) FROM case_review_events").fetchone()[0], 0)
        with self.assertRaises(sqlite3.IntegrityError):
            store.claim_publication("prepared", "a" * 64)
        for status in ["sending", "uncertain"]:
            store.publication_outcome(status, {"id": "r", "version": "v"})
        with patch.object(state, "SCHEMA_VERSION", 7):
            with self.assertRaises(StateError):
                store.initialize()
            with self.assertRaises(StateError):
                store.healthcheck()

    def test_migration_rollback(self):
        store = self.legacy()
        original = files("soc_automation").joinpath("migrations/008_initial.sql").read_text()
        resource = unittest.mock.Mock()
        resource.joinpath.return_value.read_text.return_value = original + "\nINVALID SQL;\n"
        with (
            patch.object(state, "files", return_value=resource),
            self.assertRaises(sqlite3.OperationalError),
        ):
            store.initialize()
        with store._connection() as c:
            self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 7)
            self.assertIsNone(
                c.execute(
                    "SELECT name FROM sqlite_master WHERE name='case_review_events'"
                ).fetchone()
            )
            self.assertEqual(c.execute("SELECT count(*) FROM case_publications").fetchone()[0], 4)
        store.initialize()


if __name__ == "__main__":
    unittest.main()
