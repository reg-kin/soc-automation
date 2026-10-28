"""Offline discovery and integrity-checked frozen publication snapshots."""

import base64
import binascii
import hashlib
import json
import re

REVIEW_STATUSES = ("unreviewed", "approved", "declined", "revoked")


def _sha256(text):
    if not isinstance(text, str):
        raise ValueError("Stored text required")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _object(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("Invalid JSON constant")

    result = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


class PublicationReviewStore:
    def list_case_publications(self, limit=100, *, review_status=None, target=None, cursor=None):
        """List current prepared heads in insertion order, with a fixed insertion ceiling.

        Each page has its own read snapshot: later decisions and head changes are visible.
        New insertions are excluded from continuation pages. Cursors are filter-bound.
        """
        from soc_automation.state import _canonical_case_target

        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid limit")
        if review_status is not None and review_status not in REVIEW_STATUSES:
            raise ValueError("Invalid review status")
        if target is not None and not _canonical_case_target(target):
            raise ValueError("Invalid target")
        after, ceiling = 0, None
        if cursor is not None:
            try:
                if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
                    raise ValueError("Invalid cursor")
                data = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
                version, after, ceiling, status, destination = data
                if (type(version) is not int or version != 1
                        or type(after) is not int or type(ceiling) is not int
                        or not 0 < after <= ceiling or ceiling > 2**63 - 1
                        or status != review_status or destination != target):
                    raise ValueError("Invalid cursor")
            except (ValueError, TypeError, binascii.Error, UnicodeError):
                raise ValueError("Invalid cursor") from None
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            if ceiling is None:
                ceiling = conn.execute(
                    "SELECT coalesce(max(rowid),0) FROM case_publications"
                ).fetchone()[0]
            rows = conn.execute(
                "SELECT p.rowid AS sequence,p.id,p.investigation_id,p.target,p.state,"
                "p.payload_sha256,p.created_at,coalesce(r.decision,'unreviewed') AS review_status "
                "FROM case_publications p JOIN publication_heads h ON h.publication_id=p.id "
                "AND h.investigation_id=p.investigation_id AND h.target=p.target "
                "LEFT JOIN case_review_events r ON r.id=(SELECT max(id) FROM case_review_events "
                "WHERE publication_id=p.id) WHERE p.state='prepared' AND p.rowid>? AND p.rowid<=? "
                "AND (? IS NULL OR p.target=?) "
                "AND (? IS NULL OR coalesce(r.decision,'unreviewed')=?) "
                "ORDER BY p.rowid LIMIT ?",
                (after, ceiling, target, target, review_status, review_status, limit + 1),
            ).fetchall()
            next_cursor = None
            if len(rows) > limit:
                token = [1, rows[limit - 1]["sequence"], ceiling, review_status, target]
                next_cursor = base64.urlsafe_b64encode(json.dumps(token).encode()).decode()
            items = []
            for row in rows[:limit]:
                item = dict(row)
                del item["sequence"]
                item["is_current_head"] = True
                items.append(item)
            return {"publications": items, "next_cursor": next_cursor}

    def review_case_publication(self, publication_id):
        """Return frozen artifacts verified by bindings or deterministic evidence."""
        from soc_automation.state import _identifier

        _identifier(publication_id, 256)
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            return self._verify_case_publication(conn, publication_id)

    def _verify_case_publication(self, conn, publication_id):
        """Private verifier; caller owns the connection, transaction and schema check."""
        from soc_automation.cases import RENDERER_VERSION
        from soc_automation.ingestion import encode
        from soc_automation.state import StateError, _canonical_case_target, _identifier

        _identifier(publication_id, 256)
        row = conn.execute(
            "SELECT * FROM case_publications WHERE id=?", (publication_id,)
        ).fetchone()
        if row is None:
            raise StateError("Unknown publication")
        result = dict(row)
        try:
            if not _canonical_case_target(row["target"]):
                raise ValueError("Invalid target")
            if _sha256(row["payload_json"]) != row["payload_sha256"]:
                raise ValueError("Payload hash mismatch")
            payload = _object(row["payload_json"])
            match = re.match(r"Case rendering format: ([^\s]+)\n", payload["description"])
            if match is None:
                raise ValueError("Missing renderer identity")
            renderer = match[1]
            investigation = conn.execute(
                "SELECT * FROM investigations WHERE id=?", (row["investigation_id"],)
            ).fetchone()
            if investigation is None:
                raise ValueError("Missing investigation")
            report_text = investigation["report_json"]
            report = _object(report_text)
            if report["investigation_id"] != row["investigation_id"]:
                raise ValueError("Investigation identity mismatch")
            self._validate_report_evidence(conn, report)
            report_hash = _sha256(report_text)
            history = [dict(r) for r in conn.execute(
                "SELECT * FROM case_review_events WHERE publication_id=? ORDER BY id",
                (publication_id,),
            )]
            preparations = conn.execute(
                "SELECT * FROM case_preparation_jobs WHERE publication_id=?",
                (publication_id,),
            ).fetchall()
            bound = bool(history or preparations)
            if not bound:
                if renderer != RENDERER_VERSION:
                    raise ValueError("Unsupported renderer")
                expected = self._preparation_payload(conn, report)
                if encode(payload) != encode(expected):
                    raise ValueError("Deterministic payload mismatch")
            for job in preparations:
                if (job["report_json"] != report_text or job["report_sha256"] != report_hash
                        or job["investigation_id"] != row["investigation_id"]
                        or job["target"] != row["target"] or job["renderer_version"] != renderer
                        or job["evidence_fingerprint"] != investigation["evidence_fingerprint"]
                        or job["state"] != "completed"):
                    raise ValueError("Preparation binding mismatch")
            previous = None
            for event in history:
                if (event["previous_event_id"] != (previous["id"] if previous else None)
                        or event["payload_sha256"] != row["payload_sha256"]
                        or event["target"] != row["target"]
                        or event["report_sha256"] != report_hash
                        or event["renderer_version"] != renderer):
                    raise ValueError("Review binding mismatch")
                allowed = ({"approved", "declined"} if previous is None
                           or previous["decision"] in {"declined", "revoked"} else {"revoked"})
                if event["decision"] not in allowed:
                    raise ValueError("Invalid review sequence")
                previous = event
            audit = [dict(r) for r in conn.execute(
                "SELECT * FROM case_publication_audit WHERE publication_id=? ORDER BY id",
                (publication_id,),
            )]
            states = [event["event"] for event in audit]
            if states not in (["prepared"], ["prepared", "sending"],
                              ["prepared", "sending", "uncertain"],
                              ["prepared", "sending", "published"],
                              ["prepared", "sending", "uncertain", "published"]):
                raise ValueError("Invalid transition audit")
            if states[-1] != row["state"]:
                raise ValueError("Publication state mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError,
                AttributeError, IndexError, RecursionError) as error:
            raise StateError("Frozen publication integrity verification failed") from error
        head = conn.execute(
            "SELECT publication_id FROM publication_heads "
            "WHERE investigation_id=? AND target=?",
            (row["investigation_id"], row["target"]),
        ).fetchone()
        if head is None:
            raise StateError("Missing publication head")
        result.update(
            is_current_head=head[0] == publication_id,
            payload=payload,
            payload_sha256_verified=True,
            report_json=report_text,
            report=report,
            report_sha256=report_hash,
            verification_method="hash_binding" if bound else "deterministic_evidence",
            report_sha256_verified=bound,
            report_hash_sources=(["preparation"] if preparations else [])
            + (["review"] if history else []),
            renderer_version=renderer,
            review_status=history[-1]["decision"] if history else "unreviewed",
            latest_review=history[-1] if history else None,
            review_history=history,
            audit=audit,
        )
        return result
