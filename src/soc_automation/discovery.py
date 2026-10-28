"""Bounded local discovery persistence; no scheduling or external side effects."""

import json

from soc_automation.preparation import _bound


def _cursor(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("Invalid discovery cursor or revision")
    return value


def _identity(target, renderer_version):
    from soc_automation.cases import RENDERER_VERSION
    from soc_automation.state import _canonical_case_target

    if not _canonical_case_target(target):
        raise ValueError("Canonical case target required")
    if renderer_version is None:
        renderer_version = RENDERER_VERSION
    if renderer_version != RENDERER_VERSION:
        raise ValueError("Unsupported discovery renderer")
    return renderer_version


class DiscoveryStore:
    def _discovery_checkpoint(self, conn, target, renderer_version):
        row = conn.execute(
            "SELECT * FROM case_preparation_discovery WHERE target=? AND renderer_version=?",
            (target, renderer_version),
        ).fetchone()
        return dict(row) if row else None

    def initialize_case_preparation_discovery(self, target, *, renderer_version=None):
        """Capture the audit boundary once; repeated initialization preserves progress."""
        renderer_version = _identity(target, renderer_version)
        with self._connection() as conn:
            self._validate(conn)
            high = conn.execute("SELECT coalesce(max(id),0) FROM investigation_audit").fetchone()[0]
            conn.execute(
                "INSERT OR IGNORE INTO case_preparation_discovery "
                "(target,renderer_version,historical_high_water,live_cursor) VALUES(?,?,?,?)",
                (target, renderer_version, high, high),
            )
            return self._discovery_checkpoint(conn, target, renderer_version)

    def case_preparation_discovery_checkpoint(self, target, *, renderer_version=None):
        """Read existing progress, or None; never initialize a database or checkpoint."""
        renderer_version = _identity(target, renderer_version)
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            return self._discovery_checkpoint(conn, target, renderer_version)

    def _discovery_page(self, conn, checkpoint, lane, limit):
        after = checkpoint[lane + "_cursor"]
        upper = (checkpoint["historical_high_water"] if lane == "historical" else
                 conn.execute("SELECT coalesce(max(id),0) FROM investigation_audit").fetchone()[0])
        # INTEGER PRIMARY KEY range scan, followed by at most limit PK lookups.
        rows = conn.execute(
            "SELECT a.id,a.investigation_id,i.report_json FROM investigation_audit a "
            "LEFT JOIN investigations i ON i.id=a.investigation_id "
            "WHERE a.id>? AND a.id<=? ORDER BY a.id LIMIT ?", (after, upper, limit),
        ).fetchall()
        records = []
        for row in rows:
            eligible = False
            if row["report_json"] is None and row["investigation_id"] is not None:
                from soc_automation.state import StateError

                raise StateError("Missing persisted investigation for discovery event")
            if row["report_json"] is not None:
                from soc_automation.cases import ReportIneligible
                from soc_automation.state import ReportEvidenceIneligible

                try:
                    self._preparation_payload(conn, json.loads(row["report_json"]))
                    eligible = True
                except (ReportIneligible, ReportEvidenceIneligible):
                    pass
            records.append({"audit_id": row["id"], "investigation_id": row["investigation_id"],
                            "eligible": eligible})
        return {"checkpoint": checkpoint, "lane": lane, "records": records,
                "next_cursor": rows[-1]["id"] if rows else upper}

    @staticmethod
    def _discovery_inputs(target, renderer_version, lane, limit):
        renderer_version = _identity(target, renderer_version)
        if lane not in ("historical", "live"):
            raise ValueError("Invalid discovery lane")
        _bound(limit)
        return renderer_version

    def preview_case_preparation_discovery(self, target, *, lane, limit=100,
                                           renderer_version=None):
        """Inspect one page without writes. An absent checkpoint uses a virtual boundary."""
        renderer_version = self._discovery_inputs(target, renderer_version, lane, limit)
        with self._connection(readonly=True) as conn:
            self._validate(conn)
            checkpoint = self._discovery_checkpoint(conn, target, renderer_version)
            if checkpoint is None:
                high = conn.execute(
                    "SELECT coalesce(max(id),0) FROM investigation_audit"
                ).fetchone()[0]
                checkpoint = dict(target=target, renderer_version=renderer_version,
                                  historical_high_water=high, historical_cursor=0,
                                  live_cursor=high, revision=0)
            return self._discovery_page(conn, checkpoint, lane, limit)

    def advance_case_preparation_discovery(self, target, *, lane, expected_revision,
                                           limit=100, renderer_version=None):
        """Resolve a bounded page and CAS its cursor atomically; stale revisions fail.

        Eligible records use the existing idempotent enqueue. Ineligible records are
        resolved by validation against the immutable report in this transaction.
        Unexpected errors roll back both enqueues and checkpoint movement.
        """
        from soc_automation.state import StateError

        renderer_version = self._discovery_inputs(target, renderer_version, lane, limit)
        _cursor(expected_revision)
        with self._connection() as conn:
            self._validate(conn)
            checkpoint = self._discovery_checkpoint(conn, target, renderer_version)
            if checkpoint is None or checkpoint["revision"] != expected_revision:
                raise StateError("Missing discovery checkpoint or stale revision")
            page = self._discovery_page(conn, checkpoint, lane, limit)
            for record in page["records"]:
                if record["eligible"]:
                    job = self._enqueue_case_preparation(
                        conn, record["investigation_id"], target, 3,
                    )
                    record["preparation_id"] = job["id"]
            column = "historical_cursor" if lane == "historical" else "live_cursor"
            changed = conn.execute(
                f"UPDATE case_preparation_discovery SET {column}=?,revision=revision+1 "  # noqa: S608
                "WHERE target=? AND renderer_version=? AND revision=?",
                (page["next_cursor"], target, renderer_version, expected_revision),
            )
            if changed.rowcount != 1:
                raise StateError("Stale discovery revision")
            page["checkpoint"] = self._discovery_checkpoint(conn, target, renderer_version)
            return page
