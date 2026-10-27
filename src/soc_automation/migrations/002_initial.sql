CREATE TABLE ingested_alerts (
    alert_id TEXT PRIMARY KEY REFERENCES alerts(id),
    source_index TEXT,
    document_id TEXT NOT NULL,
    original_json TEXT NOT NULL,
    original_sha256 TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    decision_json TEXT NOT NULL
);
CREATE TABLE ingestion_audit (
    id INTEGER PRIMARY KEY,
    alert_id TEXT REFERENCES alerts(id),
    event TEXT NOT NULL CHECK(event IN ('ingested','duplicate','rejected','triaged')),
    reason TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE TRIGGER ingestion_no_update BEFORE UPDATE ON ingested_alerts
BEGIN
    SELECT RAISE(ABORT, 'ingested evidence and decisions are immutable');
END;
CREATE TRIGGER ingestion_no_delete BEFORE DELETE ON ingested_alerts
BEGIN
    SELECT RAISE(ABORT, 'ingested evidence and decisions are immutable');
END;
CREATE TRIGGER ingestion_audit_no_update BEFORE UPDATE ON ingestion_audit
BEGIN
    SELECT RAISE(ABORT, 'audit records are append only');
END;
CREATE TRIGGER ingestion_audit_no_delete BEFORE DELETE ON ingestion_audit
BEGIN
    SELECT RAISE(ABORT, 'audit records are append only');
END;
