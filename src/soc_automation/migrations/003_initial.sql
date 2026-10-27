CREATE TABLE investigations (
    id TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL UNIQUE,
    report_json TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL
);
CREATE TABLE investigation_evidence (
    source_index TEXT NOT NULL,
    document_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    original_json TEXT NOT NULL,
    PRIMARY KEY(source_index, document_id)
);
CREATE TABLE investigation_references (
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    alert_id TEXT NOT NULL REFERENCES ingested_alerts(alert_id),
    reference_json TEXT NOT NULL
);
CREATE TABLE investigation_audit (
    id INTEGER PRIMARY KEY,
    investigation_id TEXT,
    correlation_id TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('completed','duplicate','failed','conflict')),
    occurred_at TEXT NOT NULL
);
CREATE TRIGGER investigations_no_update BEFORE UPDATE ON investigations
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigations_no_delete BEFORE DELETE ON investigations
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_evidence_no_update BEFORE UPDATE ON investigation_evidence
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_evidence_no_delete BEFORE DELETE ON investigation_evidence
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_references_no_update BEFORE UPDATE ON investigation_references
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_references_no_delete BEFORE DELETE ON investigation_references
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_audit_no_update BEFORE UPDATE ON investigation_audit
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_audit_no_delete BEFORE DELETE ON investigation_audit
BEGIN
 SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TABLE investigation_alerts (
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    alert_id TEXT NOT NULL REFERENCES ingested_alerts(alert_id),
    PRIMARY KEY(investigation_id, alert_id)
);
CREATE TRIGGER investigation_alerts_no_update BEFORE UPDATE ON investigation_alerts
BEGIN
    SELECT RAISE(ABORT, 'investigation records are immutable');
END;
CREATE TRIGGER investigation_alerts_no_delete BEFORE DELETE ON investigation_alerts
BEGIN
    SELECT RAISE(ABORT, 'investigation records are immutable');
END;
