CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 128),
    source_alert_id TEXT NOT NULL CHECK(length(source_alert_id) BETWEEN 1 AND 512),
    correlation_id TEXT NOT NULL CHECK(length(correlation_id) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK(state IN ('registered','triaged','investigating','completed','failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(source, source_alert_id)
);
CREATE TABLE audit_records (
    id INTEGER PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    correlation_id TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('registered','state_changed')),
    previous_state TEXT,
    new_state TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX audit_alert_id ON audit_records(alert_id, id);
CREATE TRIGGER validate_alert_transition BEFORE UPDATE OF state ON alerts
WHEN NOT (
    (OLD.state = 'registered' AND NEW.state IN ('triaged','failed')) OR
    (OLD.state = 'triaged' AND NEW.state IN ('investigating','failed')) OR
    (OLD.state = 'investigating' AND NEW.state IN ('completed','failed'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid processing transition');
END;
CREATE TRIGGER audit_registration AFTER INSERT ON alerts
BEGIN
    INSERT INTO audit_records(alert_id, correlation_id, event, previous_state, new_state, occurred_at)
    VALUES(NEW.id, NEW.correlation_id, 'registered', NULL, NEW.state, NEW.created_at);
END;
CREATE TRIGGER audit_transition AFTER UPDATE OF state ON alerts
BEGIN
    INSERT INTO audit_records(alert_id, correlation_id, event, previous_state, new_state, occurred_at)
    VALUES(NEW.id, NEW.correlation_id, 'state_changed', OLD.state, NEW.state, NEW.updated_at);
END;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_records
BEGIN
    SELECT RAISE(ABORT, 'audit records are append only');
END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_records
BEGIN
    SELECT RAISE(ABORT, 'audit records are append only');
END;
