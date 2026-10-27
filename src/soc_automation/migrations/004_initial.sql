CREATE TABLE case_publications (
 id TEXT PRIMARY KEY,
 investigation_id TEXT NOT NULL REFERENCES investigations(id),
 target TEXT NOT NULL,
 payload_json TEXT NOT NULL,
 payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
 approval_sha256 TEXT,
 state TEXT NOT NULL CHECK(state IN ('prepared','sending','uncertain','published')),
 remote_case_id TEXT,
 remote_version TEXT,
 created_at TEXT NOT NULL,
 UNIQUE(investigation_id,target),
 CHECK(approval_sha256 IS NULL OR approval_sha256=payload_sha256),
 CHECK(state='prepared' OR approval_sha256 IS NOT NULL),
 CHECK((state='published' AND remote_case_id IS NOT NULL AND remote_version IS NOT NULL)
       OR (state!='published' AND remote_case_id IS NULL AND remote_version IS NULL))
);
CREATE TABLE case_publication_audit (
 id INTEGER PRIMARY KEY,
 publication_id TEXT NOT NULL REFERENCES case_publications(id),
 event TEXT NOT NULL CHECK(event IN ('prepared','sending','uncertain','published')),
 occurred_at TEXT NOT NULL
);
CREATE TRIGGER publication_transition BEFORE UPDATE ON case_publications
WHEN NOT ((OLD.state='prepared' AND NEW.state='sending')
 OR (OLD.state='sending' AND NEW.state IN ('uncertain','published'))
 OR (OLD.state='uncertain' AND NEW.state='published'))
BEGIN SELECT RAISE(ABORT,'invalid publication transition'); END;
CREATE TRIGGER publication_frozen BEFORE UPDATE ON case_publications
WHEN NEW.id IS NOT OLD.id OR NEW.investigation_id IS NOT OLD.investigation_id
 OR NEW.target IS NOT OLD.target OR NEW.payload_json IS NOT OLD.payload_json
 OR NEW.payload_sha256 IS NOT OLD.payload_sha256 OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.approval_sha256 IS NOT NULL AND NEW.approval_sha256 IS NOT OLD.approval_sha256)
BEGIN SELECT RAISE(ABORT,'frozen publication'); END;
CREATE TRIGGER publication_no_delete BEFORE DELETE ON case_publications
BEGIN SELECT RAISE(ABORT,'immutable publication'); END;
CREATE TRIGGER publication_audit_insert AFTER INSERT ON case_publications
BEGIN INSERT INTO case_publication_audit(publication_id,event,occurred_at)
 VALUES(NEW.id,NEW.state,strftime('%Y-%m-%dT%H:%M:%fZ','now')); END;
CREATE TRIGGER publication_audit_transition AFTER UPDATE ON case_publications
BEGIN INSERT INTO case_publication_audit(publication_id,event,occurred_at)
 VALUES(NEW.id,NEW.state,strftime('%Y-%m-%dT%H:%M:%fZ','now')); END;
CREATE TRIGGER publication_audit_no_update BEFORE UPDATE ON case_publication_audit
BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER publication_audit_no_delete BEFORE DELETE ON case_publication_audit
BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER publication_initial_state BEFORE INSERT ON case_publications
WHEN NEW.state!='prepared' OR NEW.approval_sha256 IS NOT NULL
BEGIN SELECT RAISE(ABORT,'publication must start prepared'); END;
