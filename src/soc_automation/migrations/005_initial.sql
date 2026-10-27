DROP TRIGGER publication_transition;
DROP TRIGGER publication_frozen;
DROP TRIGGER publication_no_delete;
DROP TRIGGER publication_audit_insert;
DROP TRIGGER publication_audit_transition;
DROP TRIGGER publication_audit_no_update;
DROP TRIGGER publication_audit_no_delete;
DROP TRIGGER publication_initial_state;
ALTER TABLE case_publication_audit RENAME TO old_publication_audit;
ALTER TABLE case_publications RENAME TO old_publications;
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
 UNIQUE(investigation_id,target,id),
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
INSERT INTO case_publications SELECT * FROM old_publications;
INSERT INTO case_publication_audit SELECT * FROM old_publication_audit;
DROP TABLE old_publication_audit;
DROP TABLE old_publications;
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

CREATE TABLE publication_heads (
 investigation_id TEXT NOT NULL,
 target TEXT NOT NULL,
 publication_id TEXT NOT NULL UNIQUE REFERENCES case_publications(id),
 PRIMARY KEY(investigation_id,target)
);
INSERT INTO publication_heads SELECT investigation_id,target,id FROM case_publications;
CREATE TRIGGER publication_current_claim BEFORE UPDATE ON case_publications
WHEN NEW.state='sending' AND NOT EXISTS (
 SELECT 1 FROM publication_heads WHERE publication_id=NEW.id)
BEGIN SELECT RAISE(ABORT,'superseded publication'); END;
CREATE TRIGGER publication_head_guard BEFORE UPDATE ON publication_heads
WHEN NEW.investigation_id IS NOT OLD.investigation_id OR NEW.target IS NOT OLD.target
 OR NOT EXISTS (SELECT 1 FROM case_publications WHERE id=NEW.publication_id
 AND investigation_id=NEW.investigation_id AND target=NEW.target AND state='prepared')
 OR EXISTS (SELECT 1 FROM case_publications WHERE investigation_id=OLD.investigation_id
 AND target=OLD.target AND state!='prepared')
BEGIN SELECT RAISE(ABORT,'revision prohibited after send'); END;
CREATE TRIGGER publication_head_no_delete BEFORE DELETE ON publication_heads
BEGIN SELECT RAISE(ABORT,'immutable publication head'); END;
CREATE UNIQUE INDEX publication_marker_unique
 ON case_publications(target,json_extract(payload_json,'$.tags[0]'));
CREATE TRIGGER publication_head_forward BEFORE UPDATE ON publication_heads
WHEN (SELECT rowid FROM case_publications WHERE id=NEW.publication_id)
 <= (SELECT rowid FROM case_publications WHERE id=OLD.publication_id)
BEGIN SELECT RAISE(ABORT,'superseded revision cannot become current'); END;
