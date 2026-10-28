-- Stage 6.2A: persistence only. Authentication is supplied by a future trusted boundary.
CREATE TABLE case_preparation_jobs (
 id TEXT PRIMARY KEY NOT NULL CHECK(length(trim(id))>0),
 investigation_id TEXT NOT NULL REFERENCES investigations(id),
 target TEXT NOT NULL CHECK(length(trim(target))>0 AND target=trim(target) AND canonical_case_target(target)),
 renderer_version TEXT NOT NULL CHECK(length(trim(renderer_version))>0),
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 report_sha256 TEXT NOT NULL CHECK(length(report_sha256)=64 AND report_sha256 NOT GLOB '*[^0-9a-f]*'),
 evidence_fingerprint TEXT NOT NULL,
 audit_sequence INTEGER NOT NULL DEFAULT 0 CHECK(audit_sequence>=0),
 created_at REAL NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','retry_wait','completed','failed')),
 available_at REAL NOT NULL,
 max_attempts INTEGER NOT NULL CHECK(typeof(max_attempts)='integer' AND max_attempts BETWEEN 1 AND 100),
 attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempt_count)='integer' AND attempt_count BETWEEN 0 AND max_attempts),
 lease_generation INTEGER NOT NULL DEFAULT 0 CHECK(lease_generation=attempt_count),
 lease_owner TEXT,
 lease_until REAL,
 failure_code TEXT CHECK(failure_code IN ('transient','permanent','lease_expired','renderer_mismatch')),
 publication_id TEXT REFERENCES case_publications(id),
 UNIQUE(investigation_id,target,renderer_version,report_sha256),
 CHECK(state='queued' OR attempt_count>0),
 CHECK(state NOT IN ('queued','leased','completed') OR failure_code IS NULL),
 CHECK(state!='retry_wait' OR (attempt_count<max_attempts AND failure_code IN ('transient','lease_expired') AND failure_code IS NOT NULL)),
 CHECK(state!='failed' OR (failure_code IS NOT NULL AND (failure_code IN ('permanent','renderer_mismatch') OR attempt_count=max_attempts))),
 CHECK((state='leased' AND length(trim(lease_owner))>0 AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR (state!='leased' AND lease_owner IS NULL AND lease_until IS NULL)),
 CHECK((state='completed' AND publication_id IS NOT NULL) OR (state!='completed' AND publication_id IS NULL))
);
CREATE INDEX case_preparation_ready ON case_preparation_jobs(state,available_at,created_at,id);
CREATE INDEX case_preparation_publication ON case_preparation_jobs(publication_id);
CREATE TABLE case_preparation_audit (
 id INTEGER PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES case_preparation_jobs(id),
 event TEXT NOT NULL CHECK(event IN ('enqueued','claimed','renewed','retry_wait','completed','failed')),
 generation INTEGER NOT NULL CHECK(generation>=0),
 owner TEXT,
 occurred_at REAL NOT NULL,
 diagnostic_code TEXT CHECK(diagnostic_code IN ('transient','permanent','lease_expired','renderer_mismatch'))
);
CREATE INDEX case_preparation_audit_job ON case_preparation_audit(job_id,id);
CREATE TRIGGER preparation_initial BEFORE INSERT ON case_preparation_jobs
WHEN NEW.audit_sequence!=0 OR NEW.report_sha256!=sha256_text(NEW.report_json) OR NEW.state!='queued' OR NEW.attempt_count!=0 OR NEW.lease_generation!=0
 OR NOT EXISTS (SELECT 1 FROM investigations WHERE id=NEW.investigation_id AND report_json=NEW.report_json AND evidence_fingerprint=NEW.evidence_fingerprint)
BEGIN SELECT RAISE(ABORT,'invalid preparation origin'); END;
CREATE TRIGGER preparation_identity BEFORE UPDATE ON case_preparation_jobs
WHEN NEW.id IS NOT OLD.id OR NEW.investigation_id IS NOT OLD.investigation_id
 OR NEW.target IS NOT OLD.target OR NEW.renderer_version IS NOT OLD.renderer_version
 OR NEW.report_json IS NOT OLD.report_json OR NEW.report_sha256 IS NOT OLD.report_sha256
 OR NEW.evidence_fingerprint IS NOT OLD.evidence_fingerprint OR NEW.created_at IS NOT OLD.created_at
 OR NEW.max_attempts IS NOT OLD.max_attempts
BEGIN SELECT RAISE(ABORT,'immutable preparation identity'); END;
CREATE TRIGGER preparation_transition BEFORE UPDATE ON case_preparation_jobs
WHEN NEW.audit_sequence!=OLD.audit_sequence+1 OR NOT (
 (OLD.state IN ('queued','retry_wait') AND NEW.state='leased' AND OLD.available_at<=coordination_now()
 AND NEW.available_at IS OLD.available_at
 AND NEW.attempt_count=OLD.attempt_count+1 AND NEW.lease_generation=OLD.lease_generation+1 AND NEW.lease_until>coordination_now())
 OR (OLD.state='leased' AND OLD.lease_until>coordination_now() AND NEW.state='leased'
 AND NEW.lease_owner=OLD.lease_owner AND NEW.lease_until>OLD.lease_until
 AND NEW.attempt_count=OLD.attempt_count AND NEW.lease_generation=OLD.lease_generation AND NEW.available_at=OLD.available_at)
 OR (OLD.state='leased' AND NEW.state IN ('retry_wait','failed','completed')
 AND NEW.attempt_count=OLD.attempt_count AND NEW.lease_generation=OLD.lease_generation
 AND ((NEW.state='retry_wait' AND NEW.available_at>=coordination_now())
 OR (NEW.state IN ('failed','completed') AND NEW.available_at IS OLD.available_at))
 AND ((OLD.lease_until>coordination_now() AND NEW.failure_code IS NOT 'lease_expired')
 OR (OLD.lease_until<=coordination_now() AND NEW.failure_code IS 'lease_expired'))))
BEGIN SELECT RAISE(ABORT,'invalid preparation transition'); END;
CREATE TRIGGER preparation_completion BEFORE UPDATE ON case_preparation_jobs
WHEN NEW.state='completed' AND NOT EXISTS (
 SELECT 1 FROM case_publications p JOIN publication_heads h ON h.publication_id=p.id
 JOIN investigations i ON i.id=p.investigation_id
 WHERE i.report_json=NEW.report_json AND i.evidence_fingerprint=NEW.evidence_fingerprint
 AND sha256_text(i.report_json)=NEW.report_sha256
 AND p.payload_sha256=sha256_text(p.payload_json)
 AND p.id=NEW.publication_id AND p.investigation_id=NEW.investigation_id AND p.target=NEW.target AND p.state='prepared'
 AND instr(json_extract(p.payload_json,'$.description'),'Case rendering format: ' || NEW.renderer_version || char(10))=1)
BEGIN SELECT RAISE(ABORT,'invalid prepared publication'); END;
CREATE TRIGGER preparation_audit_insert AFTER INSERT ON case_preparation_jobs
BEGIN INSERT INTO case_preparation_audit(job_id,event,generation,owner,occurred_at,diagnostic_code)
 VALUES(NEW.id,'enqueued',0,NULL,coordination_now(),NULL); END;
CREATE TRIGGER preparation_audit_transition AFTER UPDATE ON case_preparation_jobs
BEGIN INSERT INTO case_preparation_audit(job_id,event,generation,owner,occurred_at,diagnostic_code)
 VALUES(NEW.id,CASE WHEN NEW.state='leased' THEN CASE WHEN OLD.state='leased' THEN 'renewed' ELSE 'claimed' END ELSE NEW.state END,
 NEW.lease_generation,coalesce(NEW.lease_owner,OLD.lease_owner),coordination_now(),NEW.failure_code); END;
CREATE TRIGGER preparation_audit_guard BEFORE INSERT ON case_preparation_audit
WHEN (SELECT count(*) FROM case_preparation_audit WHERE job_id=NEW.job_id)!=(SELECT audit_sequence FROM case_preparation_jobs WHERE id=NEW.job_id)
 OR NOT EXISTS (SELECT 1 FROM case_preparation_jobs j WHERE j.id=NEW.job_id
 AND j.lease_generation=NEW.generation AND NEW.diagnostic_code IS j.failure_code
 AND ((NEW.event='enqueued' AND j.state='queued' AND NEW.owner IS NULL)
 OR (NEW.event IN ('claimed','renewed') AND j.state='leased' AND NEW.owner=j.lease_owner)
 OR (NEW.event=j.state AND j.state IN ('retry_wait','completed','failed') AND NEW.owner=(SELECT owner FROM case_preparation_audit WHERE job_id=NEW.job_id ORDER BY id DESC LIMIT 1))))
 OR EXISTS (SELECT 1 FROM case_preparation_audit a WHERE a.job_id=NEW.job_id AND a.generation=NEW.generation AND a.event=NEW.event AND NEW.event!='renewed')
BEGIN SELECT RAISE(ABORT,'invalid preparation audit'); END;
CREATE TABLE case_review_events (
 id INTEGER PRIMARY KEY,
 publication_id TEXT NOT NULL REFERENCES case_publications(id),
 request_id TEXT NOT NULL UNIQUE CHECK(length(trim(request_id))>0),
 decision TEXT NOT NULL CHECK(decision IN ('approved','declined','revoked')),
 previous_event_id INTEGER UNIQUE REFERENCES case_review_events(id),
 payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
 target TEXT NOT NULL CHECK(length(trim(target))>0 AND target=trim(target) AND canonical_case_target(target)),
 report_sha256 TEXT NOT NULL CHECK(length(report_sha256)=64 AND report_sha256 NOT GLOB '*[^0-9a-f]*'),
 renderer_version TEXT NOT NULL CHECK(length(trim(renderer_version))>0),
 review_policy_version TEXT NOT NULL CHECK(length(trim(review_policy_version))>0),
 actor_uid INTEGER NOT NULL CHECK(typeof(actor_uid)='integer' AND actor_uid>=0),
 actor_principal TEXT NOT NULL CHECK(length(trim(actor_principal))>0),
 authentication_method TEXT NOT NULL CHECK(authentication_method IN ('os_peer_credentials','oidc')),
 decided_at TEXT NOT NULL CHECK(julianday(decided_at) IS NOT NULL),
 reason_code TEXT CHECK(reason_code IN ('operator_declined','operator_revoked','incorrect_payload','policy'))
);
CREATE INDEX case_review_publication ON case_review_events(publication_id,id);
CREATE TRIGGER review_initial BEFORE INSERT ON case_review_events
WHEN EXISTS (SELECT 1 FROM case_review_events WHERE id=NEW.id OR request_id=NEW.request_id)
 OR NOT EXISTS (SELECT 1 FROM case_publications p JOIN publication_heads h ON h.publication_id=p.id
 JOIN investigations i ON i.id=p.investigation_id
 WHERE p.id=NEW.publication_id AND p.state='prepared' AND p.target=NEW.target
 AND p.payload_sha256=sha256_text(p.payload_json)
 AND p.payload_sha256=NEW.payload_sha256 AND NEW.report_sha256=sha256_text(i.report_json)
 AND instr(json_extract(p.payload_json,'$.description'),'Case rendering format: ' || NEW.renderer_version || char(10))=1)
 OR NEW.previous_event_id IS NOT (SELECT id FROM case_review_events WHERE publication_id=NEW.publication_id ORDER BY id DESC LIMIT 1)
 OR (NEW.previous_event_id IS NULL AND NEW.decision='revoked')
 OR (NEW.previous_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM case_review_events r
 WHERE r.id=NEW.previous_event_id AND julianday(NEW.decided_at)>=julianday(r.decided_at)
 AND ((r.decision='approved' AND NEW.decision='revoked') OR (r.decision IN ('declined','revoked') AND NEW.decision IN ('approved','declined')))))
BEGIN SELECT RAISE(ABORT,'invalid review transition or binding'); END;
CREATE TRIGGER publication_approval_guard BEFORE UPDATE ON case_publications
WHEN OLD.state='prepared' AND NEW.state='sending' AND NOT EXISTS (
 SELECT 1 FROM case_review_events r JOIN investigations i ON i.id=OLD.investigation_id
 WHERE r.id=(SELECT max(id) FROM case_review_events WHERE publication_id=OLD.id)
 AND r.decision='approved' AND r.payload_sha256=OLD.payload_sha256 AND r.target=OLD.target
 AND r.report_sha256=sha256_text(i.report_json)
 AND OLD.payload_sha256=sha256_text(OLD.payload_json)
 AND instr(json_extract(OLD.payload_json,'$.description'),
 'Case rendering format: ' || r.renderer_version || char(10))=1)
BEGIN SELECT RAISE(ABORT,'current durable approval required'); END;
CREATE TRIGGER publication_head_insert BEFORE INSERT ON publication_heads
WHEN NOT EXISTS (SELECT 1 FROM case_publications WHERE id=NEW.publication_id
 AND investigation_id=NEW.investigation_id AND target=NEW.target)
BEGIN SELECT RAISE(ABORT,'publication head mismatch'); END;
CREATE TRIGGER preparation_no_delete BEFORE DELETE ON case_preparation_jobs
BEGIN SELECT RAISE(ABORT,'immutable record'); END;
CREATE TRIGGER preparation_audit_no_update BEFORE UPDATE ON case_preparation_audit
BEGIN SELECT RAISE(ABORT,'immutable record'); END;
CREATE TRIGGER preparation_audit_no_delete BEFORE DELETE ON case_preparation_audit
BEGIN SELECT RAISE(ABORT,'immutable record'); END;
CREATE TRIGGER review_no_update BEFORE UPDATE ON case_review_events
BEGIN SELECT RAISE(ABORT,'immutable record'); END;
CREATE TRIGGER review_no_delete BEFORE DELETE ON case_review_events
BEGIN SELECT RAISE(ABORT,'immutable record'); END;
-- AFTER INSERT sees the allocated rowid (BEFORE INSERT sees -1 for automatic IDs).
CREATE TRIGGER review_sequence AFTER INSERT ON case_review_events
WHEN NEW.id<=0 OR NEW.id!=(SELECT max(id) FROM case_review_events)
 OR (NEW.previous_event_id IS NOT NULL AND NEW.id<=NEW.previous_event_id)
BEGIN SELECT RAISE(ABORT,'invalid review sequence'); END;
