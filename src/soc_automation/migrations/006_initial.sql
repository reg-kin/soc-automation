CREATE TABLE investigation_jobs (
 id TEXT PRIMARY KEY,
 request_fingerprint TEXT NOT NULL UNIQUE,
 engine_version TEXT NOT NULL,
 selection_json TEXT NOT NULL CHECK(json_valid(selection_json) AND json_array_length(selection_json)=1),
 priority TEXT NOT NULL CHECK(priority IN ('P1','P2','P3','P4')),
 created_at REAL NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','retry_wait','completed','failed')),
 available_at REAL NOT NULL,
 max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
 attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND max_attempts),
 lease_generation INTEGER NOT NULL DEFAULT 0 CHECK(lease_generation>=0),
 lease_owner TEXT,
 lease_until REAL,
 failure_code TEXT CHECK(failure_code IN ('transient','permanent','lease_expired','engine_mismatch')),
 CHECK(lease_generation=attempt_count),
 CHECK(state NOT IN ('queued','leased') OR failure_code IS NULL),
 CHECK(state='queued' OR attempt_count>0),
 CHECK(state!='failed' OR (failure_code IS NOT NULL AND
  (failure_code IN ('permanent','engine_mismatch') OR attempt_count=max_attempts))),
 CHECK(state!='completed' OR failure_code IS NULL),
 CHECK(state!='retry_wait' OR (attempt_count<max_attempts AND failure_code IS NOT NULL AND failure_code IN ('transient','lease_expired'))),
 CHECK((state='leased' AND lease_owner IS NOT NULL AND length(lease_owner)>0 AND lease_until IS NOT NULL)
 OR (state!='leased' AND lease_owner IS NULL AND lease_until IS NULL))
);
CREATE INDEX investigation_jobs_ready ON investigation_jobs(state,available_at,priority,created_at,id);
CREATE TABLE investigation_job_alerts (
 job_id TEXT PRIMARY KEY REFERENCES investigation_jobs(id),
 alert_id TEXT NOT NULL UNIQUE REFERENCES ingested_alerts(alert_id)
);
CREATE TABLE investigation_job_attempts (
 job_id TEXT NOT NULL REFERENCES investigation_jobs(id),
 generation INTEGER NOT NULL CHECK(generation>0),
 owner TEXT NOT NULL CHECK(length(trim(owner))>0),
 started_at REAL NOT NULL,
 finished_at REAL,
 outcome TEXT CHECK(outcome IN ('completed','transient','permanent','lease_expired','engine_mismatch')),
 PRIMARY KEY(job_id,generation),
 CHECK(finished_at IS NULL OR finished_at>=started_at),
 CHECK((finished_at IS NULL AND outcome IS NULL) OR (finished_at IS NOT NULL AND outcome IS NOT NULL))
);
CREATE TABLE investigation_coordination_audit (
 id INTEGER PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES investigation_jobs(id),
 event TEXT NOT NULL CHECK(event IN ('enqueued','claimed','renewed','retry_wait','completed','failed')),
 generation INTEGER NOT NULL,
 owner TEXT,
 occurred_at REAL NOT NULL
);
CREATE TRIGGER investigation_job_identity BEFORE UPDATE ON investigation_jobs
WHEN NEW.id IS NOT OLD.id OR NEW.request_fingerprint IS NOT OLD.request_fingerprint
 OR NEW.engine_version IS NOT OLD.engine_version OR NEW.selection_json IS NOT OLD.selection_json
 OR NEW.priority IS NOT OLD.priority OR NEW.created_at IS NOT OLD.created_at
 OR NEW.max_attempts IS NOT OLD.max_attempts
BEGIN SELECT RAISE(ABORT,'immutable job identity'); END;
CREATE TRIGGER investigation_job_transition BEFORE UPDATE ON investigation_jobs
WHEN NOT (
 (OLD.state IN ('queued','retry_wait') AND NEW.state='leased'
  AND NEW.lease_generation=OLD.lease_generation+1 AND NEW.attempt_count=OLD.attempt_count+1)
 OR (OLD.state='leased' AND NEW.state='leased' AND NEW.lease_owner=OLD.lease_owner
  AND NEW.lease_generation=OLD.lease_generation AND NEW.attempt_count=OLD.attempt_count
  AND NEW.lease_until>OLD.lease_until)
 OR (OLD.state='leased' AND NEW.state IN ('completed','failed','retry_wait')
  AND NEW.lease_generation=OLD.lease_generation AND NEW.attempt_count=OLD.attempt_count))
BEGIN SELECT RAISE(ABORT,'invalid job transition'); END;
CREATE TRIGGER investigation_job_initial BEFORE INSERT ON investigation_jobs
WHEN NEW.state!='queued' OR NEW.attempt_count!=0 OR NEW.lease_generation!=0
BEGIN SELECT RAISE(ABORT,'invalid initial job'); END;
CREATE TRIGGER investigation_job_no_delete BEFORE DELETE ON investigation_jobs
BEGIN SELECT RAISE(ABORT,'immutable job'); END;
CREATE TRIGGER investigation_membership_guard BEFORE INSERT ON investigation_job_alerts
WHEN NOT EXISTS (SELECT 1 FROM investigation_jobs WHERE id=NEW.job_id
 AND json_extract(selection_json,'$[0]')=NEW.alert_id)
BEGIN SELECT RAISE(ABORT,'selection mismatch'); END;
CREATE TRIGGER investigation_membership_no_update BEFORE UPDATE ON investigation_job_alerts
BEGIN SELECT RAISE(ABORT,'immutable membership'); END;
CREATE TRIGGER investigation_membership_no_delete BEFORE DELETE ON investigation_job_alerts
BEGIN SELECT RAISE(ABORT,'immutable membership'); END;
CREATE TRIGGER investigation_attempt_guard BEFORE UPDATE ON investigation_job_attempts
WHEN OLD.finished_at IS NOT NULL OR NEW.job_id IS NOT OLD.job_id
 OR NEW.generation IS NOT OLD.generation OR NEW.owner IS NOT OLD.owner
 OR NEW.started_at IS NOT OLD.started_at OR NEW.finished_at IS NULL
 OR NOT EXISTS (SELECT 1 FROM investigation_jobs WHERE id=OLD.job_id
  AND state='leased' AND lease_generation=OLD.generation AND lease_owner=OLD.owner
  AND ((lease_until>coordination_now() AND NEW.outcome!='lease_expired')
   OR (lease_until<=coordination_now() AND NEW.outcome='lease_expired')))
BEGIN SELECT RAISE(ABORT,'immutable attempt'); END;
CREATE TRIGGER investigation_attempt_no_delete BEFORE DELETE ON investigation_job_attempts
BEGIN SELECT RAISE(ABORT,'immutable attempt'); END;
CREATE TRIGGER investigation_coordination_no_update BEFORE UPDATE ON investigation_coordination_audit
BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER investigation_coordination_no_delete BEFORE DELETE ON investigation_coordination_audit
BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER investigation_job_lease_time BEFORE UPDATE ON investigation_jobs
WHEN (OLD.state='leased' AND NOT (
 (OLD.lease_until>coordination_now() AND NEW.failure_code IS NOT 'lease_expired')
 OR (OLD.lease_until<=coordination_now() AND NEW.state IN ('retry_wait','failed')
 AND NEW.failure_code IS 'lease_expired')))
 OR (NEW.state='leased' AND NEW.lease_until<=coordination_now())
 OR (OLD.state IN ('queued','retry_wait') AND OLD.available_at>coordination_now())
BEGIN SELECT RAISE(ABORT,'expired or unavailable lease'); END;

CREATE TRIGGER investigation_attempt_initial BEFORE INSERT ON investigation_job_attempts
WHEN NEW.finished_at IS NOT NULL OR NEW.outcome IS NOT NULL OR NOT EXISTS (
 SELECT 1 FROM investigation_jobs WHERE id=NEW.job_id AND state='leased'
 AND lease_generation=NEW.generation AND lease_owner=NEW.owner)
BEGIN SELECT RAISE(ABORT,'invalid attempt'); END;

CREATE TRIGGER investigation_job_terminal BEFORE UPDATE ON investigation_jobs
WHEN NEW.state IN ('completed','failed','retry_wait') AND (
 NOT EXISTS (SELECT 1 FROM investigation_job_attempts WHERE job_id=OLD.id
  AND generation=OLD.lease_generation AND owner=OLD.lease_owner
  AND finished_at IS NOT NULL AND outcome=coalesce(NEW.failure_code,'completed'))
 OR (NEW.state='completed' AND NOT EXISTS (
  SELECT 1 FROM investigations WHERE request_fingerprint=NEW.request_fingerprint)))
BEGIN SELECT RAISE(ABORT,'missing attempt outcome or investigation report'); END;
