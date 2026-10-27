ALTER TABLE investigation_jobs ADD COLUMN investigation_id TEXT REFERENCES investigations(id);
CREATE TRIGGER investigation_job_report_initial BEFORE INSERT ON investigation_jobs
WHEN NEW.investigation_id IS NOT NULL
BEGIN SELECT RAISE(ABORT,'invalid initial job report'); END;
CREATE TRIGGER investigation_job_report_guard BEFORE UPDATE ON investigation_jobs
WHEN (OLD.investigation_id IS NOT NULL AND NEW.investigation_id IS NOT OLD.investigation_id)
 OR (NEW.investigation_id IS NOT NULL AND (
 NEW.state NOT IN ('completed','failed') OR NOT EXISTS (
 SELECT 1 FROM investigations WHERE id=NEW.investigation_id
 AND request_fingerprint=NEW.request_fingerprint
 AND json_extract(report_json,'$.engine_version')=NEW.engine_version
 AND json_extract(report_json,'$.source_alert_ids')=NEW.selection_json
 AND (NEW.state!='completed' OR json_extract(report_json,'$.status')='completed'))))
 OR (NEW.state='completed' AND NEW.investigation_id IS NULL)
BEGIN SELECT RAISE(ABORT,'invalid investigation job report'); END;
