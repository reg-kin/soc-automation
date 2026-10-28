-- Independent lanes partition the append-only persistence audit at initialization.
CREATE TABLE case_preparation_discovery (
 target TEXT NOT NULL CHECK(canonical_case_target(target)),
 renderer_version TEXT NOT NULL CHECK(length(trim(renderer_version))>0),
 historical_high_water INTEGER NOT NULL CHECK(typeof(historical_high_water)='integer' AND historical_high_water>=0),
 historical_cursor INTEGER NOT NULL DEFAULT 0 CHECK(typeof(historical_cursor)='integer' AND historical_cursor BETWEEN 0 AND historical_high_water),
 live_cursor INTEGER NOT NULL CHECK(typeof(live_cursor)='integer' AND live_cursor>=historical_high_water),
 revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision)='integer' AND revision>=0),
 PRIMARY KEY(target,renderer_version)
);
CREATE TRIGGER discovery_transition BEFORE UPDATE ON case_preparation_discovery
WHEN NEW.target IS NOT OLD.target OR NEW.renderer_version IS NOT OLD.renderer_version
 OR NEW.historical_high_water IS NOT OLD.historical_high_water
 OR NEW.revision!=OLD.revision+1
 OR NEW.historical_cursor<OLD.historical_cursor OR NEW.live_cursor<OLD.live_cursor
 OR (NEW.historical_cursor!=OLD.historical_cursor AND NEW.live_cursor!=OLD.live_cursor)
BEGIN SELECT RAISE(ABORT,'invalid discovery transition'); END;
CREATE TRIGGER discovery_no_delete BEFORE DELETE ON case_preparation_discovery
BEGIN SELECT RAISE(ABORT,'immutable discovery checkpoint'); END;
