-- Empty until explicit trusted installation; migration never invents policy authority.
CREATE TABLE review_policy_generations (
 generation INTEGER PRIMARY KEY CHECK(generation>0),
 version TEXT NOT NULL UNIQUE,
 content TEXT NOT NULL,
 content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
 installed_at TEXT NOT NULL
);
CREATE TRIGGER policy_generation_insert BEFORE INSERT ON review_policy_generations
WHEN NEW.generation != (SELECT coalesce(max(generation),0)+1 FROM review_policy_generations)
 OR EXISTS (SELECT 1 FROM review_policy_generations WHERE version=NEW.version)
 OR NEW.content_sha256 != sha256_text(NEW.content)
BEGIN SELECT RAISE(ABORT,'invalid policy generation'); END;
CREATE TRIGGER policy_generation_no_update BEFORE UPDATE ON review_policy_generations
BEGIN SELECT RAISE(ABORT,'immutable policy generation'); END;
CREATE TRIGGER policy_generation_no_delete BEFORE DELETE ON review_policy_generations
BEGIN SELECT RAISE(ABORT,'immutable policy generation'); END;
