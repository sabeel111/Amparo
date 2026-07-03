-- 002_unique_org_name.sql — fix: organization.name needs a unique constraint
-- for EnsureProject's ON CONFLICT to work. Without it, every EnsureProject call
-- created a duplicate org (and thus a duplicate project), breaking finding
-- lookup by project name.

-- Deduplicate existing org rows first: collapse duplicates into the min(id),
-- re-pointing projects and findings. (Best-effort for dev data.)
UPDATE project SET org_id = (
    SELECT min(id) FROM organization o2 WHERE o2.name = (SELECT name FROM organization WHERE id = project.org_id)
);

DELETE FROM organization o1 USING organization o2
WHERE o1.name = o2.name AND o1.id > o2.id;

ALTER TABLE organization ADD CONSTRAINT organization_name_unique UNIQUE (name);
