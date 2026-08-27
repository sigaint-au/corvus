-- 0017: Team- and project-level metadata with precedence (team > project > secret).
-- Keys defined higher in the hierarchy cannot be overridden lower down.

CREATE TABLE IF NOT EXISTS api.team_meta (
    team_id    uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    value      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, key)
);

CREATE TABLE IF NOT EXISTS api.project_meta (
    project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    value      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, key)
);

-- Guard: reject writes of a key that already exists higher in the hierarchy.
CREATE OR REPLACE FUNCTION private.guard_meta_precedence() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private
AS $fn$
DECLARE
    v_team_id    uuid;
    v_project_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'team_meta' THEN
        RETURN NEW;
    ELSIF TG_TABLE_NAME = 'project_meta' THEN
        SELECT team_id INTO v_team_id FROM api.projects WHERE id = NEW.project_id;
        IF EXISTS (SELECT 1 FROM api.team_meta WHERE team_id = v_team_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at team level and cannot be overridden', NEW.key;
        END IF;
        RETURN NEW;
    ELSE  -- secret_meta
        SELECT project_id INTO v_project_id FROM api.secrets WHERE id = NEW.secret_id;
        SELECT team_id    INTO v_team_id    FROM api.projects WHERE id = v_project_id;
        IF EXISTS (SELECT 1 FROM api.team_meta WHERE team_id = v_team_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at team level and cannot be overridden', NEW.key;
        END IF;
        IF EXISTS (SELECT 1 FROM api.project_meta WHERE project_id = v_project_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at project level and cannot be overridden', NEW.key;
        END IF;
        RETURN NEW;
    END IF;
END;
$fn$;

DROP TRIGGER IF EXISTS team_meta_guard ON api.team_meta;
CREATE TRIGGER team_meta_guard BEFORE INSERT OR UPDATE ON api.team_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

DROP TRIGGER IF EXISTS project_meta_guard ON api.project_meta;
CREATE TRIGGER project_meta_guard BEFORE INSERT OR UPDATE ON api.project_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

DROP TRIGGER IF EXISTS secret_meta_guard ON api.secret_meta;
CREATE TRIGGER secret_meta_guard BEFORE INSERT OR UPDATE ON api.secret_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

-- RLS: read for anyone with visibility, write for admins only.
ALTER TABLE api.team_meta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS team_meta_select ON api.team_meta;
CREATE POLICY team_meta_select ON api.team_meta FOR SELECT TO authenticated
    USING (api.team_role(team_id) IS NOT NULL);
DROP POLICY IF EXISTS team_meta_admin ON api.team_meta;
CREATE POLICY team_meta_admin ON api.team_meta FOR ALL TO authenticated
    USING (api.team_role(team_id) IN ('team-owner', 'team-admin'))
    WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));

ALTER TABLE api.project_meta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_meta_select ON api.project_meta;
CREATE POLICY project_meta_select ON api.project_meta FOR SELECT TO authenticated
    USING (api.can_read_project(project_id));
DROP POLICY IF EXISTS project_meta_admin ON api.project_meta;
CREATE POLICY project_meta_admin ON api.project_meta FOR ALL TO authenticated
    USING (api.can_admin_project(project_id))
    WITH CHECK (api.can_admin_project(project_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_meta, api.project_meta TO authenticated;
GRANT EXECUTE ON FUNCTION private.guard_meta_precedence() TO authenticator, authenticated;

-- Merged read view for secrets: inherited metadata flows down.
-- Precedence on key collision: team > project > secret. Adds a source column.
-- CREATE OR REPLACE cannot change OUT/TABLE columns; drop the 0001 signature first.
DROP FUNCTION IF EXISTS private.secret_meta_rows(uuid);
CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)
RETURNS TABLE(key text, value text, updated_at timestamptz, source text)
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = api, private
AS $fn$
WITH scope AS (
    SELECT s.project_id AS project_id, p.team_id AS team_id
    FROM api.secrets s
    JOIN api.projects p ON p.id = s.project_id
    WHERE s.id = p_secret
),
own AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.secret_meta m
    WHERE m.secret_id = p_secret
),
pm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.project_meta m
    JOIN scope ON scope.project_id = m.project_id
),
tm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.team_meta m
    JOIN scope ON scope.team_id = m.team_id
),
merged AS (
    SELECT key, value, updated_at, 'team' AS source FROM tm
    UNION ALL
    SELECT key, value, updated_at, 'project' AS source FROM pm
    UNION ALL
    SELECT key, value, updated_at, 'secret' AS source FROM own
)
SELECT DISTINCT ON (key) key, value, updated_at, source
FROM merged
WHERE api.can_access_secret(p_secret, 'read')
ORDER BY key, source = 'secret', source = 'project'
$fn$;

GRANT EXECUTE ON FUNCTION private.secret_meta_rows TO authenticator, authenticated;
