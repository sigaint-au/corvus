-- Folders: hierarchical key prefixes for secrets within a project.
--
-- A folder is a container whose `path` is a key prefix. Secrets in a folder
-- have `key = folder.path || '/' || leaf`. Both a secret `prod` and a folder
-- `prod` can coexist (S3-style).
--
-- Idempotent with IF NOT EXISTS / DO $$ blocks. Additive only — do not edit
-- 0001_init.sql (squashed baseline, checksum-protected).
--
-- Org audit actions emitted by this feature (via private.audit_org):
--   folder_created, folder_deleted, folder_moved
-- The org-audit webhook trigger maps these to org.folder_* events automatically.

-- ── api.folders ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api.folders (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  parent_id  uuid REFERENCES api.folders(id) ON DELETE CASCADE,
  name       text NOT NULL
               CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$'
                  AND name NOT IN ('.', '..')),
  path       text NOT NULL
               CHECK (path ~ '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,15}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  UNIQUE (project_id, path),
  CHECK (
    (parent_id IS NULL AND path = name)
    OR (parent_id IS NOT NULL AND path LIKE '%/' || name)
  )
);
CREATE INDEX IF NOT EXISTS folders_project_parent_idx
  ON api.folders (project_id, parent_id);

-- ── api.secrets.folder_id ───────────────────────────────────────────────
ALTER TABLE api.secrets
  ADD COLUMN IF NOT EXISTS folder_id uuid
    REFERENCES api.folders(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS secrets_folder_idx
  ON api.secrets (folder_id) WHERE deleted_at IS NULL;

-- ── RLS on api.folders ──────────────────────────────────────────────────
ALTER TABLE api.folders FORCE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'folders' AND policyname = 'folders_select'
  ) THEN
    CREATE POLICY folders_select ON api.folders FOR SELECT
      USING (api.can_read_project(project_id));
    CREATE POLICY folders_insert ON api.folders FOR INSERT
      WITH CHECK (api.can_write_project(project_id));
    CREATE POLICY folders_update ON api.folders FOR UPDATE
      USING (api.can_write_project(project_id))
      WITH CHECK (api.can_write_project(project_id));
    CREATE POLICY folders_delete ON api.folders FOR DELETE
      USING (api.can_write_project(project_id));
  END IF;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON api.folders TO authenticated;

-- ── private.ensure_folder_path ──────────────────────────────────────────
-- SECURITY DEFINER, row_security = off. Creates ancestor folders for a path.
-- Returns the leaf folder id (NULL for empty path).
CREATE OR REPLACE FUNCTION private.ensure_folder_path(
  p_project uuid,
  p_path    text,
  p_actor   uuid DEFAULT NULL
) RETURNS uuid
  LANGUAGE plpgsql STRICT
  SECURITY DEFINER
  SET row_security = off
AS $$
DECLARE
  segs       text[];
  cur_path   text;
  par_id     uuid;
  leaf_id    uuid;
  i          int;
BEGIN
  IF p_path IS NULL OR p_path = '' THEN
    RETURN NULL;
  END IF;
  -- Normalize: strip leading/trailing slashes, reject illegal
  segs := string_to_array(trim(BOTH '/' FROM p_path), '/');
  IF array_length(segs, 1) IS NULL OR array_length(segs, 1) > 16 THEN
    RAISE EXCEPTION 'folder path must have 1-16 segments, got %',
      COALESCE(array_length(segs, 1)::text, '0');
  END IF;
  FOREACH cur_path IN ARRAY segs LOOP
    IF cur_path = '' OR cur_path = '.' OR cur_path = '..' THEN
      RAISE EXCEPTION 'invalid segment "%" in folder path', cur_path;
    END IF;
  END LOOP;
  par_id := NULL;
  leaf_id := NULL;
  FOR i IN 1 .. array_length(segs, 1) LOOP
    cur_path := array_to_string(segs[1:i], '/');
    INSERT INTO api.folders (project_id, parent_id, name, path, created_by)
    VALUES (p_project, par_id, segs[i], cur_path, p_actor)
    ON CONFLICT (project_id, path) DO UPDATE SET
      updated_at = now()
    RETURNING id INTO leaf_id;
    par_id := leaf_id;
  END LOOP;
  RETURN leaf_id;
END;
$$;

GRANT EXECUTE ON FUNCTION private.ensure_folder_path(uuid, text, uuid) TO authenticator, authenticated;

-- ── Backfill folder_id for existing secrets with '/' in key ─────────────
DO $$ BEGIN
  -- Only run once: skip if backfill already done for this project
  -- (checked by looking for any non-null folder_id)
  IF NOT EXISTS (
    SELECT 1 FROM api.secrets WHERE folder_id IS NOT NULL LIMIT 1
  ) THEN
    WITH slash_keys AS (
      SELECT id, project_id, key,
             substring(key FROM '^(.+)/[^/]+$') AS folder_path
      FROM api.secrets
      WHERE key LIKE '%/%' AND deleted_at IS NULL
    )
    UPDATE api.secrets s
    SET folder_id = private.ensure_folder_path(
      sk.project_id, sk.folder_path, NULL
    )
    FROM slash_keys sk
    WHERE s.id = sk.id AND sk.folder_path IS NOT NULL;
  END IF;
END $$;

-- ── RBAC: add 'folder' to scope_kind CHECK ──────────────────────────────
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    WHERE t.relname = 'bindings' AND c.conname LIKE '%scope_kind%'
  ) THEN
    ALTER TABLE rbac.bindings DROP CONSTRAINT IF EXISTS bindings_scope_kind_check;
    ALTER TABLE rbac.bindings ADD CONSTRAINT bindings_scope_kind_check
      CHECK (scope_kind IN ('cluster', 'team', 'project', 'secret', 'folder'));
  END IF;
END $$;

-- ── validate_binding_scope: allow secret-% at folder scope ──────────────
CREATE OR REPLACE FUNCTION rbac.validate_binding_scope()
  RETURNS trigger
  LANGUAGE plpgsql
AS $$
DECLARE
  r_name text;
BEGIN
  SELECT r.name INTO r_name FROM rbac.roles r WHERE r.id = NEW.role_id;
  IF r_name IS NULL THEN
    RAISE EXCEPTION 'unknown role_id %', NEW.role_id;
  END IF;
  IF r_name LIKE 'service-%' THEN
    IF NEW.scope_kind NOT IN ('project', 'secret') THEN
      RAISE EXCEPTION 'role % cannot be assigned at scope %', r_name, NEW.scope_kind;
    END IF;
  ELSIF r_name LIKE 'secret-%' THEN
    IF NEW.scope_kind NOT IN ('secret', 'folder') THEN
      RAISE EXCEPTION 'role % cannot be assigned at scope %', r_name, NEW.scope_kind;
    END IF;
  ELSIF r_name LIKE 'project-%' THEN
    IF NEW.scope_kind != 'project' THEN
      RAISE EXCEPTION 'role % cannot be assigned at scope %', r_name, NEW.scope_kind;
    END IF;
  ELSIF r_name LIKE 'team-%' THEN
    IF NEW.scope_kind != 'team' THEN
      RAISE EXCEPTION 'role % cannot be assigned at scope %', r_name, NEW.scope_kind;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- ── rbac_scope_chain: walk folder parents then project → team → cluster ─
CREATE OR REPLACE FUNCTION api.rbac_scope_chain(
  p_scope_kind text,
  p_scope_id   uuid
) RETURNS TABLE(scope_kind text, scope_id uuid)
  LANGUAGE plpgsql STABLE
  SET row_security = off
AS $$
BEGIN
  IF p_scope_kind = 'folder' AND p_scope_id IS NOT NULL THEN
    RETURN QUERY
    WITH RECURSIVE folder_chain AS (
      SELECT f.id, f.parent_id, f.project_id
      FROM api.folders f
      WHERE f.id = p_scope_id
      UNION ALL
      SELECT f.id, f.parent_id, f.project_id
      FROM api.folders f
      JOIN folder_chain fc ON fc.parent_id = f.id
    )
    SELECT 'folder'::text, fc.id FROM folder_chain fc
    UNION ALL
    SELECT 'project'::text, fc.project_id FROM folder_chain fc LIMIT 1
    UNION ALL
    SELECT 'team'::text, p.team_id FROM (
      SELECT fc.project_id FROM folder_chain fc LIMIT 1
    ) fc2 JOIN api.projects p ON p.id = fc2.project_id
    UNION ALL
    SELECT 'cluster'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_scope_kind = 'secret' AND p_scope_id IS NOT NULL THEN
    RETURN QUERY
    SELECT 'secret'::text, s.id FROM api.secrets s WHERE s.id = p_scope_id
    UNION ALL
    SELECT 'folder'::text, s.folder_id FROM api.secrets s WHERE s.id = p_scope_id AND s.folder_id IS NOT NULL
    UNION ALL
    SELECT 'project'::text, s.project_id FROM api.secrets s WHERE s.id = p_scope_id
    UNION ALL
    SELECT 'team'::text, p.team_id FROM api.secrets s JOIN api.projects p ON p.id = s.project_id WHERE s.id = p_scope_id
    UNION ALL
    SELECT 'cluster'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_scope_kind = 'project' AND p_scope_id IS NOT NULL THEN
    RETURN QUERY
    SELECT 'project'::text, p.id FROM api.projects p WHERE p.id = p_scope_id
    UNION ALL
    SELECT 'team'::text, p.team_id FROM api.projects p WHERE p.id = p_scope_id
    UNION ALL
    SELECT 'cluster'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_scope_kind = 'team' AND p_scope_id IS NOT NULL THEN
    RETURN QUERY
    SELECT 'team'::text, t.id FROM api.teams t WHERE t.id = p_scope_id
    UNION ALL
    SELECT 'cluster'::text, NULL::uuid;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'cluster'::text, NULL::uuid;
END;
$$;

-- ── can_manage_rbac for folder scope ────────────────────────────────────
CREATE OR REPLACE FUNCTION api.can_manage_rbac(
  p_scope_kind text,
  p_scope_id   uuid
) RETURNS boolean
  LANGUAGE plpgsql STABLE
  SET row_security = off
AS $$
BEGIN
  IF p_scope_kind = 'folder' AND p_scope_id IS NOT NULL THEN
    RETURN EXISTS (
      SELECT 1 FROM api.folders f
      WHERE f.id = p_scope_id
        AND api.can_admin_project(f.project_id)
    );
  END IF;
  IF p_scope_kind = 'secret' AND p_scope_id IS NOT NULL THEN
    RETURN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = p_scope_id
        AND (
          api.can_admin_project(s.project_id)
          OR (s.created_by = api.current_user_id() AND s.deleted_at IS NULL)
        )
    );
  END IF;
  IF p_scope_kind = 'project' AND p_scope_id IS NOT NULL THEN
    RETURN api.can_admin_project(p_scope_id);
  END IF;
  IF p_scope_kind = 'team' AND p_scope_id IS NOT NULL THEN
    RETURN api.can_admin_project(NULL)
      OR EXISTS (
        SELECT 1 FROM api.teams t
        WHERE t.id = p_scope_id
          AND api.team_role(t.id) IN ('team-owner', 'team-admin')
      );
  END IF;
  IF p_scope_kind = 'cluster' THEN
    RETURN api.is_global_admin();
  END IF;
  RETURN false;
END;
$$;