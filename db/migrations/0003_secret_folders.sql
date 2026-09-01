-- Project-scoped secret folders.  The full secret key remains canonical in
-- api.secrets.key; folder_id is the navigable prefix.
CREATE TABLE IF NOT EXISTS api.folders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  parent_id uuid,
  name text NOT NULL CHECK (name <> '' AND name NOT IN ('.', '..') AND name !~ '[\\\\/]'),
  path text NOT NULL CHECK (path <> '' AND path !~ '(^/|/$|//|[\\\\])'),
  access_mode text NOT NULL DEFAULT 'inherit'
    CHECK (access_mode IN ('inherit', 'restricted')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, id),
  UNIQUE (project_id, path),
  FOREIGN KEY (project_id, parent_id)
    REFERENCES api.folders(project_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS folders_project_parent_idx
  ON api.folders(project_id, parent_id);

ALTER TABLE api.secrets ADD COLUMN IF NOT EXISTS folder_id uuid;
ALTER TABLE api.secrets
  ADD CONSTRAINT secrets_project_folder_fk
  FOREIGN KEY (project_id, folder_id)
  REFERENCES api.folders(project_id, id) ON DELETE RESTRICT;

DROP INDEX IF EXISTS api.secrets_project_key_live;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_key_live
  ON api.secrets (project_id, key)
  WHERE folder_id IS NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_folder_key_live
  ON api.secrets (project_id, folder_id, key)
  WHERE folder_id IS NOT NULL AND deleted_at IS NULL;

ALTER TABLE rbac.bindings DROP CONSTRAINT IF EXISTS bindings_scope_kind_check;
ALTER TABLE rbac.bindings
  ADD CONSTRAINT bindings_scope_kind_check
  CHECK (scope_kind IN ('cluster', 'team', 'project', 'folder', 'secret'));

ALTER TABLE api.folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.folders FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON api.folders TO authenticator, authenticated;

CREATE OR REPLACE FUNCTION api.rbac_scope_chain(
  p_scope_kind text,
  p_scope_id uuid
) RETURNS TABLE(scope_kind text, scope_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, rbac, pg_catalog
SET row_security = off AS $$
DECLARE
  v_project uuid;
  v_team uuid;
  v_folder uuid;
  v_parent uuid;
  v_seen uuid[] := ARRAY[]::uuid[];
BEGIN
  IF p_scope_kind IS NULL THEN
    RETURN;
  END IF;
  IF p_scope_kind = 'cluster' THEN
    scope_kind := 'cluster'; scope_id := NULL; RETURN NEXT;
    RETURN;
  END IF;
  IF p_scope_kind = 'secret' AND p_scope_id IS NOT NULL THEN
    scope_kind := 'secret'; scope_id := p_scope_id; RETURN NEXT;
    SELECT s.project_id, s.folder_id INTO v_project, v_folder
    FROM api.secrets s WHERE s.id = p_scope_id;
    IF v_folder IS NOT NULL THEN
      RETURN QUERY SELECT * FROM api.rbac_scope_chain('folder', v_folder);
      RETURN;
    END IF;
    IF v_project IS NOT NULL THEN
      scope_kind := 'project'; scope_id := v_project; RETURN NEXT;
      SELECT p.team_id INTO v_team FROM api.projects p WHERE p.id = v_project;
      IF v_team IS NOT NULL THEN
        scope_kind := 'team'; scope_id := v_team; RETURN NEXT;
      END IF;
    END IF;
    scope_kind := 'cluster'; scope_id := NULL; RETURN NEXT;
    RETURN;
  END IF;
  IF p_scope_kind = 'folder' AND p_scope_id IS NOT NULL THEN
    v_folder := p_scope_id;
    WHILE v_folder IS NOT NULL AND NOT v_folder = ANY(v_seen) LOOP
      v_seen := array_append(v_seen, v_folder);
      SELECT f.project_id, f.parent_id INTO v_project, v_parent
      FROM api.folders f WHERE f.id = v_folder;
      EXIT WHEN NOT FOUND;
      scope_kind := 'folder'; scope_id := v_folder; RETURN NEXT;
      v_folder := v_parent;
    END LOOP;
    IF v_project IS NOT NULL THEN
      scope_kind := 'project'; scope_id := v_project; RETURN NEXT;
      SELECT p.team_id INTO v_team FROM api.projects p WHERE p.id = v_project;
      IF v_team IS NOT NULL THEN
        scope_kind := 'team'; scope_id := v_team; RETURN NEXT;
      END IF;
    END IF;
    scope_kind := 'cluster'; scope_id := NULL; RETURN NEXT;
    RETURN;
  END IF;
  IF p_scope_kind = 'project' AND p_scope_id IS NOT NULL THEN
    scope_kind := 'project'; scope_id := p_scope_id; RETURN NEXT;
    SELECT p.team_id INTO v_team FROM api.projects p WHERE p.id = p_scope_id;
    IF v_team IS NOT NULL THEN
      scope_kind := 'team'; scope_id := v_team; RETURN NEXT;
    END IF;
    scope_kind := 'cluster'; scope_id := NULL; RETURN NEXT;
    RETURN;
  END IF;
  IF p_scope_kind = 'team' AND p_scope_id IS NOT NULL THEN
    scope_kind := 'team'; scope_id := p_scope_id; RETURN NEXT;
    scope_kind := 'cluster'; scope_id := NULL; RETURN NEXT;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION api.rbac_folder_binding_allows(
  p_folder_id uuid,
  p_need text,
  p_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
  SELECT EXISTS (
    SELECT 1
    FROM api.rbac_subjects(COALESCE(p_subject, api.current_user_id())) sub
    JOIN rbac.bindings b
      ON b.subject_kind = sub.subject_kind AND b.subject_id = sub.subject_id
    JOIN rbac.role_rules rr ON rr.role_id = b.role_id
    WHERE b.scope_kind = 'folder'
      AND b.scope_id IN (
        SELECT c.scope_id FROM api.rbac_scope_chain('folder', p_folder_id) c
        WHERE c.scope_kind = 'folder'
      )
      AND CASE lower(COALESCE(p_need, ''))
        WHEN 'write' THEN
          api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'create')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
        WHEN 'reveal' THEN
          api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
        ELSE
          api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'get')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'list')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
      END
  );
$$;

CREATE OR REPLACE FUNCTION api.rbac_secret_binding_allows(
  p_sid uuid,
  p_need text,
  p_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
  SELECT EXISTS (
    SELECT 1
    FROM api.secrets s
    JOIN api.rbac_subjects(COALESCE(p_subject, api.current_user_id())) sub ON true
    JOIN rbac.bindings b
      ON b.subject_kind = sub.subject_kind AND b.subject_id = sub.subject_id
    JOIN rbac.role_rules rr ON rr.role_id = b.role_id
    WHERE s.id = p_sid
      AND (
        (b.scope_kind = 'secret' AND b.scope_id = p_sid)
        OR (b.scope_kind = 'folder' AND b.scope_id IN (
          SELECT c.scope_id FROM api.rbac_scope_chain('folder', s.folder_id) c
          WHERE c.scope_kind = 'folder'
        ))
      )
      AND CASE lower(COALESCE(p_need, ''))
        WHEN 'write' THEN
          api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'create')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
        WHEN 'reveal' THEN
          api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
        ELSE
          api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'get')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'list')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
          OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
      END
  );
$$;

CREATE OR REPLACE FUNCTION api.can_access_folder(
  p_folder_id uuid,
  p_need text DEFAULT 'read'
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
  SELECT COALESCE((
    SELECT CASE
      WHEN api.can_admin_project(f.project_id) THEN true
      WHEN f.access_mode = 'restricted' THEN api.rbac_folder_binding_allows(f.id, p_need)
      WHEN p_need = 'write' THEN (
        api.can('update', 'secrets', 'folder', f.id)
        OR api.can('create', 'secrets', 'folder', f.id)
        OR api.can('admin', 'secrets', 'folder', f.id)
        OR api.can('*', '*', 'folder', f.id)
      )
      ELSE (
        api.can('get', 'secrets', 'folder', f.id)
        OR api.can('list', 'secrets', 'folder', f.id)
        OR api.can('reveal', 'secrets', 'folder', f.id)
        OR api.can('update', 'secrets', 'folder', f.id)
        OR api.can('admin', 'secrets', 'folder', f.id)
        OR api.can('*', '*', 'folder', f.id)
      )
    END
    FROM api.folders f WHERE f.id = p_folder_id
  ), false);
$$;

GRANT EXECUTE ON FUNCTION api.rbac_folder_binding_allows TO authenticator, authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_access_folder TO authenticator, authenticated, anon;

CREATE OR REPLACE FUNCTION api.can_access_secret_row(
  sid uuid,
  pid uuid,
  mode text,
  need text DEFAULT 'read',
  deleted_at timestamptz DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL OR pid IS NULL THEN false
    WHEN deleted_at IS NOT NULL THEN false
    WHEN need IS NULL OR need NOT IN ('read', 'reveal', 'write') THEN false
    WHEN api.can_admin_project(pid) THEN true
    WHEN COALESCE(mode, 'inherit') = 'restricted' THEN api.rbac_secret_binding_allows(sid, need)
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s JOIN api.folders f ON f.id = s.folder_id
      WHERE s.id = sid AND f.access_mode = 'restricted'
    ) THEN api.rbac_secret_binding_allows(sid, need)
    WHEN need = 'write' THEN (
      api.can('update', 'secrets', 'secret', sid)
      OR api.can('create', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
    WHEN need = 'reveal' THEN (
      api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
    ELSE (
      api.can('get', 'secrets', 'secret', sid)
      OR api.can('list', 'secrets', 'secret', sid)
      OR api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('update', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
  END;
$$;

DROP POLICY IF EXISTS folders_select ON api.folders;
CREATE POLICY folders_select ON api.folders FOR SELECT TO authenticated
USING (api.can_access_folder(id, 'read'));
DROP POLICY IF EXISTS folders_insert ON api.folders;
CREATE POLICY folders_insert ON api.folders FOR INSERT TO authenticated
WITH CHECK (api.can_write_project(project_id));
DROP POLICY IF EXISTS folders_update ON api.folders;
CREATE POLICY folders_update ON api.folders FOR UPDATE TO authenticated
USING (api.can_write_project(project_id))
WITH CHECK (api.can_write_project(project_id));
DROP POLICY IF EXISTS folders_delete ON api.folders;
CREATE POLICY folders_delete ON api.folders FOR DELETE TO authenticated
USING (api.can_admin_project(project_id));

CREATE OR REPLACE FUNCTION rbac.validate_binding_scope()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
DECLARE role_name text;
DECLARE invoker text := session_user;
BEGIN
  IF NEW.scope_kind NOT IN ('cluster', 'team', 'project', 'folder', 'secret') THEN
    RAISE EXCEPTION 'invalid binding scope';
  END IF;
  IF (NEW.scope_kind = 'cluster') IS DISTINCT FROM (NEW.scope_id IS NULL) THEN
    RAISE EXCEPTION 'cluster bindings require a null scope_id';
  END IF;
  IF NEW.scope_kind <> 'cluster' AND NEW.scope_id IS NULL THEN
    RAISE EXCEPTION 'non-cluster bindings require a scope_id';
  END IF;
  SELECT name INTO role_name FROM rbac.roles WHERE id = NEW.role_id;
  IF role_name IS NULL THEN
    RAISE EXCEPTION 'binding role does not exist';
  END IF;
  IF (
    (role_name LIKE 'team-%' AND NEW.scope_kind <> 'team') OR
    (role_name LIKE 'project-%' AND NEW.scope_kind <> 'project') OR
    (role_name LIKE 'secret-%' AND NEW.scope_kind NOT IN ('folder', 'secret')) OR
    (role_name LIKE 'service-%' AND NEW.scope_kind NOT IN ('project', 'folder', 'secret')) OR
    (role_name IN ('global-admin', 'audit-viewer') AND NEW.scope_kind <> 'cluster') OR
    (role_name NOT LIKE 'team-%' AND role_name NOT LIKE 'project-%'
     AND role_name NOT LIKE 'secret-%' AND role_name NOT LIKE 'service-%'
     AND role_name NOT IN ('global-admin', 'audit-viewer')
     AND NEW.scope_kind = 'cluster')
  ) THEN
    RAISE EXCEPTION 'role % cannot be assigned at scope %', role_name, NEW.scope_kind;
  END IF;
  IF NEW.scope_kind = 'folder' AND NOT EXISTS (
    SELECT 1 FROM api.folders WHERE id = NEW.scope_id
  ) THEN
    RAISE EXCEPTION 'binding folder does not exist';
  END IF;
  IF role_name = 'team-owner' AND NEW.scope_kind = 'team' THEN
    IF invoker IN ('authenticator', 'authenticated', 'anon') THEN
      IF NOT api.is_global_admin()
         AND api.team_role(NEW.scope_id) IS DISTINCT FROM 'team-owner'
         AND EXISTS (
           SELECT 1 FROM rbac.bindings b
           JOIN rbac.roles r ON r.id = b.role_id
           WHERE b.scope_kind = 'team' AND b.scope_id = NEW.scope_id
             AND r.name = 'team-owner'
             AND (TG_OP = 'INSERT' OR b.id IS DISTINCT FROM NEW.id)
         ) THEN
        RAISE EXCEPTION 'only a team owner can assign team-owner';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS validate_binding_scope ON rbac.bindings;
CREATE TRIGGER validate_binding_scope
BEFORE INSERT OR UPDATE ON rbac.bindings
FOR EACH ROW EXECUTE FUNCTION rbac.validate_binding_scope();
