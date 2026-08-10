-- Kubernetes-style RBAC (Subjects + Roles + RoleBindings)
-- Applied by ensure_schema() and on fresh volumes after init.sql.
-- Start-fresh: no migration from team_members / project_members / secret_acl.

CREATE SCHEMA IF NOT EXISTS rbac;
GRANT USAGE ON SCHEMA rbac TO authenticator, authenticated, anon;

-- ── Roles ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rbac.roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  built_in boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One PolicyRule per row (k8s-style): resources[] × verbs[]
CREATE TABLE IF NOT EXISTS rbac.role_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
  resources text[] NOT NULL,
  verbs text[] NOT NULL,
  CHECK (cardinality(resources) >= 1),
  CHECK (cardinality(verbs) >= 1)
);
CREATE INDEX IF NOT EXISTS role_rules_role_idx ON rbac.role_rules(role_id);

-- ── RoleBindings ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rbac.bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
  subject_kind text NOT NULL
    CHECK (subject_kind IN ('User', 'Group', 'ServiceAccount')),
  subject_id uuid NOT NULL,
  -- cluster | team | project | secret
  scope_kind text NOT NULL
    CHECK (scope_kind IN ('cluster', 'team', 'project', 'secret')),
  scope_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid,
  CHECK (
    (scope_kind = 'cluster' AND scope_id IS NULL)
    OR (scope_kind <> 'cluster' AND scope_id IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS bindings_subject_idx
  ON rbac.bindings(subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS bindings_scope_idx
  ON rbac.bindings(scope_kind, scope_id);
CREATE INDEX IF NOT EXISTS bindings_role_idx ON rbac.bindings(role_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON rbac.roles TO authenticator, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON rbac.role_rules TO authenticator, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON rbac.bindings TO authenticator, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA rbac TO authenticator;

ALTER TABLE rbac.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac.roles FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac.role_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac.role_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac.bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac.bindings FORCE ROW LEVEL SECURITY;

-- Policies recreated after can() exists (see bottom)

-- ── Seed built-in roles (idempotent by name) ─────────────────────────
CREATE OR REPLACE FUNCTION rbac.ensure_builtin_roles() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = rbac, pg_catalog
SET row_security = off AS $$
DECLARE
  rid uuid;
BEGIN
  -- helper: upsert role + replace rules
  -- cluster-admin
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('cluster-admin', 'Full access to all resources at every scope', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['*'], ARRAY['*']);

  -- audit-viewer
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('audit-viewer', 'Read audit logs', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['audit'], ARRAY['get', 'list']);

  -- team-owner
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-owner', 'Full control of a team and its projects/secrets', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['*'], ARRAY['*']);

  -- team-admin
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-admin', 'Administer team projects and members (not ownership transfer)', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['teams', 'projects', 'secrets', 'bindings', 'groups', 'machine_tokens', 'audit'],
         ARRAY['get', 'list', 'create', 'update', 'delete', 'reveal', 'admin']);

  -- team-member
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-member', 'Read projects; create/update secrets in team projects', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets', 'machine_tokens'], ARRAY['get', 'list', 'create', 'update', 'reveal']);

  -- team-viewer
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-viewer', 'Read-only access to team projects and secret metadata', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets'], ARRAY['get', 'list']);

  -- project-admin
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('project-admin', 'Full admin of a single project', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets', 'bindings', 'machine_tokens', 'audit'],
         ARRAY['get', 'list', 'create', 'update', 'delete', 'reveal', 'admin']);

  -- project-write
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('project-write', 'Create and update secrets in a project', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets', 'machine_tokens'],
         ARRAY['get', 'list', 'create', 'update', 'reveal']);

  -- project-read
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('project-read', 'Read project and secret metadata', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets'], ARRAY['get', 'list']);

  -- secret-read / secret-reveal / secret-write
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('secret-read', 'Read secret metadata (not plaintext)', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list']);

  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('secret-reveal', 'Read secret metadata and reveal plaintext', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list', 'reveal']);

  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('secret-write', 'Update secret value and metadata', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list', 'update', 'reveal']);

  -- service accounts (machine tokens)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('service-readonly', 'Machine token: list and get secrets', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list', 'reveal']);

  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('service-write', 'Machine token: read and write secrets', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list', 'create', 'update', 'reveal']);
END;
$$;

SELECT rbac.ensure_builtin_roles();

-- ── Scope ancestry: secret → project → team → cluster ────────────────
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
    SELECT s.project_id INTO v_project FROM api.secrets s WHERE s.id = p_scope_id;
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
    RETURN;
  END IF;
END;
$$;

-- Subjects for the current (or given) user: self + group memberships
CREATE OR REPLACE FUNCTION api.rbac_subjects(p_user uuid DEFAULT NULL)
RETURNS TABLE(subject_kind text, subject_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
  WITH u AS (
    SELECT COALESCE(p_user, api.current_user_id()) AS id
  )
  SELECT 'User'::text, u.id FROM u WHERE u.id IS NOT NULL
  UNION ALL
  SELECT 'Group'::text, gm.group_id
  FROM u
  JOIN api.group_members gm ON gm.user_id = u.id;
$$;

-- Rule match: resource/verb against role_rules (wildcard *)
CREATE OR REPLACE FUNCTION api.rbac_rule_matches(
  p_resources text[],
  p_verbs text[],
  p_resource text,
  p_verb text
) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT
    (
      '*' = ANY (p_resources)
      OR lower(p_resource) = ANY (SELECT lower(x) FROM unnest(p_resources) AS x)
    )
    AND (
      '*' = ANY (p_verbs)
      OR lower(p_verb) = ANY (SELECT lower(x) FROM unnest(p_verbs) AS x)
    );
$$;

-- Core authorizer
CREATE OR REPLACE FUNCTION api.can(
  p_verb text,
  p_resource text,
  p_scope_kind text DEFAULT 'cluster',
  p_scope_id uuid DEFAULT NULL,
  p_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
DECLARE
  uid uuid := COALESCE(p_subject, api.current_user_id());
  v_verb text := lower(btrim(COALESCE(p_verb, '')));
  v_res text := lower(btrim(COALESCE(p_resource, '')));
  ok boolean;
BEGIN
  IF uid IS NULL OR v_verb = '' OR v_res = '' THEN
    RETURN false;
  END IF;
  -- Global admin short-circuit (cluster-admin equivalent)
  IF EXISTS (
    SELECT 1 FROM private.users WHERE id = uid AND is_global_admin
  ) THEN
    RETURN true;
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM api.rbac_subjects(uid) sub
    JOIN rbac.bindings b
      ON b.subject_kind = sub.subject_kind
     AND b.subject_id = sub.subject_id
    JOIN api.rbac_scope_chain(p_scope_kind, p_scope_id) sc
      ON sc.scope_kind = b.scope_kind
     AND (
       (sc.scope_kind = 'cluster' AND b.scope_id IS NULL)
       OR (b.scope_id IS NOT DISTINCT FROM sc.scope_id)
     )
    JOIN rbac.role_rules rr ON rr.role_id = b.role_id
    WHERE api.rbac_rule_matches(rr.resources, rr.verbs, v_res, v_verb)
  ) INTO ok;
  RETURN COALESCE(ok, false);
END;
$$;

GRANT EXECUTE ON FUNCTION api.can TO authenticator, authenticated, anon;
GRANT EXECUTE ON FUNCTION api.rbac_scope_chain TO authenticator, authenticated, anon;
GRANT EXECUTE ON FUNCTION api.rbac_subjects TO authenticator, authenticated, anon;
GRANT EXECUTE ON FUNCTION api.rbac_rule_matches TO authenticator, authenticated, anon;
GRANT EXECUTE ON FUNCTION rbac.ensure_builtin_roles TO authenticator;

-- ── Compatibility helpers rewritten over can() ───────────────────────
-- Start-fresh: legacy team_members / project_members / secret_acl are NOT consulted.

CREATE OR REPLACE FUNCTION api.is_team_member(tid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin()
    OR api.can('get', 'teams', 'team', tid)
    OR api.can('list', 'projects', 'team', tid)
    OR api.can('get', 'projects', 'team', tid)
    OR api.can('list', 'secrets', 'team', tid);
$$;

CREATE OR REPLACE FUNCTION api.team_role(tid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private
SET row_security = off AS $$
  SELECT CASE
    WHEN api.is_global_admin() THEN 'owner'
    WHEN api.can('*', '*', 'team', tid)
      OR EXISTS (
        SELECT 1 FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        JOIN api.rbac_subjects(api.current_user_id()) s
          ON s.subject_kind = b.subject_kind AND s.subject_id = b.subject_id
        WHERE b.scope_kind = 'team' AND b.scope_id = tid AND r.name = 'team-owner'
      ) THEN 'owner'
    WHEN api.can('admin', 'projects', 'team', tid)
      OR EXISTS (
        SELECT 1 FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        JOIN api.rbac_subjects(api.current_user_id()) s
          ON s.subject_kind = b.subject_kind AND s.subject_id = b.subject_id
        WHERE b.scope_kind = 'team' AND b.scope_id = tid AND r.name = 'team-admin'
      ) THEN 'admin'
    WHEN api.can('create', 'secrets', 'team', tid)
      OR EXISTS (
        SELECT 1 FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        JOIN api.rbac_subjects(api.current_user_id()) s
          ON s.subject_kind = b.subject_kind AND s.subject_id = b.subject_id
        WHERE b.scope_kind = 'team' AND b.scope_id = tid AND r.name = 'team-member'
      ) THEN 'member'
    WHEN api.can('get', 'projects', 'team', tid)
      OR api.can('list', 'secrets', 'team', tid) THEN 'viewer'
    ELSE NULL
  END;
$$;

CREATE OR REPLACE FUNCTION api.project_role(pid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private
SET row_security = off AS $$
  SELECT CASE
    WHEN api.can('admin', 'projects', 'project', pid)
      OR api.can('*', '*', 'project', pid) THEN 'admin'
    WHEN api.can('create', 'secrets', 'project', pid)
      OR api.can('update', 'secrets', 'project', pid) THEN 'write'
    WHEN api.can('get', 'projects', 'project', pid)
      OR api.can('list', 'secrets', 'project', pid) THEN 'read'
    ELSE NULL
  END;
$$;

CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('get', 'projects', 'project', pid)
    OR api.can('list', 'projects', 'project', pid)
    OR api.can('list', 'secrets', 'project', pid)
    OR api.can('get', 'secrets', 'project', pid);
$$;

CREATE OR REPLACE FUNCTION api.can_write_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('create', 'secrets', 'project', pid)
    OR api.can('update', 'secrets', 'project', pid)
    OR api.can('admin', 'projects', 'project', pid)
    OR api.can('*', '*', 'project', pid);
$$;

CREATE OR REPLACE FUNCTION api.can_admin_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('admin', 'projects', 'project', pid)
    OR api.can('*', '*', 'project', pid)
    OR api.can('admin', 'bindings', 'project', pid);
$$;

-- Secret ACL modes (inherit/custom/…) retained as optional restriction *after* RBAC
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
    -- RBAC gate (scope chain includes secret + ancestors)
    WHEN need = 'write' AND NOT (
      api.can('update', 'secrets', 'secret', sid)
      OR api.can('create', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    ) THEN false
    WHEN need = 'reveal' AND NOT (
      api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('update', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    ) THEN false
    WHEN need = 'read' AND NOT (
      api.can('get', 'secrets', 'secret', sid)
      OR api.can('list', 'secrets', 'secret', sid)
      OR api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('update', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    ) THEN false
    -- Project admins / * always full
    WHEN api.can_admin_project(pid) THEN true
    -- Optional legacy-style mode ladder (start-fresh: inherit = project RBAC only)
    WHEN COALESCE(mode, 'inherit') IN ('inherit', 'writers', 'admins', 'owners', 'custom')
      THEN true
    ELSE false
  END;
$$;

CREATE OR REPLACE FUNCTION api.can_access_secret(sid uuid, need text DEFAULT 'read')
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(
    (
      SELECT api.can_access_secret_row(
        s.id, s.project_id, s.acl_mode, need, s.deleted_at
      )
      FROM api.secrets s
      WHERE s.id = sid
    ),
    false
  );
$$;

-- can_reveal_secret: RBAC reveal + approval layer (unchanged approval logic)
CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
    WHEN api.is_global_admin() THEN true
    WHEN api.can_admin_project(
      (SELECT project_id FROM api.secrets WHERE id = sid)
    ) THEN true
    WHEN NOT api.secret_requires_approval(sid) THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secret_access_requests r
      WHERE r.secret_id = sid
        AND r.user_id = api.current_user_id()
        AND r.status = 'approved'
        AND r.approved_until IS NOT NULL
        AND r.approved_until > now()
    ) THEN true
    ELSE false
  END;
$$;

-- Bind creator as team-owner when a team is created
CREATE OR REPLACE FUNCTION private.create_team(p_user uuid, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, rbac
SET row_security = off AS $$
DECLARE
  tid uuid;
  rid uuid;
BEGIN
  INSERT INTO api.teams (name, created_by) VALUES (p_name, p_user) RETURNING id INTO tid;
  -- legacy membership row kept for UI that still reads team_members
  INSERT INTO api.team_members (team_id, user_id, role, source)
  VALUES (tid, p_user, 'owner', 'manual')
  ON CONFLICT (team_id, user_id) DO UPDATE SET role = 'owner', source = 'manual';
  SELECT id INTO rid FROM rbac.roles WHERE name = 'team-owner' LIMIT 1;
  IF rid IS NOT NULL THEN
    INSERT INTO rbac.bindings (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
    VALUES (rid, 'User', p_user, 'team', tid, p_user);
  END IF;
  RETURN tid;
END;
$$;

-- Who can manage RBAC at a scope?
CREATE OR REPLACE FUNCTION api.can_manage_rbac(
  p_scope_kind text,
  p_scope_id uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin()
    OR api.can('admin', 'bindings', p_scope_kind, p_scope_id)
    OR api.can('*', '*', p_scope_kind, p_scope_id)
    OR (
      p_scope_kind = 'project'
      AND api.can_admin_project(p_scope_id)
    )
    OR (
      p_scope_kind = 'team'
      AND api.team_role(p_scope_id) IN ('owner', 'admin')
    );
$$;

GRANT EXECUTE ON FUNCTION api.can_manage_rbac TO authenticator, authenticated;

-- RLS on rbac tables
DROP POLICY IF EXISTS rbac_roles_select ON rbac.roles;
CREATE POLICY rbac_roles_select ON rbac.roles FOR SELECT TO authenticated
  USING (true);
DROP POLICY IF EXISTS rbac_roles_write ON rbac.roles;
CREATE POLICY rbac_roles_write ON rbac.roles FOR ALL TO authenticated
  USING (api.is_global_admin() OR api.can('admin', 'roles', 'cluster', NULL))
  WITH CHECK (api.is_global_admin() OR api.can('admin', 'roles', 'cluster', NULL));

DROP POLICY IF EXISTS rbac_rules_select ON rbac.role_rules;
CREATE POLICY rbac_rules_select ON rbac.role_rules FOR SELECT TO authenticated
  USING (true);
DROP POLICY IF EXISTS rbac_rules_write ON rbac.role_rules;
CREATE POLICY rbac_rules_write ON rbac.role_rules FOR ALL TO authenticated
  USING (api.is_global_admin() OR api.can('admin', 'roles', 'cluster', NULL))
  WITH CHECK (api.is_global_admin() OR api.can('admin', 'roles', 'cluster', NULL));

DROP POLICY IF EXISTS rbac_bindings_select ON rbac.bindings;
CREATE POLICY rbac_bindings_select ON rbac.bindings FOR SELECT TO authenticated
  USING (
    api.is_global_admin()
    OR api.can_manage_rbac(scope_kind, scope_id)
    OR (
      subject_kind = 'User' AND subject_id = api.current_user_id()
    )
  );
DROP POLICY IF EXISTS rbac_bindings_write ON rbac.bindings;
CREATE POLICY rbac_bindings_write ON rbac.bindings FOR ALL TO authenticated
  USING (api.can_manage_rbac(scope_kind, scope_id))
  WITH CHECK (api.can_manage_rbac(scope_kind, scope_id));
