-- Kubernetes-style RBAC (Subjects + Roles + RoleBindings)
-- Applied by ensure_schema() and on fresh volumes after init.sql.
-- Start-fresh: access is designed around rbac.bindings; legacy tables are not used.

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
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap', 'oidc')),
  updated_at timestamptz,
  updated_by uuid,
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
-- Prevent duplicate bindings (same subject + role + scope)
CREATE UNIQUE INDEX IF NOT EXISTS bindings_unique_idx
  ON rbac.bindings(role_id, subject_kind, subject_id, scope_kind,
                   COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid));

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
  -- Rename the old cluster-admin role to global-admin (idempotent)
  UPDATE rbac.roles SET name = 'global-admin',
    description = 'Full access to all resources at every scope'
    WHERE name = 'cluster-admin';
  -- global-admin
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('global-admin', 'Full access to all resources at every scope', true)
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

  -- team-owner (scoped — not wildcard; global-admin is the only * / * built-in role)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-owner', 'Full control of a team and its projects/secrets', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['teams', 'projects', 'secrets', 'bindings', 'groups', 'machine_tokens', 'audit'],
         ARRAY['get', 'list', 'create', 'update', 'delete', 'reveal', 'admin']);

  -- team-admin (includes roles read for binding dropdowns)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-admin', 'Administer team projects and members (not ownership transfer)', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['teams', 'projects', 'secrets', 'bindings', 'groups', 'machine_tokens', 'audit'],
         ARRAY['get', 'list', 'create', 'update', 'delete', 'reveal', 'admin']);
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['roles'], ARRAY['get', 'list']);

  -- team-member (no reveal — members must be granted reveal explicitly)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-member', 'Read projects; create/update secrets in team projects', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets', 'machine_tokens'], ARRAY['get', 'list', 'create', 'update']);

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

  -- project-write (includes reveal — document clearly)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('project-write', 'Create, update, and reveal secrets in a project', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets', 'machine_tokens'],
         ARRAY['get', 'list', 'create', 'update', 'reveal']);

  -- project-reveal (reveal without write)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('project-reveal', 'Read project and reveal secret values (no edit)', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs) VALUES
    (rid, ARRAY['projects', 'secrets'], ARRAY['get', 'list', 'reveal']);

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
  VALUES ('secret-write', 'Create, update, delete secret value and metadata', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list', 'create', 'update', 'delete', 'reveal']);

  -- team-audit-viewer (team-scoped audit delegation)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('team-audit-viewer', 'Read audit logs for a specific team', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['audit'], ARRAY['get', 'list']);

  -- service accounts (machine tokens)
  -- service-read: metadata only (no plaintext)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('service-read', 'Machine token: list and get secret metadata (no plaintext)', true)
  ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
  RETURNING id INTO rid;
  DELETE FROM rbac.role_rules WHERE role_id = rid;
  INSERT INTO rbac.role_rules (role_id, resources, verbs)
  VALUES (rid, ARRAY['secrets'], ARRAY['get', 'list']);

  -- service-reveal: metadata + plaintext (for ESO)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('service-reveal', 'Machine token: list, get, and reveal secrets', true)
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
  -- Global admin short-circuit (global-admin equivalent)
  IF EXISTS (
    SELECT 1 FROM private.users WHERE id = uid AND is_global_admin
  ) THEN
    RETURN true;
  END IF;

  -- Reject deleted secrets at the authorizer level
  IF v_res = 'secrets' AND p_scope_kind = 'secret' AND p_scope_id IS NOT NULL THEN
    IF EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = p_scope_id AND s.deleted_at IS NOT NULL
    ) THEN
      RETURN false;
    END IF;
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
-- Membership and access now resolve exclusively through rbac.bindings.

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
    WHEN api.is_global_admin() THEN 'team-owner'
    WHEN api.can('*', '*', 'team', tid)
      OR EXISTS (
        SELECT 1 FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        JOIN api.rbac_subjects(api.current_user_id()) s
          ON s.subject_kind = b.subject_kind AND s.subject_id = b.subject_id
        WHERE b.scope_kind = 'team' AND b.scope_id = tid AND r.name = 'team-owner'
      ) THEN 'team-owner'
    WHEN api.can('admin', 'projects', 'team', tid)
      OR EXISTS (
        SELECT 1 FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        JOIN api.rbac_subjects(api.current_user_id()) s
          ON s.subject_kind = b.subject_kind AND s.subject_id = b.subject_id
        WHERE b.scope_kind = 'team' AND b.scope_id = tid AND r.name = 'team-admin'
      ) THEN 'team-admin'
    WHEN api.can('create', 'secrets', 'team', tid)
      OR EXISTS (
        SELECT 1 FROM rbac.bindings b
        JOIN rbac.roles r ON r.id = b.role_id
        JOIN api.rbac_subjects(api.current_user_id()) s
          ON s.subject_kind = b.subject_kind AND s.subject_id = b.subject_id
        WHERE b.scope_kind = 'team' AND b.scope_id = tid AND r.name = 'team-member'
      ) THEN 'team-member'
    WHEN api.can('get', 'projects', 'team', tid)
      OR api.can('list', 'secrets', 'team', tid) THEN 'team-viewer'
    ELSE NULL
  END;
$$;

CREATE OR REPLACE FUNCTION api.project_role(pid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private
SET row_security = off AS $$
  SELECT CASE
    WHEN api.can('admin', 'projects', 'project', pid)
      OR api.can('*', '*', 'project', pid) THEN 'project-admin'
    WHEN api.can('create', 'secrets', 'project', pid)
      OR api.can('update', 'secrets', 'project', pid) THEN 'project-write'
    WHEN api.can('get', 'projects', 'project', pid)
      OR api.can('list', 'secrets', 'project', pid) THEN 'project-read'
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

-- Admin floor: anyone who can admin the project has full access to every secret
-- in it (see can_access_secret_row). Bindings cannot remove that floor.
CREATE OR REPLACE FUNCTION api.can_admin_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('admin', 'projects', 'project', pid)
    OR api.can('*', '*', 'project', pid)
    OR api.can('admin', 'bindings', 'project', pid);
$$;

-- Does the subject have a secret-scoped binding that covers this need?
-- (Does not walk project/team ancestors — used for restricted secrets.)
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
    FROM api.rbac_subjects(COALESCE(p_subject, api.current_user_id())) sub
    JOIN rbac.bindings b
      ON b.subject_kind = sub.subject_kind
     AND b.subject_id = sub.subject_id
    JOIN rbac.role_rules rr ON rr.role_id = b.role_id
    WHERE b.scope_kind = 'secret'
      AND b.scope_id = p_sid
      AND (
        CASE lower(COALESCE(p_need, ''))
          WHEN 'write' THEN
            api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'create')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
          WHEN 'reveal' THEN
            api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
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
      )
  );
$$;

GRANT EXECUTE ON FUNCTION api.rbac_secret_binding_allows TO authenticator, authenticated, anon;

-- Secret access: RBAC on scope chain, or restricted = secret bindings only.
-- access_mode 'restricted' is the exclusive / "deny broader grants" mode: team and project
-- bindings do NOT apply — only secret-scope bindings + project admins (admin floor).
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
    -- Project admins always full
    WHEN api.can_admin_project(pid) THEN true
    -- Restricted: secret-scope bindings only
    WHEN COALESCE(mode, 'inherit') = 'restricted' THEN
      api.rbac_secret_binding_allows(sid, need)
    -- inherit → project/team RBAC via the scope chain
    WHEN need = 'write' THEN (
      api.can('update', 'secrets', 'secret', sid)
      OR api.can('create', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
    WHEN need = 'reveal' THEN (
      api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('update', 'secrets', 'secret', sid)
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

CREATE OR REPLACE FUNCTION api.can_access_secret(sid uuid, need text DEFAULT 'read')
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(
    (
      SELECT api.can_access_secret_row(
        s.id, s.project_id, s.access_mode, need, s.deleted_at
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
  -- RBAC only: create team-owner binding via rbac.bindings
  SELECT id INTO rid FROM rbac.roles WHERE name = 'team-owner' LIMIT 1;
  IF rid IS NOT NULL THEN
    INSERT INTO rbac.bindings (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
    VALUES (rid, 'User', p_user, 'team', tid, p_user);
  END IF;
  RETURN tid;
END;
$$;

-- Team member listing via rbac.bindings (replaces legacy team_members queries)
CREATE OR REPLACE FUNCTION private.team_member_rows(p_team uuid)
RETURNS TABLE (role text, source text, user_id uuid, email text, name text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, rbac
SET row_security = off AS $$
  SELECT r.name AS role, COALESCE(b.source, 'manual') AS source,
         u.id, u.email, u.name
  FROM rbac.bindings b
  JOIN rbac.roles r ON r.id = b.role_id
  JOIN private.users u ON u.id = b.subject_id
  WHERE b.scope_kind = 'team' AND b.scope_id = p_team
    AND b.subject_kind = 'User'
    AND api.is_team_member(p_team)
  ORDER BY r.name, u.email;
$$;
GRANT EXECUTE ON FUNCTION private.team_member_rows TO authenticator, authenticated;

-- Project member listing via rbac.bindings
CREATE OR REPLACE FUNCTION private.project_member_rows(p_project uuid)
RETURNS TABLE (role text, user_id uuid, email text, name text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, rbac
SET row_security = off AS $$
  SELECT r.name AS role, u.id, u.email, u.name
  FROM rbac.bindings b
  JOIN rbac.roles r ON r.id = b.role_id
  JOIN private.users u ON u.id = b.subject_id
  WHERE b.scope_kind = 'project' AND b.scope_id = p_project
    AND b.subject_kind = 'User'
    AND api.can_read_project(p_project)
  ORDER BY r.name, u.email;
$$;
GRANT EXECUTE ON FUNCTION private.project_member_rows TO authenticator, authenticated;

-- Project group role listing via rbac.bindings
CREATE OR REPLACE FUNCTION private.project_group_role_rows(p_project uuid)
RETURNS TABLE (
  group_id uuid,
  group_name text,
  role text,
  source text
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, rbac
SET row_security = off AS $$
  SELECT g.id AS group_id, g.name AS group_name, r.name AS role,
         COALESCE(b.source, 'manual') AS source
  FROM rbac.bindings b
  JOIN rbac.roles r ON r.id = b.role_id
  JOIN api.groups g ON g.id = b.subject_id
  WHERE b.scope_kind = 'project' AND b.scope_id = p_project
    AND b.subject_kind = 'Group'
    AND api.can_read_project(p_project)
  ORDER BY g.name;
$$;
GRANT EXECUTE ON FUNCTION private.project_group_role_rows TO authenticator, authenticated;

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
      p_scope_kind = 'team'
      AND api.team_role(p_scope_id) IN ('team-owner', 'team-admin')
    )
    OR (
      p_scope_kind = 'project'
      AND api.can_admin_project(p_scope_id)
    )
    OR (
      p_scope_kind = 'secret'
      AND EXISTS (
        SELECT 1 FROM api.secrets s
        WHERE s.id = p_scope_id
          AND s.deleted_at IS NULL
          AND api.can_admin_project(s.project_id)
      )
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

-- Prevent removing the last team-owner binding (User or Group subject)
CREATE OR REPLACE FUNCTION rbac.guard_last_team_owner_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  old_role text;
  new_role text;
  remaining int;
  tid uuid;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT r.name INTO old_role FROM rbac.roles r WHERE r.id = OLD.role_id;
    IF OLD.scope_kind = 'team' AND old_role = 'team-owner' THEN
      tid := OLD.scope_id;
      SELECT count(*) INTO remaining
      FROM rbac.bindings b
      JOIN rbac.roles r ON r.id = b.role_id
      WHERE b.scope_kind = 'team' AND b.scope_id = tid
        AND r.name = 'team-owner'
        AND b.id IS DISTINCT FROM OLD.id;
      IF remaining = 0 THEN
        RAISE EXCEPTION 'cannot remove the last team owner; transfer ownership first';
      END IF;
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    SELECT r.name INTO old_role FROM rbac.roles r WHERE r.id = OLD.role_id;
    SELECT r.name INTO new_role FROM rbac.roles r WHERE r.id = NEW.role_id;
    IF OLD.scope_kind = 'team' AND old_role = 'team-owner'
       AND new_role IS DISTINCT FROM 'team-owner' THEN
      tid := OLD.scope_id;
      SELECT count(*) INTO remaining
      FROM rbac.bindings b
      JOIN rbac.roles r ON r.id = b.role_id
      WHERE b.scope_kind = 'team' AND b.scope_id = tid
        AND r.name = 'team-owner'
        AND b.id IS DISTINCT FROM OLD.id;
      IF remaining = 0 THEN
        RAISE EXCEPTION 'cannot remove the last team owner; transfer ownership first';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS bindings_guard_last_team_owner ON rbac.bindings;
CREATE TRIGGER bindings_guard_last_team_owner
  BEFORE UPDATE OR DELETE ON rbac.bindings
  FOR EACH ROW EXECUTE FUNCTION rbac.guard_last_team_owner_binding();

-- ── Drop legacy secret ACL (replaced by secret-scope rbac.bindings) ──
DROP FUNCTION IF EXISTS private.secret_acl_rows(uuid);
DROP TABLE IF EXISTS api.secret_acl CASCADE;


-- ── Self-service: a user's own bindings across scopes (Profile → My access) ──
CREATE OR REPLACE FUNCTION api.my_access_rows()
RETURNS TABLE(
  scope_kind text,
  scope_label text,
  role_name text,
  role_description text,
  grant_kind text,
  grant_subject text,
  created_at timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
DECLARE
  uid uuid := api.current_user_id();
BEGIN
  IF uid IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY
  SELECT
    b.scope_kind::text,
    CASE b.scope_kind
      WHEN 'cluster' THEN 'Global'::text
      WHEN 'team' THEN t.name
      WHEN 'project' THEN p.name
      ELSE COALESCE(
             CASE WHEN COALESCE(se.project_name, '') = '' THEN ''
                  ELSE se.project_name || ' / ' END
             || COALESCE(se.key, ''),
             '')
    END::text AS scope_label,
    r.name::text AS role_name,
    COALESCE(r.description, '')::text AS role_description,
    CASE WHEN b.subject_kind = 'User' THEN 'Direct' ELSE 'Group' END::text AS grant_kind,
    COALESCE(g.name, 'You')::text AS grant_subject,
    b.created_at
  FROM api.rbac_subjects(uid) sub
  JOIN rbac.bindings b
    ON b.subject_kind = sub.subject_kind
   AND b.subject_id = sub.subject_id
  JOIN rbac.roles r ON r.id = b.role_id
  LEFT JOIN api.groups g ON b.subject_kind = 'Group' AND g.id = b.subject_id
  LEFT JOIN api.teams t ON b.scope_kind = 'team' AND t.id = b.scope_id
  LEFT JOIN api.projects p ON b.scope_kind = 'project' AND p.id = b.scope_id
  LEFT JOIN LATERAL (
    SELECT proj.name AS project_name, s.key
    FROM api.secrets s
    LEFT JOIN api.projects proj ON proj.id = s.project_id
    WHERE s.id = b.scope_id
  ) se ON b.scope_kind = 'secret'
  ORDER BY b.scope_kind, 2, r.name;
END;
$$;
GRANT EXECUTE ON FUNCTION api.my_access_rows TO authenticator, authenticated, anon;

-- ── Resource perspective: who can access a scope and why ────────────────
-- Admin/manager-gated. Walks the scope inheritance chain (secret → project →
-- team → cluster) and expands groups to members; appends global admins.
CREATE OR REPLACE FUNCTION api.effective_access_rows(
  p_scope_kind text,
  p_scope_id uuid DEFAULT NULL
)
RETURNS TABLE(
  subject_email text,
  subject_name text,
  subject_kind text,
  scope_kind text,
  scope_label text,
  role_name text,
  grant_kind text,
  grant_subject text,
  is_global_admin boolean
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NOT (api.is_global_admin() OR api.can_manage_rbac(p_scope_kind, p_scope_id)) THEN
    RETURN;
  END IF;

  RETURN QUERY
  WITH chain AS (
    SELECT c.scope_kind::text, c.scope_id
    FROM api.rbac_scope_chain(p_scope_kind, p_scope_id) AS c
  ),
  labels AS (
    SELECT 'cluster'::text AS scope_kind, NULL::uuid AS scope_id, 'Global'::text AS scope_label
    UNION ALL
    SELECT 'team', t.id, t.name FROM api.teams t
    UNION ALL
    SELECT 'project', p.id, p.name FROM api.projects p
    UNION ALL
    SELECT 'secret', s.id, COALESCE(p2.name, '') || ' / ' || s.key
      FROM api.secrets s LEFT JOIN api.projects p2 ON p2.id = s.project_id
  ),
  grants AS (
    SELECT b.subject_kind, b.subject_id, b.scope_kind, b.scope_id, r.name AS role_name
    FROM rbac.bindings b
    JOIN rbac.roles r ON r.id = b.role_id
    JOIN chain sc ON sc.scope_kind = b.scope_kind
      AND (
        b.scope_kind = 'cluster'
        OR sc.scope_id IS NOT DISTINCT FROM b.scope_id
      )
  ),
  scoped AS (
    SELECT g.*, COALESCE(l.scope_label, g.scope_kind) AS scope_label
    FROM grants g
    LEFT JOIN labels l
      ON l.scope_kind = g.scope_kind
     AND l.scope_id IS NOT DISTINCT FROM g.scope_id
  )
  SELECT u.email::text, u.name::text, 'User'::text, s.scope_kind, s.scope_label,
         s.role_name, 'Direct'::text, u.email::text, u.is_global_admin
    FROM scoped s
    JOIN private.users u ON s.subject_kind = 'User' AND u.id = s.subject_id
   WHERE u.disabled_at IS NULL
  UNION ALL
  SELECT u.email::text, u.name::text, 'User'::text, s.scope_kind, s.scope_label,
         s.role_name, 'Group: ' || gr.name, gr.name, u.is_global_admin
    FROM scoped s
    JOIN api.groups gr ON s.subject_kind = 'Group' AND gr.id = s.subject_id
    JOIN api.group_members gm ON gm.group_id = gr.id
    JOIN private.users u ON u.id = gm.user_id
   WHERE u.disabled_at IS NULL
  UNION ALL
  SELECT NULL::text, NULL::text, 'ServiceAccount'::text, s.scope_kind, s.scope_label,
         s.role_name, 'Direct'::text, s.subject_id::text, false
    FROM scoped s
   WHERE s.subject_kind = 'ServiceAccount'
  UNION ALL
  SELECT u.email::text, u.name::text, 'User'::text, 'cluster',
         'Global', 'global-admin', 'Global admin', u.email::text, true
    FROM private.users u
   WHERE u.disabled_at IS NULL AND u.is_global_admin
  ORDER BY 1 NULLS LAST, 4, 6;
END;
$$;
GRANT EXECUTE ON FUNCTION api.effective_access_rows TO authenticator, authenticated;
