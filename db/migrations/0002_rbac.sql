-- Kubernetes-style RBAC (Subjects + Roles + RoleBindings)
-- Baseline migration 0002: applied on fresh volumes after 0001_init.sql and by
-- the migration runner (app/migrations.py) on existing volumes.
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
-- Inserts/replaces all built-in roles and their role_rules.
-- Called once at the end of this script (SELECT rbac.ensure_builtin_roles()).
-- Idempotent: safe to re-run; replaces rules each time.
--
-- Input:  none
-- Output: void
-- Example: SELECT rbac.ensure_builtin_roles();
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
-- Returns the scope chain from the given scope up to cluster.
-- For a secret: secret → project → team → cluster.
-- For a project: project → team → cluster.
-- For a team:    team → cluster.
-- For cluster:  cluster.
--
-- Input:  p_scope_kind (text: 'cluster'|'team'|'project'|'secret'),
--         p_scope_id  (uuid: scope id, NULL for cluster)
-- Output: TABLE(scope_kind text, scope_id uuid) — ancestor scopes
-- Example: SELECT * FROM api.rbac_scope_chain('secret', '<secret-uuid>');
--          → ('secret', <sid>), ('project', <pid>), ('team', <tid>), ('cluster', NULL)
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

-- Subjects for the current (or given) user: self + group memberships.
-- Returns one row for the user ('User', user_id) plus one row per group
-- membership ('Group', group_id).
--
-- Input:  p_user (uuid: user id; NULL = current user from JWT)
-- Output: TABLE(subject_kind text, subject_id uuid)
-- Example: SELECT * FROM api.rbac_subjects();
--          → ('User', <uid>), ('Group', <gid1>), ('Group', <gid2>)
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

-- Rule match: resource/verb against role_rules (wildcard *).
-- Returns true if the resource and verb match any entry in the arrays,
-- case-insensitive. '*' in resources or verbs matches anything.
--
-- Input:  p_resources (text[]: e.g. ['secrets']),
--         p_verbs    (text[]: e.g. ['get','list','reveal']),
--         p_resource (text:  e.g. 'secrets'),
--         p_verb     (text:  e.g. 'reveal')
-- Output: boolean — true if match
-- Example: SELECT api.rbac_rule_matches(ARRAY['secrets'], ARRAY['reveal'], 'secrets', 'reveal');
--          → true
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

-- Core authorizer. Checks whether the current (or given) subject has a
-- binding whose role rules match the verb+resource at the given scope
-- (or any ancestor scope via rbac_scope_chain). Global admins short-circuit
-- to true. Deleted secrets are rejected at the authorizer level.
--
-- Input:  p_verb       (text: 'get'|'list'|'create'|'update'|'delete'|'reveal'|'admin'|'*'),
--         p_resource   (text: 'teams'|'projects'|'secrets'|'bindings'|'roles'|'audit'|'*'),
--         p_scope_kind (text: 'cluster'|'team'|'project'|'secret'; default 'cluster'),
--         p_scope_id   (uuid: scope id; NULL for cluster; default NULL),
--         p_subject    (uuid: override user; NULL = current JWT user; default NULL)
-- Output: boolean — true if access allowed
-- Example: SELECT api.can('reveal', 'secrets', 'secret', '<secret-uuid>');
--          SELECT api.can('admin', 'projects', 'project', '<project-uuid>');
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
-- These wrap api.can() so existing RLS policies and app code work unchanged.

-- Check if the current user is a member of the given team (direct or via group).
-- Returns true for global admins.
--
-- Input:  tid (uuid: team id)
-- Output: boolean
-- Example: SELECT api.is_team_member('<team-uuid>');
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

-- Return the highest team role for the current user: 'team-owner',
-- 'team-admin', 'team-member', 'team-viewer', or NULL.
-- Global admins return 'team-owner'. Checks direct and group bindings.
--
-- Input:  tid (uuid: team id)
-- Output: text — role name or NULL
-- Example: SELECT api.team_role('<team-uuid>');
--          → 'team-admin'
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

-- Return the highest project role for the current user: 'project-admin',
-- 'project-write', 'project-read', or NULL. Does not fall back to team role.
--
-- Input:  pid (uuid: project id)
-- Output: text — role name or NULL
-- Example: SELECT api.project_role('<project-uuid>');
--          → 'project-write'
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

-- Check if the current user can read the given project (list secrets, view metadata).
--
-- Input:  pid (uuid: project id)
-- Output: boolean
-- Example: SELECT api.can_read_project('<project-uuid>');
CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('get', 'projects', 'project', pid)
    OR api.can('list', 'projects', 'project', pid)
    OR api.can('list', 'secrets', 'project', pid)
    OR api.can('get', 'secrets', 'project', pid);
$$;

-- Check if the current user can write secrets in the given project
-- (create, update, or admin).
--
-- Input:  pid (uuid: project id)
-- Output: boolean
-- Example: SELECT api.can_write_project('<project-uuid>');
CREATE OR REPLACE FUNCTION api.can_write_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('create', 'secrets', 'project', pid)
    OR api.can('update', 'secrets', 'project', pid)
    OR api.can('admin', 'projects', 'project', pid)
    OR api.can('*', '*', 'project', pid);
$$;

-- Check if the current user can administer the given project.
-- Admin floor: anyone who can admin the project has full access to every
-- secret in it (see can_access_secret_row). Bindings cannot remove that floor.
--
-- Input:  pid (uuid: project id)
-- Output: boolean
-- Example: SELECT api.can_admin_project('<project-uuid>');
CREATE OR REPLACE FUNCTION api.can_admin_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.can('admin', 'projects', 'project', pid)
    OR api.can('*', '*', 'project', pid)
    OR api.can('admin', 'bindings', 'project', pid);
$$;

-- Check if the current (or given) subject has a secret-scoped binding that
-- covers the requested need. Does NOT walk project/team ancestors — used
-- for restricted secrets where only secret-scope bindings apply.
--
-- Input:  p_sid     (uuid: secret id),
--         p_need    (text: 'read'|'reveal'|'write'),
--         p_subject (uuid: override user; NULL = current user; default NULL)
-- Output: boolean — true if a secret-scope binding grants the need
-- Example: SELECT api.rbac_secret_binding_allows('<secret-uuid>', 'reveal');
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

-- Secret access check: RBAC on scope chain, or restricted = secret bindings only.
-- access_mode 'restricted' is the exclusive / "deny broader grants" mode: team
-- and project bindings do NOT apply — only secret-scope bindings + project
-- admins (admin floor). Safe for INSERT…RETURNING (takes row values as params).
--
-- Input:  sid        (uuid: secret id),
--         pid        (uuid: project id),
--         mode       (text: 'inherit'|'restricted' — from secrets.access_mode),
--         need       (text: 'read'|'reveal'|'write'; default 'read'),
--         deleted_at (timestamptz: secret.deleted_at; NULL = live)
-- Output: boolean — true if access allowed
-- Example: SELECT api.can_access_secret_row('<sid>', '<pid>', 'inherit', 'reveal', NULL);
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

-- Wrapper for can_access_secret_row that loads the secret row from the DB.
-- Use this when you have only the secret id (not the full row).
--
-- Input:  sid  (uuid: secret id),
--         need (text: 'read'|'reveal'|'write'; default 'read')
-- Output: boolean — true if access allowed (false if secret not found)
-- Example: SELECT api.can_access_secret('<secret-uuid>', 'reveal');
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

-- Check if the current user can reveal the secret value NOW.
-- Combines RBAC reveal permission with the approval layer:
--   1. Must have 'reveal' via can_access_secret.
--   2. Global admins and project admins always pass.
--   3. If secret_requires_approval is false, pass.
--   4. Otherwise, must have an approved access request with approved_until > now().
--
-- Input:  sid (uuid: secret id)
-- Output: boolean — true if reveal allowed now
-- Example: SELECT api.can_reveal_secret('<secret-uuid>');
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

-- Create a team and bind the creator as team-owner via rbac.bindings.
-- Called by the Flask app when a user creates a new team.
--
-- Input:  p_user (uuid: creator user id),
--         p_name (text: team name)
-- Output: uuid — new team id
-- Example: SELECT private.create_team('<user-uuid>', 'Platform');
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

-- List team members via rbac.bindings (replaces legacy team_members queries).
-- Returns one row per User-scope binding at team scope.
--
-- Input:  p_team (uuid: team id)
-- Output: TABLE(role text, source text, user_id uuid, email text, name text)
-- Example: SELECT * FROM private.team_member_rows('<team-uuid>');
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

-- List project members via rbac.bindings.
-- Returns one row per User-scope binding at project scope.
--
-- Input:  p_project (uuid: project id)
-- Output: TABLE(role text, user_id uuid, email text, name text)
-- Example: SELECT * FROM private.project_member_rows('<project-uuid>');
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

-- List project group bindings via rbac.bindings.
-- Returns one row per Group-scope binding at project scope.
--
-- Input:  p_project (uuid: project id)
-- Output: TABLE(group_id uuid, group_name text, role text, source text)
-- Example: SELECT * FROM private.project_group_role_rows('<project-uuid>');
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

-- Check if the current user can manage RBAC bindings at the given scope.
-- True for global admins, anyone with 'admin' on 'bindings' at the scope,
-- team-owner/team-admin for team scope, project-admin for project scope,
-- or project-admin for secret scope.
--
-- Input:  p_scope_kind (text: 'cluster'|'team'|'project'|'secret'),
--         p_scope_id  (uuid: scope id; NULL for cluster; default NULL)
-- Output: boolean
-- Example: SELECT api.can_manage_rbac('team', '<team-uuid>');
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

-- ── RLS on rbac tables: roles (all read, global admin write),
--    role_rules (all read, global admin write),
--    bindings (scope manager or self read, can_manage_rbac write)
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

-- Trigger: prevent removing the last team-owner binding.
-- Fires BEFORE UPDATE OR DELETE on rbac.bindings. If the operation would
-- leave a team with zero team-owner bindings, raises an exception.
--
-- Input:  Trigger (OLD/NEW row from rbac.bindings)
-- Output: trigger — OLD or NEW row (or raises exception)
-- Example: (trigger — not called directly)
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
-- Returns all bindings for the current user, with friendly scope labels.
-- Used by the Profile → My access tab.
--
-- Input:  none (uses current user from JWT)
-- Output: TABLE(scope_kind, scope_label, role_name, role_description,
--               grant_kind, grant_subject, created_at)
-- Example: SELECT * FROM api.my_access_rows();
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
-- Returns everyone who can access the given scope and why — including direct
-- bindings, group members expanded, service accounts, and global admins.
-- Admin/manager-gated. Walks the scope inheritance chain (secret → project →
-- team → cluster) and expands groups to members; appends global admins.
--
-- Input:  p_scope_kind (text: 'cluster'|'team'|'project'|'secret'),
--         p_scope_id  (uuid: scope id; NULL for cluster; default NULL)
-- Output: TABLE(subject_email, subject_name, subject_kind, scope_kind,
--               scope_label, role_name, grant_kind, grant_subject, is_global_admin)
-- Example: SELECT * FROM api.effective_access_rows('project', '<project-uuid>');
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

-- ── RLS Policies (created after auth functions exist) ──────────────────
-- All RLS policies are defined here (not in init.sql) because they reference
-- RBAC auth functions defined above. Each policy uses DROP POLICY IF EXISTS
-- before CREATE POLICY for idempotency.
--
-- Convention: policies use the `authenticated` role (SET ROLE from JWT).
-- Global admins short-circuit via api.is_global_admin() in helpers.

-- Grant execute on auth functions to authenticated and anon (PostgREST)
GRANT EXECUTE ON FUNCTION api.is_team_member TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.team_role TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.project_role TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_read_project TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_write_project TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_admin_project TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_access_secret_row TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_access_secret TO authenticated, anon;

-- ── teams: select (member), insert (creator/admin), update (owner/admin), delete (owner)
DROP POLICY IF EXISTS teams_select ON api.teams;
CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
  USING (api.is_global_admin() OR api.is_team_member(id));
DROP POLICY IF EXISTS teams_insert ON api.teams;
CREATE POLICY teams_insert ON api.teams FOR INSERT TO authenticated
  WITH CHECK (created_by = api.current_user_id() OR api.is_global_admin());
DROP POLICY IF EXISTS teams_update ON api.teams;
CREATE POLICY teams_update ON api.teams FOR UPDATE TO authenticated
  USING (api.team_role(id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS teams_delete ON api.teams;
CREATE POLICY teams_delete ON api.teams FOR DELETE TO authenticated
  USING (api.team_role(id) = 'team-owner');

-- ── team_ldap_maps: select (member), write (team-owner/admin)
DROP POLICY IF EXISTS tlm_select ON api.team_ldap_maps;
CREATE POLICY tlm_select ON api.team_ldap_maps FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
DROP POLICY IF EXISTS tlm_insert ON api.team_ldap_maps;
CREATE POLICY tlm_insert ON api.team_ldap_maps FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS tlm_update ON api.team_ldap_maps;
CREATE POLICY tlm_update ON api.team_ldap_maps FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS tlm_delete ON api.team_ldap_maps;
CREATE POLICY tlm_delete ON api.team_ldap_maps FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

-- ── team_oidc_maps: select (member), write (team-owner/admin)
DROP POLICY IF EXISTS tom_select ON api.team_oidc_maps;
CREATE POLICY tom_select ON api.team_oidc_maps FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
DROP POLICY IF EXISTS tom_insert ON api.team_oidc_maps;
CREATE POLICY tom_insert ON api.team_oidc_maps FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS tom_update ON api.team_oidc_maps;
CREATE POLICY tom_update ON api.team_oidc_maps FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS tom_delete ON api.team_oidc_maps;
CREATE POLICY tom_delete ON api.team_oidc_maps FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

-- ── team_invites: select/insert/update/delete (team-owner/admin only)
DROP POLICY IF EXISTS team_invites_select ON api.team_invites;
CREATE POLICY team_invites_select ON api.team_invites FOR SELECT TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS team_invites_insert ON api.team_invites;
CREATE POLICY team_invites_insert ON api.team_invites FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS team_invites_update ON api.team_invites;
CREATE POLICY team_invites_update ON api.team_invites FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS team_invites_delete ON api.team_invites;
CREATE POLICY team_invites_delete ON api.team_invites FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

-- ── team_join_requests: select (admin or self), insert (self), update (admin)
DROP POLICY IF EXISTS team_join_requests_select ON api.team_join_requests;
CREATE POLICY team_join_requests_select ON api.team_join_requests FOR SELECT TO authenticated
  USING (
    api.team_role(team_id) IN ('team-owner', 'team-admin')
    OR user_id = api.current_user_id()
  );
DROP POLICY IF EXISTS team_join_requests_insert ON api.team_join_requests;
CREATE POLICY team_join_requests_insert ON api.team_join_requests FOR INSERT TO authenticated
  WITH CHECK (user_id = api.current_user_id());
DROP POLICY IF EXISTS team_join_requests_update ON api.team_join_requests;
CREATE POLICY team_join_requests_update ON api.team_join_requests FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

-- ── org_audit: select (team member or project reader)
DROP POLICY IF EXISTS org_audit_select ON api.org_audit;
CREATE POLICY org_audit_select ON api.org_audit FOR SELECT TO authenticated
  USING (
    (team_id IS NOT NULL AND api.is_team_member(team_id))
    OR (project_id IS NOT NULL AND api.can_read_project(project_id))
  );

-- ── projects: select (team member), insert (team-owner/admin/member),
--    update (can_admin_project), delete (team-owner/admin)
DROP POLICY IF EXISTS projects_select ON api.projects;
CREATE POLICY projects_select ON api.projects FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
DROP POLICY IF EXISTS projects_insert ON api.projects;
CREATE POLICY projects_insert ON api.projects FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin', 'team-member'));
DROP POLICY IF EXISTS projects_update ON api.projects;
CREATE POLICY projects_update ON api.projects FOR UPDATE TO authenticated
  USING (api.can_admin_project(id));
DROP POLICY IF EXISTS projects_delete ON api.projects;
CREATE POLICY projects_delete ON api.projects FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

-- ── secret_pins: select/insert/delete (self only, secret must be readable)
DROP POLICY IF EXISTS secret_pins_select ON api.secret_pins;
CREATE POLICY secret_pins_select ON api.secret_pins FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
DROP POLICY IF EXISTS secret_pins_insert ON api.secret_pins;
CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
DROP POLICY IF EXISTS secret_pins_delete ON api.secret_pins;
CREATE POLICY secret_pins_delete ON api.secret_pins FOR DELETE TO authenticated
  USING (user_id = api.current_user_id());

-- ── secret_recent: select/insert/update/delete (self only, secret must be readable)
DROP POLICY IF EXISTS secret_recent_select ON api.secret_recent;
CREATE POLICY secret_recent_select ON api.secret_recent FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
DROP POLICY IF EXISTS secret_recent_insert ON api.secret_recent;
CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
DROP POLICY IF EXISTS secret_recent_update ON api.secret_recent;
CREATE POLICY secret_recent_update ON api.secret_recent FOR UPDATE TO authenticated
  USING (user_id = api.current_user_id());
DROP POLICY IF EXISTS secret_recent_delete ON api.secret_recent;
CREATE POLICY secret_recent_delete ON api.secret_recent FOR DELETE TO authenticated
  USING (user_id = api.current_user_id());

-- ── secrets: select (can_access_secret_row read/write), insert (can_write_project),
--    update (can_access_secret_row write), delete (soft-deleted + write)
DROP POLICY IF EXISTS secrets_select ON api.secrets;
CREATE POLICY secrets_select ON api.secrets FOR SELECT TO authenticated
  USING (
    (deleted_at IS NULL AND api.can_access_secret_row(id, project_id, access_mode, 'read', NULL))
    OR (deleted_at IS NOT NULL AND api.can_access_secret_row(id, project_id, access_mode, 'write', NULL))
  );
DROP POLICY IF EXISTS secrets_insert ON api.secrets;
CREATE POLICY secrets_insert ON api.secrets FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
DROP POLICY IF EXISTS secrets_update ON api.secrets;
CREATE POLICY secrets_update ON api.secrets FOR UPDATE TO authenticated
  USING (api.can_access_secret_row(id, project_id, access_mode, 'write', NULL))
  WITH CHECK (api.can_access_secret_row(id, project_id, access_mode, 'write', NULL));
DROP POLICY IF EXISTS secrets_delete ON api.secrets;
CREATE POLICY secrets_delete ON api.secrets FOR DELETE TO authenticated
  USING (
    deleted_at IS NOT NULL
    AND api.can_access_secret_row(id, project_id, access_mode, 'write', NULL)
  );

-- ── secret_meta: select/insert/update/delete (can_access_secret read/write)
DROP POLICY IF EXISTS secret_meta_select ON api.secret_meta;
CREATE POLICY secret_meta_select ON api.secret_meta FOR SELECT TO authenticated
  USING (api.can_access_secret(secret_id, 'read'));
DROP POLICY IF EXISTS secret_meta_insert ON api.secret_meta;
CREATE POLICY secret_meta_insert ON api.secret_meta FOR INSERT TO authenticated
  WITH CHECK (api.can_access_secret(secret_id, 'write'));
DROP POLICY IF EXISTS secret_meta_update ON api.secret_meta;
CREATE POLICY secret_meta_update ON api.secret_meta FOR UPDATE TO authenticated
  USING (api.can_access_secret(secret_id, 'write'));
DROP POLICY IF EXISTS secret_meta_delete ON api.secret_meta;
CREATE POLICY secret_meta_delete ON api.secret_meta FOR DELETE TO authenticated
  USING (api.can_access_secret(secret_id, 'write'));

-- ── secret_versions: select (parent secret readable), no client insert (trigger-only)
DROP POLICY IF EXISTS secret_versions_select ON api.secret_versions;
CREATE POLICY secret_versions_select ON api.secret_versions FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', s.deleted_at
        )
    )
  );

-- ── secret_audit: select (can_read_project), no client insert (SECURITY DEFINER only)
DROP POLICY IF EXISTS secret_audit_select ON api.secret_audit;
CREATE POLICY secret_audit_select ON api.secret_audit FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));

-- ── groups: select (team member), write (team-owner/admin)
DROP POLICY IF EXISTS groups_select ON api.groups;
CREATE POLICY groups_select ON api.groups FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
DROP POLICY IF EXISTS groups_insert ON api.groups;
CREATE POLICY groups_insert ON api.groups FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS groups_update ON api.groups;
CREATE POLICY groups_update ON api.groups FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));
DROP POLICY IF EXISTS groups_delete ON api.groups;
CREATE POLICY groups_delete ON api.groups FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

-- ── group_members: select (team member), write (team-owner/admin),
--    delete (team-owner/admin or self)
DROP POLICY IF EXISTS gm_select ON api.group_members;
CREATE POLICY gm_select ON api.group_members FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.is_team_member(g.team_id)
    )
  );
DROP POLICY IF EXISTS gm_insert ON api.group_members;
CREATE POLICY gm_insert ON api.group_members FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.team_role(g.team_id) IN ('team-owner', 'team-admin')
    )
  );
DROP POLICY IF EXISTS gm_update ON api.group_members;
CREATE POLICY gm_update ON api.group_members FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.team_role(g.team_id) IN ('team-owner', 'team-admin')
    )
  );
DROP POLICY IF EXISTS gm_delete ON api.group_members;
CREATE POLICY gm_delete ON api.group_members FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.team_role(g.team_id) IN ('team-owner', 'team-admin')
    )
    OR user_id = api.current_user_id()
  );

-- ── secret_access_requests: select (admin or self), insert (self + can_read),
--    update (admin only — approve/deny)
DROP POLICY IF EXISTS secret_access_requests_select ON api.secret_access_requests;
CREATE POLICY secret_access_requests_select ON api.secret_access_requests
  FOR SELECT TO authenticated
  USING (
    api.can_admin_project(project_id)
    OR user_id = api.current_user_id()
  );
DROP POLICY IF EXISTS secret_access_requests_insert ON api.secret_access_requests;
CREATE POLICY secret_access_requests_insert ON api.secret_access_requests
  FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND api.can_read_project(project_id)
  );
DROP POLICY IF EXISTS secret_access_requests_update ON api.secret_access_requests;
CREATE POLICY secret_access_requests_update ON api.secret_access_requests
  FOR UPDATE TO authenticated
  USING (api.can_admin_project(project_id));

-- ── machine_tokens: select (can_read_project), insert/delete (can_write_project)
DROP POLICY IF EXISTS mt_select ON api.machine_tokens;
CREATE POLICY mt_select ON api.machine_tokens FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
DROP POLICY IF EXISTS mt_insert ON api.machine_tokens;
CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
DROP POLICY IF EXISTS mt_delete ON api.machine_tokens;
CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
  USING (api.can_write_project(project_id));

-- ── machine_token_scope: select (can_read_project), insert/delete (can_write_project)
DROP POLICY IF EXISTS mts_select ON api.machine_token_scope;
CREATE POLICY mts_select ON api.machine_token_scope FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_read_project(t.project_id)
    )
  );
DROP POLICY IF EXISTS mts_insert ON api.machine_token_scope;
CREATE POLICY mts_insert ON api.machine_token_scope FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_write_project(t.project_id)
    )
  );
DROP POLICY IF EXISTS mts_delete ON api.machine_token_scope;
CREATE POLICY mts_delete ON api.machine_token_scope FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_write_project(t.project_id)
    )
  );
