-- Secret Store schema: teams → projects → secrets + memberships, RLS for PostgREST
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS api;
CREATE SCHEMA IF NOT EXISTS private;

-- Roles
DO $$ BEGIN
  CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'authenticator';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE ROLE anon NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE ROLE authenticated NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

GRANT USAGE ON SCHEMA api TO anon, authenticated, authenticator;
GRANT anon, authenticated TO authenticator;
ALTER ROLE authenticator SET search_path TO api, public;
ALTER ROLE authenticated SET search_path TO api, public;

-- Users (private; auth via Flask — local password and/or LDAP)
CREATE TABLE private.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  password_hash text,  -- null for LDAP-only accounts
  name text NOT NULL DEFAULT '',
  is_global_admin boolean NOT NULL DEFAULT false,
  auth_source text NOT NULL DEFAULT 'local'
    CHECK (auth_source IN ('local', 'ldap')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Server-wide settings (classification banner, LDAP, etc.)
CREATE TABLE private.server_settings (
  key text PRIMARY KEY,
  value text NOT NULL DEFAULT ''
);

INSERT INTO private.server_settings (key, value) VALUES
  ('classification_enabled', 'false'),
  ('classification_text', 'OFFICIAL'),
  ('classification_color', '#677381'),
  ('classification_fg', '#ffffff'),
  ('registration_enabled', 'true'),
  ('user_team_creation_enabled', 'true'),
  ('ldap_enabled', 'false'),
  ('ldap_url', ''),
  ('ldap_start_tls', 'false'),
  ('ldap_bind_dn', ''),
  ('ldap_bind_password', ''),
  ('ldap_user_base', ''),
  ('ldap_user_filter', '(|(mail={login})(uid={login}))'),
  ('ldap_email_attr', 'mail'),
  ('ldap_name_attr', 'displayName'),
  ('ldap_group_base', ''),
  ('ldap_group_filter', '(member={dn})'),
  ('ldap_use_memberof', 'true')
ON CONFLICT (key) DO NOTHING;

-- LDAP group → server role (global admin only for now)
CREATE TABLE private.ldap_role_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ldap_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('global_admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ldap_group)
);

-- Teams
CREATE TABLE api.teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  created_by uuid REFERENCES private.users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api.team_members (
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap')),
  PRIMARY KEY (team_id, user_id)
);

-- Team owner rules: LDAP group → automatic team membership/role
CREATE TABLE api.team_ldap_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  ldap_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, ldap_group)
);

-- Projects (Bitwarden-style: access control surface)
CREATE TABLE api.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, name)
);

CREATE TABLE api.project_members (
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  PRIMARY KEY (project_id, user_id)
);

-- Secrets (value_enc = Fernet ciphertext from Flask)
-- Soft-delete via deleted_at; live rows unique on (project_id, key)
CREATE TABLE api.secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  key text NOT NULL,
  value_enc text NOT NULL,
  note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE UNIQUE INDEX secrets_project_key_live
  ON api.secrets (project_id, key) WHERE deleted_at IS NULL;

-- Secret audit log (create / update / reveal / delete / restore / purge)
CREATE TABLE api.secret_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  secret_id uuid,  -- may be null after permanent purge
  secret_key text NOT NULL DEFAULT '',
  user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
  actor_email text NOT NULL DEFAULT '',
  action text NOT NULL CHECK (action IN (
    'created', 'updated', 'revealed', 'deleted', 'restored', 'purged'
  )),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX secret_audit_project_created_idx
  ON api.secret_audit (project_id, created_at DESC);

-- Machine tokens (OpenShift ESO / external secrets)
CREATE TABLE api.machine_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_hash text NOT NULL,
  token_prefix text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Helpers: current user from JWT claim
CREATE OR REPLACE FUNCTION api.current_user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
$$;

-- Global admin: full access across teams/projects
CREATE OR REPLACE FUNCTION api.is_global_admin() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(
    (SELECT is_global_admin FROM private.users WHERE id = api.current_user_id()),
    false
  );
$$;

-- row_security=off: avoid RLS recursion inside policy helper functions
CREATE OR REPLACE FUNCTION api.is_team_member(tid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin() OR EXISTS (
    SELECT 1 FROM api.team_members
    WHERE team_id = tid AND user_id = api.current_user_id()
  );
$$;

CREATE OR REPLACE FUNCTION api.team_role(tid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN api.is_global_admin() THEN 'owner'
    ELSE (SELECT role FROM api.team_members
          WHERE team_id = tid AND user_id = api.current_user_id())
  END;
$$;

CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin() OR EXISTS (
    SELECT 1 FROM api.projects p
    JOIN api.team_members tm ON tm.team_id = p.team_id
    WHERE p.id = pid AND tm.user_id = api.current_user_id()
  ) OR EXISTS (
    SELECT 1 FROM api.project_members
    WHERE project_id = pid AND user_id = api.current_user_id()
  );
$$;

CREATE OR REPLACE FUNCTION api.can_write_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin() OR EXISTS (
    SELECT 1 FROM api.projects p
    JOIN api.team_members tm ON tm.team_id = p.team_id
    WHERE p.id = pid AND tm.user_id = api.current_user_id()
  ) OR EXISTS (
    SELECT 1 FROM api.project_members
    WHERE project_id = pid AND user_id = api.current_user_id()
      AND role IN ('admin', 'write')
  );
$$;

-- RLS
ALTER TABLE api.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_ldap_maps ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.project_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.machine_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
  USING (api.is_global_admin() OR api.is_team_member(id));
CREATE POLICY teams_insert ON api.teams FOR INSERT TO authenticated
  WITH CHECK (created_by = api.current_user_id() OR api.is_global_admin());
CREATE POLICY teams_update ON api.teams FOR UPDATE TO authenticated
  USING (api.team_role(id) IN ('owner', 'admin'));
CREATE POLICY teams_delete ON api.teams FOR DELETE TO authenticated
  USING (api.team_role(id) = 'owner');

CREATE POLICY tm_select ON api.team_members FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
CREATE POLICY tm_insert ON api.team_members FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin') OR user_id = api.current_user_id());
CREATE POLICY tm_update ON api.team_members FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY tm_delete ON api.team_members FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin') OR user_id = api.current_user_id());

CREATE POLICY tlm_select ON api.team_ldap_maps FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
CREATE POLICY tlm_insert ON api.team_ldap_maps FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY tlm_update ON api.team_ldap_maps FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY tlm_delete ON api.team_ldap_maps FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));

-- Use team_id on the row (not can_read_project(id)) so INSERT … RETURNING works
CREATE POLICY projects_select ON api.projects FOR SELECT TO authenticated
  USING (
    api.is_team_member(team_id)
    OR EXISTS (
      SELECT 1 FROM api.project_members pm
      WHERE pm.project_id = id AND pm.user_id = api.current_user_id()
    )
  );
CREATE POLICY projects_insert ON api.projects FOR INSERT TO authenticated
  WITH CHECK (api.is_team_member(team_id));
CREATE POLICY projects_update ON api.projects FOR UPDATE TO authenticated
  USING (api.is_team_member(team_id));
CREATE POLICY projects_delete ON api.projects FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));

CREATE POLICY pm_select ON api.project_members FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
CREATE POLICY pm_insert ON api.project_members FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
CREATE POLICY pm_delete ON api.project_members FOR DELETE TO authenticated
  USING (api.can_write_project(project_id));

CREATE POLICY secrets_select ON api.secrets FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
CREATE POLICY secrets_insert ON api.secrets FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
CREATE POLICY secrets_update ON api.secrets FOR UPDATE TO authenticated
  USING (api.can_write_project(project_id));
CREATE POLICY secrets_delete ON api.secrets FOR DELETE TO authenticated
  USING (api.can_write_project(project_id));

CREATE POLICY secret_audit_select ON api.secret_audit FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
CREATE POLICY secret_audit_insert ON api.secret_audit FOR INSERT TO authenticated
  WITH CHECK (api.can_read_project(project_id));

CREATE POLICY mt_select ON api.machine_tokens FOR SELECT TO authenticated
  USING (api.can_write_project(project_id));
CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
  USING (api.can_write_project(project_id));

-- Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA api TO authenticated;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA api TO authenticated, anon;

-- Auth helpers (SECURITY DEFINER; Flask/anon only)
CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
DECLARE first_user boolean;
BEGIN
  SELECT NOT EXISTS (SELECT 1 FROM private.users) INTO first_user;
  INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
  VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), first_user, 'local')
  RETURNING id INTO uid;
  RETURN uid;
END;
$$;

CREATE OR REPLACE FUNCTION private.verify_user(p_email text, p_password text)
RETURNS TABLE (id uuid, email text, name text, is_global_admin boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email, u.name, u.is_global_admin FROM private.users u
  WHERE u.email = lower(p_email)
    AND u.password_hash IS NOT NULL
    AND u.password_hash = crypt(p_password, u.password_hash);
END;
$$;

-- Provision / refresh LDAP user (no password stored)
CREATE OR REPLACE FUNCTION private.upsert_ldap_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
DECLARE first_user boolean;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    SELECT NOT EXISTS (SELECT 1 FROM private.users) INTO first_user;
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), first_user, 'ldap')
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = 'ldap'
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;

CREATE OR REPLACE FUNCTION private.create_team(p_user uuid, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private AS $$
DECLARE tid uuid;
BEGIN
  INSERT INTO api.teams (name, created_by) VALUES (p_name, p_user) RETURNING id INTO tid;
  INSERT INTO api.team_members (team_id, user_id, role) VALUES (tid, p_user, 'owner');
  RETURN tid;
END;
$$;

-- Public user directory for membership UI (no password_hash)
CREATE OR REPLACE VIEW api.user_directory AS
  SELECT id, email, name, is_global_admin, created_at FROM private.users;
GRANT SELECT ON api.user_directory TO authenticated;

-- Machine/ESO helpers (bypass RLS; token hash is the gate)
CREATE OR REPLACE FUNCTION private.auth_machine(p_project uuid, p_hash text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
  SELECT EXISTS (
    SELECT 1 FROM api.machine_tokens
    WHERE project_id = p_project AND token_hash = p_hash
  );
$$;

CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN NULL;
  END IF;
  RETURN (
    SELECT value_enc FROM api.secrets
    WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
  );
END;
$$;

CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
RETURNS TABLE (key text, value_enc text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.key, s.value_enc FROM api.secrets s
    WHERE s.project_id = p_project AND s.deleted_at IS NULL;
END;
$$;

GRANT USAGE ON SCHEMA private TO authenticator;
GRANT EXECUTE ON FUNCTION private.register_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.upsert_ldap_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.create_team TO authenticator;
GRANT EXECUTE ON FUNCTION private.auth_machine TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_enc TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_enc TO authenticator;
GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon;

-- PostgREST needs table privileges via authenticator switching roles
GRANT ALL ON ALL TABLES IN SCHEMA api TO authenticator;
GRANT USAGE ON SCHEMA private TO authenticated;

COMMENT ON SCHEMA api IS 'PostgREST + RLS secret store';
