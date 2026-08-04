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

-- Users (private; auth via Flask)
CREATE TABLE private.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  name text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
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
  PRIMARY KEY (team_id, user_id)
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
CREATE TABLE api.secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  key text NOT NULL,
  value_enc text NOT NULL,
  note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, key)
);

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

-- row_security=off: avoid RLS recursion inside policy helper functions
CREATE OR REPLACE FUNCTION api.is_team_member(tid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT EXISTS (
    SELECT 1 FROM api.team_members
    WHERE team_id = tid AND user_id = api.current_user_id()
  );
$$;

CREATE OR REPLACE FUNCTION api.team_role(tid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT role FROM api.team_members
  WHERE team_id = tid AND user_id = api.current_user_id();
$$;

CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT EXISTS (
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
  SELECT EXISTS (
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
ALTER TABLE api.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.project_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.machine_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
  USING (api.is_team_member(id));
CREATE POLICY teams_insert ON api.teams FOR INSERT TO authenticated
  WITH CHECK (created_by = api.current_user_id());
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
BEGIN
  INSERT INTO private.users (email, password_hash, name)
  VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''))
  RETURNING id INTO uid;
  RETURN uid;
END;
$$;

CREATE OR REPLACE FUNCTION private.verify_user(p_email text, p_password text)
RETURNS TABLE (id uuid, email text, name text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email, u.name FROM private.users u
  WHERE u.email = lower(p_email) AND u.password_hash = crypt(p_password, u.password_hash);
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
  SELECT id, email, name, created_at FROM private.users;
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
  RETURN (SELECT value_enc FROM api.secrets WHERE project_id = p_project AND key = p_key);
END;
$$;

CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
RETURNS TABLE (key text, value_enc text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT s.key, s.value_enc FROM api.secrets s WHERE s.project_id = p_project;
END;
$$;

GRANT USAGE ON SCHEMA private TO authenticator;
GRANT EXECUTE ON FUNCTION private.register_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.create_team TO authenticator;
GRANT EXECUTE ON FUNCTION private.auth_machine TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_enc TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_enc TO authenticator;

-- PostgREST needs table privileges via authenticator switching roles
GRANT ALL ON ALL TABLES IN SCHEMA api TO authenticator;
GRANT USAGE ON SCHEMA private TO authenticated;

COMMENT ON SCHEMA api IS 'PostgREST + RLS secret store';
