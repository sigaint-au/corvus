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
    CHECK (auth_source IN ('local', 'ldap', 'oidc')),
  totp_secret_enc text,          -- Fernet-encrypted TOTP secret when 2FA enabled
  totp_enabled_at timestamptz,   -- null = 2FA off
  disabled_at timestamptz,       -- null = active; set by global admin
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One-time recovery codes (hashed) for TOTP lockout bypass
CREATE TABLE private.totp_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX totp_recovery_codes_user_idx
  ON private.totp_recovery_codes (user_id)
  WHERE used_at IS NULL;

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
  ('ldap_use_memberof', 'true'),
  ('smtp_enabled', 'false'),
  ('smtp_host', ''),
  ('smtp_port', '587'),
  ('smtp_encryption', 'starttls'),
  ('smtp_username', ''),
  ('smtp_password', ''),
  ('smtp_from_email', ''),
  ('smtp_from_name', 'Sigaint Secret Server'),
  ('smtp_login_alerts', 'false'),
  ('totp_enforce_global_admins', 'false')
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
  created_at timestamptz NOT NULL DEFAULT now(),
  -- Team-level defaults / overrides (null = use server default)
  default_token_days int CHECK (
    default_token_days IS NULL OR (default_token_days > 0 AND default_token_days <= 3650)
  ),
  classification_enabled boolean,
  classification_text text NOT NULL DEFAULT '',
  classification_color text NOT NULL DEFAULT '',
  classification_fg text NOT NULL DEFAULT ''
);

CREATE TABLE api.team_members (
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap', 'oidc')),
  PRIMARY KEY (team_id, user_id)
);

-- Team owner rules: LDAP group → automatic team membership/role
CREATE TABLE api.team_ldap_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  ldap_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, ldap_group)
);

-- Invite links (share token; redeem creates a pending join request)
CREATE TABLE api.team_invites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'member'
    CHECK (role IN ('admin', 'member', 'viewer')),
  expires_at timestamptz NOT NULL,
  created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX team_invites_team_idx ON api.team_invites (team_id) WHERE revoked_at IS NULL;

-- Pending self-service join requests (via invite link)
CREATE TABLE api.team_join_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  invite_id uuid REFERENCES api.team_invites(id) ON DELETE SET NULL,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member'
    CHECK (role IN ('admin', 'member', 'viewer')),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolved_by uuid REFERENCES private.users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX team_join_requests_pending_uidx
  ON api.team_join_requests (team_id, user_id) WHERE status = 'pending';

-- Projects (Bitwarden-style: access control surface)
CREATE TABLE api.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  -- When true, secrets inherit require-approval for reveal (unless per-secret override)
  require_reveal_approval boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, name)
);

CREATE TABLE api.project_members (
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  PRIMARY KEY (project_id, user_id)
);

-- Team-scoped groups (manual members and/or LDAP/OIDC external_key mapping)
CREATE TABLE api.groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  name text NOT NULL,
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap', 'oidc')),
  -- When source is ldap/oidc, directory group token (DN/CN/claim) for membership sync
  external_key text,
  -- If set, group members receive this team role (max with direct team_members)
  -- No 'owner': groups must not create team owners (break-glass stays direct members)
  team_role text CHECK (
    team_role IS NULL OR team_role IN ('admin', 'member', 'viewer')
  ),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, name)
);
CREATE UNIQUE INDEX groups_external_key_uidx
  ON api.groups (team_id, source, external_key)
  WHERE external_key IS NOT NULL AND source IN ('ldap', 'oidc');

CREATE TABLE api.group_members (
  group_id uuid NOT NULL REFERENCES api.groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap', 'oidc')),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON api.group_members (user_id);

-- Group → project role (group must belong to the project's team; enforced in app)
CREATE TABLE api.project_group_roles (
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  group_id uuid NOT NULL REFERENCES api.groups(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('admin', 'write', 'read')),
  PRIMARY KEY (project_id, group_id)
);

-- Membership / settings / access-control audit (not secret values)
CREATE TABLE api.org_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES api.teams(id) ON DELETE CASCADE,
  project_id uuid REFERENCES api.projects(id) ON DELETE CASCADE,
  action text NOT NULL,
  detail text NOT NULL DEFAULT '',
  user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
  actor_email text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX org_audit_team_created_idx ON api.org_audit (team_id, created_at DESC);
CREATE INDEX org_audit_project_created_idx ON api.org_audit (project_id, created_at DESC);

-- Secrets (value_enc = Fernet ciphertext from Flask)
-- note is intentional plaintext (labels/search only — do not store secrets there)
-- Soft-delete via deleted_at; live rows unique on (project_id, key)
CREATE TABLE api.secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  key text NOT NULL,
  value_enc text NOT NULL,
  note text NOT NULL DEFAULT '',  -- non-sensitive; not encrypted
  kind text NOT NULL DEFAULT 'plain'
    CHECK (kind IN ('plain', 'database', 'certificate', 'ssh', 'kv')),
  expires_at timestamptz,        -- hard expiry (optional)
  -- NULL = inherit project.require_reveal_approval; true/false = override
  requires_approval boolean,
  -- Per-secret access tighter than project membership (see api.can_access_secret)
  acl_mode text NOT NULL DEFAULT 'inherit'
    CHECK (acl_mode IN ('inherit', 'writers', 'admins', 'owners', 'custom')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE UNIQUE INDEX secrets_project_key_live
  ON api.secrets (project_id, key) WHERE deleted_at IS NULL;

-- Explicit per-user or per-group grants when secrets.acl_mode = 'custom'
CREATE TABLE api.secret_acl (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  user_id uuid REFERENCES private.users(id) ON DELETE CASCADE,
  group_id uuid REFERENCES api.groups(id) ON DELETE CASCADE,
  -- read < reveal < write (write implies reveal + read)
  permission text NOT NULL DEFAULT 'reveal'
    CHECK (permission IN ('read', 'reveal', 'write')),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  CHECK (
    (user_id IS NOT NULL AND group_id IS NULL)
    OR (user_id IS NULL AND group_id IS NOT NULL)
  )
);
CREATE UNIQUE INDEX secret_acl_user_uidx
  ON api.secret_acl (secret_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX secret_acl_group_uidx
  ON api.secret_acl (secret_id, group_id) WHERE group_id IS NOT NULL;
CREATE INDEX secret_acl_user_idx ON api.secret_acl (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX secret_acl_group_idx ON api.secret_acl (group_id) WHERE group_id IS NOT NULL;


-- Per-user pins (favorites) and recently accessed secrets
CREATE TABLE api.secret_pins (
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, secret_id)
);

CREATE TABLE api.secret_recent (
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  accessed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, secret_id)
);
CREATE INDEX secret_recent_user_accessed_idx
  ON api.secret_recent (user_id, accessed_at DESC);

-- Prior value_enc snapshots on update (trigger-filled; human + machine paths)
CREATE TABLE api.secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  value_enc text NOT NULL,
  note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()  -- when this version was superseded
);
CREATE INDEX secret_versions_secret_created_idx
  ON api.secret_versions (secret_id, created_at DESC);

-- Keep updated_at current on any row change (app code should not set it manually)
CREATE OR REPLACE FUNCTION api.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
CREATE TRIGGER secrets_touch_updated_at
  BEFORE UPDATE ON api.secrets
  FOR EACH ROW EXECUTE FUNCTION api.touch_updated_at();

-- Archive previous ciphertext when value changes
CREATE OR REPLACE FUNCTION api.archive_secret_version()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.value_enc IS DISTINCT FROM NEW.value_enc THEN
    INSERT INTO api.secret_versions (secret_id, value_enc, note)
    VALUES (OLD.id, OLD.value_enc, OLD.note);
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER secrets_archive_version
  BEFORE UPDATE ON api.secrets
  FOR EACH ROW EXECUTE FUNCTION api.archive_secret_version();

-- Secret audit log (create / update / reveal / delete / restore / purge / machine_upsert)
CREATE TABLE api.secret_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  secret_id uuid,  -- may be null after permanent purge
  secret_key text NOT NULL DEFAULT '',
  user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
  actor_email text NOT NULL DEFAULT '',
  action text NOT NULL CHECK (action IN (
    'created', 'updated', 'revealed', 'deleted', 'restored', 'purged',
    'machine_upsert', 'exported',
    'access_requested', 'access_approved', 'access_denied'
  )),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX secret_audit_project_created_idx
  ON api.secret_audit (project_id, created_at DESC);

-- Reveal access approval (non-admins request; project admin / team owner approve)
CREATE TABLE api.secret_access_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied')),
  reason text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolved_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  approved_until timestamptz
);
CREATE UNIQUE INDEX secret_access_requests_pending_uidx
  ON api.secret_access_requests (secret_id, user_id) WHERE status = 'pending';
CREATE INDEX secret_access_requests_project_status_idx
  ON api.secret_access_requests (project_id, status, created_at DESC);
CREATE INDEX secret_access_requests_grant_idx
  ON api.secret_access_requests (secret_id, user_id, approved_until)
  WHERE status = 'approved';

-- Machine tokens / accounts (OpenShift ESO / CI)
-- role: read-only = ESO fetch only; write = fetch + machine upsert API
CREATE TABLE api.machine_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_hash text NOT NULL,
  token_prefix text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'read-only'
    CHECK (role IN ('read-only', 'write')),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Login failure throttle (Flask app; shared across workers)
CREATE TABLE private.login_failures (
  id bigserial PRIMARY KEY,
  email text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_email_created_idx
  ON private.login_failures (email, created_at);

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
CREATE OR REPLACE FUNCTION api._role_rank(r text) RETURNS int
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE r
    WHEN 'owner' THEN 4
    WHEN 'admin' THEN 3
    WHEN 'member' THEN 2
    WHEN 'write' THEN 2
    WHEN 'viewer' THEN 1
    WHEN 'read' THEN 1
    ELSE 0
  END;
$$;

CREATE OR REPLACE FUNCTION api._perm_rank(p text) RETURNS int
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p
    WHEN 'read' THEN 1
    WHEN 'reveal' THEN 2
    WHEN 'write' THEN 3
    ELSE 0
  END;
$$;

CREATE OR REPLACE FUNCTION api.is_team_member(tid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin()
    OR EXISTS (
      SELECT 1 FROM api.team_members
      WHERE team_id = tid AND user_id = api.current_user_id()
    )
    OR EXISTS (
      SELECT 1 FROM api.group_members gm
      JOIN api.groups g ON g.id = gm.group_id
      WHERE g.team_id = tid
        AND gm.user_id = api.current_user_id()
        AND g.team_role IS NOT NULL
    );
$$;

CREATE OR REPLACE FUNCTION api.team_role(tid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN api.is_global_admin() THEN 'owner'
    ELSE (
      SELECT r FROM (
        SELECT tm.role AS r, api._role_rank(tm.role) AS rank
        FROM api.team_members tm
        WHERE tm.team_id = tid AND tm.user_id = api.current_user_id()
        UNION ALL
        SELECT g.team_role, api._role_rank(g.team_role)
        FROM api.group_members gm
        JOIN api.groups g ON g.id = gm.group_id
        WHERE g.team_id = tid
          AND gm.user_id = api.current_user_id()
          AND g.team_role IS NOT NULL
      ) x
      ORDER BY rank DESC
      LIMIT 1
    )
  END;
$$;

-- Highest project-level role from direct membership or group grants (null if none)
CREATE OR REPLACE FUNCTION api.project_role(pid uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT r FROM (
    SELECT pm.role AS r, api._role_rank(pm.role) AS rank
    FROM api.project_members pm
    WHERE pm.project_id = pid AND pm.user_id = api.current_user_id()
    UNION ALL
    SELECT pgr.role, api._role_rank(pgr.role)
    FROM api.project_group_roles pgr
    JOIN api.group_members gm ON gm.group_id = pgr.group_id
    WHERE pgr.project_id = pid AND gm.user_id = api.current_user_id()
  ) x
  ORDER BY rank DESC
  LIMIT 1;
$$;

-- Project access: project-level role (user or group) when present; else team role.
-- Team owner/admin always keep admin/write (cannot demote via project grants).
CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin()
    OR api.project_role(pid) IS NOT NULL
    OR EXISTS (
      SELECT 1 FROM api.projects p
      WHERE p.id = pid AND api.is_team_member(p.team_id)
    );
$$;

CREATE OR REPLACE FUNCTION api.can_write_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin()
    OR api.team_role((SELECT team_id FROM api.projects WHERE id = pid))
         IN ('owner', 'admin')
    OR api.project_role(pid) IN ('admin', 'write')
    OR (
      api.project_role(pid) IS NULL
      AND api.team_role((SELECT team_id FROM api.projects WHERE id = pid)) = 'member'
    );
$$;

CREATE OR REPLACE FUNCTION api.can_admin_project(pid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT api.is_global_admin()
    OR api.team_role((SELECT team_id FROM api.projects WHERE id = pid))
         IN ('owner', 'admin')
    OR api.project_role(pid) = 'admin';
$$;

-- Per-secret access using row fields (safe for INSERT … RETURNING RLS).
-- Do not re-query api.secrets here — the new row is not visible mid-insert.
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
    WHEN NOT api.can_read_project(pid) THEN false
    WHEN api.can_admin_project(pid) THEN true
    WHEN COALESCE(mode, 'inherit') = 'inherit' THEN (
      CASE need
        WHEN 'write' THEN api.can_write_project(pid)
        ELSE true
      END
    )
    WHEN mode = 'writers' THEN api.can_write_project(pid)
    WHEN mode = 'admins' THEN false
    WHEN mode = 'owners' THEN (
      api.team_role((SELECT team_id FROM api.projects WHERE id = pid)) = 'owner'
    )
    WHEN mode = 'custom' THEN EXISTS (
      SELECT 1 FROM api.secret_acl a
      WHERE a.secret_id = sid
        AND api._perm_rank(a.permission) >= api._perm_rank(need)
        AND (
          a.user_id = api.current_user_id()
          OR EXISTS (
            SELECT 1 FROM api.group_members gm
            WHERE gm.group_id = a.group_id
              AND gm.user_id = api.current_user_id()
          )
        )
    )
    ELSE false
  END;
$$;

-- App-facing helper: load the secret row then apply can_access_secret_row
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

-- Prevent removing the last team owner (except when the team itself is deleted)
CREATE OR REPLACE FUNCTION api.guard_last_team_owner()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE remaining int;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.role = 'owner' THEN
      -- ON DELETE CASCADE from api.teams runs after the team row is gone; allow that.
      IF NOT EXISTS (SELECT 1 FROM api.teams WHERE id = OLD.team_id) THEN
        RETURN OLD;
      END IF;
      SELECT count(*) INTO remaining FROM api.team_members
      WHERE team_id = OLD.team_id AND role = 'owner' AND user_id <> OLD.user_id;
      IF remaining = 0 THEN
        RAISE EXCEPTION 'cannot remove the last team owner; transfer ownership first';
      END IF;
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.role = 'owner' AND NEW.role IS DISTINCT FROM 'owner' THEN
      SELECT count(*) INTO remaining FROM api.team_members
      WHERE team_id = OLD.team_id AND role = 'owner' AND user_id <> OLD.user_id;
      IF remaining = 0 THEN
        RAISE EXCEPTION 'cannot demote the last team owner; transfer ownership first';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER team_members_guard_last_owner
  BEFORE UPDATE OR DELETE ON api.team_members
  FOR EACH ROW EXECUTE FUNCTION api.guard_last_team_owner();

-- RLS
ALTER TABLE api.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_ldap_maps ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_join_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.project_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.project_group_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_recent ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.org_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_acl ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_access_requests ENABLE ROW LEVEL SECURITY;
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
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'));
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

CREATE POLICY team_invites_select ON api.team_invites FOR SELECT TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY team_invites_insert ON api.team_invites FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY team_invites_update ON api.team_invites FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY team_invites_delete ON api.team_invites FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));

CREATE POLICY team_join_requests_select ON api.team_join_requests FOR SELECT TO authenticated
  USING (
    api.team_role(team_id) IN ('owner', 'admin')
    OR user_id = api.current_user_id()
  );
CREATE POLICY team_join_requests_insert ON api.team_join_requests FOR INSERT TO authenticated
  WITH CHECK (user_id = api.current_user_id());
CREATE POLICY team_join_requests_update ON api.team_join_requests FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));

CREATE POLICY org_audit_select ON api.org_audit FOR SELECT TO authenticated
  USING (
    (team_id IS NOT NULL AND api.is_team_member(team_id))
    OR (project_id IS NOT NULL AND api.can_read_project(project_id))
  );
-- INSERT only via private.audit_org

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
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin', 'member'));
CREATE POLICY projects_update ON api.projects FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin', 'member'));
CREATE POLICY projects_delete ON api.projects FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));

CREATE POLICY pm_select ON api.project_members FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
CREATE POLICY pm_insert ON api.project_members FOR INSERT TO authenticated
  WITH CHECK (api.can_admin_project(project_id));
CREATE POLICY pm_update ON api.project_members FOR UPDATE TO authenticated
  USING (api.can_admin_project(project_id));
CREATE POLICY pm_delete ON api.project_members FOR DELETE TO authenticated
  USING (api.can_admin_project(project_id));

-- Pins / recent: own rows only, and only if secret is still readable
CREATE POLICY secret_pins_select ON api.secret_pins FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
CREATE POLICY secret_pins_delete ON api.secret_pins FOR DELETE TO authenticated
  USING (user_id = api.current_user_id());

CREATE POLICY secret_recent_select ON api.secret_recent FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_read_project(s.project_id)
    )
  );
CREATE POLICY secret_recent_update ON api.secret_recent FOR UPDATE TO authenticated
  USING (user_id = api.current_user_id());
CREATE POLICY secret_recent_delete ON api.secret_recent FOR DELETE TO authenticated
  USING (user_id = api.current_user_id());

CREATE POLICY secrets_select ON api.secrets FOR SELECT TO authenticated
  USING (api.can_access_secret_row(id, project_id, acl_mode, 'read', deleted_at));
CREATE POLICY secrets_insert ON api.secrets FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
CREATE POLICY secrets_update ON api.secrets FOR UPDATE TO authenticated
  USING (api.can_access_secret_row(id, project_id, acl_mode, 'write', deleted_at));
CREATE POLICY secrets_delete ON api.secrets FOR DELETE TO authenticated
  USING (api.can_access_secret_row(id, project_id, acl_mode, 'write', deleted_at));

-- Versions inherit access from parent secret's project
CREATE POLICY secret_versions_select ON api.secret_versions FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id
        AND api.can_access_secret_row(
          s.id, s.project_id, s.acl_mode, 'read', s.deleted_at
        )
    )
  );
CREATE POLICY secret_versions_insert ON api.secret_versions FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id
        AND api.can_access_secret_row(
          s.id, s.project_id, s.acl_mode, 'write', s.deleted_at
        )
    )
  );
-- No direct UPDATE/DELETE for authenticated (purge via secret CASCADE)

CREATE POLICY secret_audit_select ON api.secret_audit FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
-- INSERT only via private.audit_secret (SECURITY DEFINER); no direct client insert

CREATE POLICY groups_select ON api.groups FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
CREATE POLICY groups_insert ON api.groups FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY groups_update ON api.groups FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY groups_delete ON api.groups FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));

CREATE POLICY gm_select ON api.group_members FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.is_team_member(g.team_id)
    )
  );
CREATE POLICY gm_insert ON api.group_members FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.team_role(g.team_id) IN ('owner', 'admin')
    )
  );
CREATE POLICY gm_update ON api.group_members FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.team_role(g.team_id) IN ('owner', 'admin')
    )
  );
CREATE POLICY gm_delete ON api.group_members FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.groups g
      WHERE g.id = group_id AND api.team_role(g.team_id) IN ('owner', 'admin')
    )
    OR user_id = api.current_user_id()
  );

CREATE POLICY pgr_select ON api.project_group_roles FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
CREATE POLICY pgr_insert ON api.project_group_roles FOR INSERT TO authenticated
  WITH CHECK (api.can_admin_project(project_id));
CREATE POLICY pgr_update ON api.project_group_roles FOR UPDATE TO authenticated
  USING (api.can_admin_project(project_id));
CREATE POLICY pgr_delete ON api.project_group_roles FOR DELETE TO authenticated
  USING (api.can_admin_project(project_id));

CREATE POLICY secret_acl_select ON api.secret_acl FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id
        AND api.can_access_secret_row(
          s.id, s.project_id, s.acl_mode, 'read', s.deleted_at
        )
    )
  );
CREATE POLICY secret_acl_insert ON api.secret_acl FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND api.can_admin_project(s.project_id)
    )
  );
CREATE POLICY secret_acl_update ON api.secret_acl FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND api.can_admin_project(s.project_id)
    )
  );
CREATE POLICY secret_acl_delete ON api.secret_acl FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND api.can_admin_project(s.project_id)
    )
  );

CREATE POLICY secret_access_requests_select ON api.secret_access_requests
  FOR SELECT TO authenticated
  USING (
    api.can_admin_project(project_id)
    OR user_id = api.current_user_id()
  );
CREATE POLICY secret_access_requests_insert ON api.secret_access_requests
  FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND api.can_read_project(project_id)
  );
CREATE POLICY secret_access_requests_update ON api.secret_access_requests
  FOR UPDATE TO authenticated
  USING (api.can_admin_project(project_id));

-- read-only may list tokens (name/prefix/expiry); only writers create/revoke
CREATE POLICY mt_select ON api.machine_tokens FOR SELECT TO authenticated
  USING (api.can_read_project(project_id));
CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
  WITH CHECK (api.can_write_project(project_id));
CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
  USING (api.can_write_project(project_id));

-- Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA api TO authenticated;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA api TO authenticated, anon;
-- Audit rows must not be forgeable via PostgREST / authenticated INSERT
REVOKE INSERT ON api.secret_audit FROM authenticated;
REVOKE INSERT ON api.org_audit FROM authenticated;
-- Access requests: no client DELETE (resolve via UPDATE)
REVOKE DELETE ON api.secret_access_requests FROM authenticated;

-- Auth helpers (SECURITY DEFINER; Flask/anon only)
-- Never auto-promote first registrant; GLOBAL_ADMIN_EMAIL / BOOTSTRAP_ADMIN_EMAIL does that in app.
CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
  VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), false, 'local')
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
    AND u.disabled_at IS NULL
    AND u.password_hash = crypt(p_password, u.password_hash);
END;
$$;

-- Change password (local accounts only; requires current password)
CREATE OR REPLACE FUNCTION private.change_password(
  p_user uuid, p_old text, p_new text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  IF p_new IS NULL OR length(p_new) < 8 THEN
    RAISE EXCEPTION 'password must be at least 8 characters';
  END IF;
  UPDATE private.users
  SET password_hash = crypt(p_new, gen_salt('bf'))
  WHERE id = p_user
    AND auth_source = 'local'
    AND password_hash IS NOT NULL
    AND password_hash = crypt(p_old, password_hash);
  RETURN FOUND;
END;
$$;

-- Set password after verified reset (local accounts only)
CREATE OR REPLACE FUNCTION private.set_local_password(p_user uuid, p_new text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  IF p_new IS NULL OR length(p_new) < 8 THEN
    RAISE EXCEPTION 'password must be at least 8 characters';
  END IF;
  UPDATE private.users
  SET password_hash = crypt(p_new, gen_salt('bf'))
  WHERE id = p_user
    AND auth_source = 'local'
    AND password_hash IS NOT NULL;
  RETURN FOUND;
END;
$$;

-- Server-side browser sessions (for multi-device sign-out)
CREATE TABLE private.user_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  user_agent text NOT NULL DEFAULT '',
  ip text NOT NULL DEFAULT ''
);
CREATE INDEX user_sessions_user_active_idx
  ON private.user_sessions (user_id, last_seen_at DESC)
  WHERE revoked_at IS NULL;

-- One-time password reset tokens (store only hash)
CREATE TABLE private.password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_user_idx
  ON private.password_reset_tokens (user_id)
  WHERE used_at IS NULL;

-- Provision / refresh LDAP user (no password stored; never auto-promote admin)
CREATE OR REPLACE FUNCTION private.upsert_ldap_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'ldap')
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

-- Provision / refresh OIDC SSO user (no password stored)
CREATE OR REPLACE FUNCTION private.upsert_oidc_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'oidc')
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = CASE
          WHEN auth_source = 'local' AND password_hash IS NOT NULL THEN auth_source
          ELSE 'oidc'
        END
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;

-- Global role maps from OIDC groups
CREATE TABLE private.oidc_role_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oidc_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('global_admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (oidc_group)
);

-- Team membership maps from OIDC groups
CREATE TABLE api.team_oidc_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  oidc_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, oidc_group)
);
ALTER TABLE api.team_oidc_maps ENABLE ROW LEVEL SECURITY;
CREATE POLICY tom_select ON api.team_oidc_maps FOR SELECT TO authenticated
  USING (api.is_team_member(team_id));
CREATE POLICY tom_insert ON api.team_oidc_maps FOR INSERT TO authenticated
  WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY tom_update ON api.team_oidc_maps FOR UPDATE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
CREATE POLICY tom_delete ON api.team_oidc_maps FOR DELETE TO authenticated
  USING (api.team_role(team_id) IN ('owner', 'admin'));
GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_oidc_maps TO authenticated;
GRANT ALL ON api.team_oidc_maps TO authenticator;

-- Personal access tokens (user-scoped)
CREATE TABLE private.personal_access_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX personal_access_tokens_user_idx
  ON private.personal_access_tokens (user_id, created_at DESC);

CREATE OR REPLACE FUNCTION private.create_team(p_user uuid, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private AS $$
DECLARE tid uuid;
BEGIN
  INSERT INTO api.teams (name, created_by) VALUES (p_name, p_user) RETURNING id INTO tid;
  INSERT INTO api.team_members (team_id, user_id, role) VALUES (tid, p_user, 'owner');
  RETURN tid;
END;
$$;

-- User directory: not granted to authenticated (prevents full-user enumeration via PostgREST)
CREATE OR REPLACE VIEW api.user_directory AS
  SELECT id, email, name, is_global_admin, created_at FROM private.users;
-- Global admin / app admin path only
GRANT SELECT ON api.user_directory TO authenticator;

-- Lookup by email for add-member (does not list all users)
CREATE OR REPLACE FUNCTION private.lookup_user(p_email text)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = private
SET row_security = off AS $$
  SELECT id FROM private.users WHERE email = lower(p_email) LIMIT 1;
$$;

-- Team member listing with emails (caller must be a team member / global admin)
CREATE OR REPLACE FUNCTION private.team_member_rows(p_team uuid)
RETURNS TABLE (role text, source text, user_id uuid, email text, name text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT tm.role, tm.source, u.id, u.email, u.name
  FROM api.team_members tm
  JOIN private.users u ON u.id = tm.user_id
  WHERE tm.team_id = p_team
    AND api.is_team_member(p_team)
  ORDER BY tm.role, u.email;
$$;

-- Project-level members with emails
CREATE OR REPLACE FUNCTION private.project_member_rows(p_project uuid)
RETURNS TABLE (role text, user_id uuid, email text, name text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT pm.role, u.id, u.email, u.name
  FROM api.project_members pm
  JOIN private.users u ON u.id = pm.user_id
  WHERE pm.project_id = p_project
    AND api.can_read_project(p_project)
  ORDER BY pm.role, u.email;
$$;

-- Team groups listing
CREATE OR REPLACE FUNCTION private.team_group_rows(p_team uuid)
RETURNS TABLE (
  id uuid,
  name text,
  source text,
  external_key text,
  team_role text,
  member_count bigint,
  created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT g.id, g.name, g.source, g.external_key, g.team_role,
         (SELECT count(*) FROM api.group_members gm WHERE gm.group_id = g.id),
         g.created_at
  FROM api.groups g
  WHERE g.team_id = p_team
    AND api.is_team_member(p_team)
  ORDER BY g.name;
$$;

CREATE OR REPLACE FUNCTION private.group_member_rows(p_group uuid)
RETURNS TABLE (user_id uuid, email text, name text, source text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT u.id, u.email, u.name, gm.source
  FROM api.group_members gm
  JOIN private.users u ON u.id = gm.user_id
  JOIN api.groups g ON g.id = gm.group_id
  WHERE gm.group_id = p_group
    AND api.is_team_member(g.team_id)
  ORDER BY u.email;
$$;

CREATE OR REPLACE FUNCTION private.project_group_role_rows(p_project uuid)
RETURNS TABLE (
  group_id uuid,
  group_name text,
  role text,
  source text
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT g.id, g.name, pgr.role, g.source
  FROM api.project_group_roles pgr
  JOIN api.groups g ON g.id = pgr.group_id
  WHERE pgr.project_id = p_project
    AND api.can_read_project(p_project)
  ORDER BY g.name;
$$;

-- Per-secret ACL rows (user and/or group grants)
CREATE OR REPLACE FUNCTION private.secret_acl_rows(p_secret uuid)
RETURNS TABLE (
  id uuid,
  user_id uuid,
  group_id uuid,
  email text,
  name text,
  group_name text,
  permission text,
  created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT a.id, a.user_id, a.group_id,
         COALESCE(u.email, ''),
         COALESCE(u.name, ''),
         COALESCE(g.name, ''),
         a.permission, a.created_at
  FROM api.secret_acl a
  JOIN api.secrets s ON s.id = a.secret_id
  LEFT JOIN private.users u ON u.id = a.user_id
  LEFT JOIN api.groups g ON g.id = a.group_id
  WHERE a.secret_id = p_secret
    AND (
      api.can_admin_project(s.project_id)
      OR a.user_id = api.current_user_id()
      OR EXISTS (
        SELECT 1 FROM api.group_members gm
        WHERE gm.group_id = a.group_id
          AND gm.user_id = api.current_user_id()
      )
    )
  ORDER BY COALESCE(u.email, g.name);
$$;

-- Org / membership audit insert (JWT actor only)
CREATE OR REPLACE FUNCTION private.audit_org(
  p_team uuid,
  p_project uuid,
  p_action text,
  p_detail text DEFAULT '',
  p_actor_email text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private AS $$
DECLARE
  uid uuid;
  email text;
BEGIN
  IF p_action IS NULL OR btrim(p_action) = '' THEN
    RAISE EXCEPTION 'invalid org audit action';
  END IF;
  BEGIN
    uid := NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
  EXCEPTION WHEN others THEN
    uid := NULL;
  END;
  email := COALESCE(
    (SELECT u.email FROM private.users u WHERE u.id = uid),
    NULLIF(p_actor_email, ''),
    ''
  );
  INSERT INTO api.org_audit (team_id, project_id, action, detail, user_id, actor_email)
  VALUES (p_team, p_project, p_action, COALESCE(p_detail, ''), uid, email);
END;
$$;

-- Resolve invite token → team (SECURITY DEFINER; hash is the gate)
CREATE OR REPLACE FUNCTION private.lookup_invite(p_hash text)
RETURNS TABLE (
  invite_id uuid, team_id uuid, team_name text, role text, expires_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT i.id, i.team_id, t.name, i.role, i.expires_at
  FROM api.team_invites i
  JOIN api.teams t ON t.id = i.team_id
  WHERE i.token_hash = p_hash
    AND i.revoked_at IS NULL
    AND i.expires_at > now()
  LIMIT 1;
$$;

-- Audit insert only via this function (not direct table INSERT for authenticated).
-- p_user_id is ignored: actor is always taken from JWT claims (defense-in-depth
-- against forged attribution if this function is ever exposed). Machine/system
-- callers with no JWT leave user_id NULL and may set p_actor_email (e.g. 'machine').
CREATE OR REPLACE FUNCTION private.audit_secret(
  p_project uuid,
  p_secret_id uuid,
  p_secret_key text,
  p_action text,
  p_user_id uuid DEFAULT NULL,
  p_actor_email text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private AS $$
DECLARE
  uid uuid;
  email text;
BEGIN
  IF p_action NOT IN (
    'created', 'updated', 'revealed', 'deleted', 'restored', 'purged',
    'machine_upsert', 'exported',
    'access_requested', 'access_approved', 'access_denied'
  ) THEN
    RAISE EXCEPTION 'invalid audit action: %', p_action;
  END IF;
  -- Never trust caller-supplied p_user_id
  BEGIN
    uid := NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
  EXCEPTION WHEN others THEN
    uid := NULL;
  END;
  email := COALESCE(
    (SELECT u.email FROM private.users u WHERE u.id = uid),
    NULLIF(p_actor_email, ''),
    ''
  );
  INSERT INTO api.secret_audit (project_id, secret_id, secret_key, user_id, actor_email, action)
  VALUES (p_project, p_secret_id, COALESCE(p_secret_key, ''), uid, email, p_action);
END;
$$;

-- Machine/ESO helpers (bypass RLS; token hash is the gate)
CREATE OR REPLACE FUNCTION private.auth_machine(p_project uuid, p_hash text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
  SELECT EXISTS (
    SELECT 1 FROM api.machine_tokens
    WHERE project_id = p_project AND token_hash = p_hash
      AND (expires_at IS NULL OR expires_at > now())
  );
$$;

CREATE OR REPLACE FUNCTION private.machine_role(p_project uuid, p_hash text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
  SELECT role FROM api.machine_tokens
  WHERE project_id = p_project AND token_hash = p_hash
    AND (expires_at IS NULL OR expires_at > now())
  LIMIT 1;
$$;

-- Label for audit actor_email (e.g. "eso-pull:ss_abc12xyz")
CREATE OR REPLACE FUNCTION private.machine_token_label(p_project uuid, p_hash text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
  SELECT COALESCE(NULLIF(btrim(name), ''), 'token') || ':' || token_prefix
  FROM api.machine_tokens
  WHERE project_id = p_project AND token_hash = p_hash
    AND (expires_at IS NULL OR expires_at > now())
  LIMIT 1;
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

-- Full row for CLI/ESO get (metadata + ciphertext)
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
RETURNS TABLE (
  id uuid,
  key text,
  value_enc text,
  note text,
  kind text,
  expires_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at, s.created_at, s.updated_at
    FROM api.secrets s
    WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
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

-- Metadata-only list for CLI (no ciphertext / values)
CREATE OR REPLACE FUNCTION private.machine_list_meta(p_project uuid, p_hash text, p_q text DEFAULT NULL)
RETURNS TABLE (
  id uuid,
  key text,
  note text,
  kind text,
  expires_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
DECLARE q text := NULLIF(btrim(COALESCE(p_q, '')), '');
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.note, s.kind, s.expires_at, s.created_at, s.updated_at
    FROM api.secrets s
    WHERE s.project_id = p_project
      AND s.deleted_at IS NULL
      AND (
        q IS NULL
        OR s.key ILIKE ('%' || q || '%')
        OR s.note ILIKE ('%' || q || '%')
      )
    ORDER BY s.key;
END;
$$;

-- Soft-delete via write-scoped machine token (returns id, or NULL if denied/missing)
CREATE OR REPLACE FUNCTION private.machine_delete(
  p_project uuid, p_hash text, p_key text
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = api AS $$
DECLARE sid uuid;
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'write' THEN
    RETURN NULL;
  END IF;
  IF p_key IS NULL OR btrim(p_key) = '' THEN
    RETURN NULL;
  END IF;
  UPDATE api.secrets
  SET deleted_at = now()
  WHERE project_id = p_project
    AND key = p_key
    AND deleted_at IS NULL
  RETURNING id INTO sid;
  RETURN sid;
END;
$$;

-- Upsert secret via write-scoped machine token (returns id, or NULL if denied)
-- p_set_expires: when true, set expires_at to p_expires_at (NULL clears expiry)
DROP FUNCTION IF EXISTS private.machine_upsert_enc(uuid, text, text, text, text);
CREATE OR REPLACE FUNCTION private.machine_upsert_enc(
  p_project uuid,
  p_hash text,
  p_key text,
  p_value_enc text,
  p_note text,
  p_kind text DEFAULT 'plain',
  p_expires_at timestamptz DEFAULT NULL,
  p_set_expires boolean DEFAULT false
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = api AS $$
DECLARE
  sid uuid;
  k text := COALESCE(NULLIF(btrim(p_kind), ''), 'plain');
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'write' THEN
    RETURN NULL;
  END IF;
  IF p_key IS NULL OR btrim(p_key) = '' OR p_value_enc IS NULL THEN
    RETURN NULL;
  END IF;
  IF k NOT IN ('plain', 'database', 'certificate', 'ssh', 'kv') THEN
    k := 'plain';
  END IF;
  INSERT INTO api.secrets (project_id, key, value_enc, note, kind, expires_at)
  VALUES (
    p_project,
    p_key,
    p_value_enc,
    COALESCE(p_note, ''),
    k,
    CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END
  )
  ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
    SET value_enc = EXCLUDED.value_enc,
        note = EXCLUDED.note,
        kind = EXCLUDED.kind,
        expires_at = CASE
          WHEN p_set_expires THEN p_expires_at
          ELSE api.secrets.expires_at
        END
  RETURNING id INTO sid;
  RETURN sid;
END;
$$;

GRANT USAGE ON SCHEMA private TO authenticator;
GRANT EXECUTE ON FUNCTION private.register_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.change_password TO authenticator;
GRANT EXECUTE ON FUNCTION private.set_local_password TO authenticator;
GRANT EXECUTE ON FUNCTION private.upsert_ldap_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.upsert_oidc_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.create_team TO authenticator;
GRANT EXECUTE ON FUNCTION private.lookup_user TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.team_member_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.project_member_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.team_group_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.group_member_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.project_group_role_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.secret_acl_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.audit_org TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.lookup_invite TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.audit_secret TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.auth_machine TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_role TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_token_label TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_enc TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_enc TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_meta TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_delete TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_upsert_enc TO authenticator;
GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api._role_rank TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api._perm_rank TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.is_team_member TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.team_role TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.project_role TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_read_project TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_write_project TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_admin_project TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_access_secret_row TO authenticated, anon;
GRANT EXECUTE ON FUNCTION api.can_access_secret TO authenticated, anon;

-- Effective policy: secret.requires_approval overrides project default
CREATE OR REPLACE FUNCTION api.secret_requires_approval(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN s.requires_approval IS TRUE THEN true
    WHEN s.requires_approval IS FALSE THEN false
    ELSE COALESCE(p.require_reveal_approval, false)
  END
  FROM api.secrets s
  JOIN api.projects p ON p.id = s.project_id
  WHERE s.id = sid AND s.deleted_at IS NULL;
$$;
GRANT EXECUTE ON FUNCTION api.secret_requires_approval TO authenticated, anon;

-- Non-admins need ACL reveal + optional approved grant when approval is required
CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
    -- Per-secret ACL (and project read) first
    WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
    WHEN api.is_global_admin() THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid AND api.can_admin_project(s.project_id)
    ) THEN true
    WHEN NOT COALESCE(api.secret_requires_approval(sid), false) THEN true
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
GRANT EXECUTE ON FUNCTION api.can_reveal_secret TO authenticated, anon;

CREATE OR REPLACE FUNCTION private.secret_access_request_rows(p_project uuid)
RETURNS TABLE (
  id uuid,
  secret_id uuid,
  secret_key text,
  user_id uuid,
  email text,
  name text,
  status text,
  reason text,
  created_at timestamptz,
  resolved_at timestamptz,
  approved_until timestamptz,
  resolver_email text
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT r.id, r.secret_id, COALESCE(s.key, ''), r.user_id,
         u.email, u.name, r.status, r.reason, r.created_at,
         r.resolved_at, r.approved_until,
         COALESCE(ru.email, '')
  FROM api.secret_access_requests r
  JOIN private.users u ON u.id = r.user_id
  LEFT JOIN api.secrets s ON s.id = r.secret_id
  LEFT JOIN private.users ru ON ru.id = r.resolved_by
  WHERE r.project_id = p_project
    AND (
      api.can_admin_project(p_project)
      OR r.user_id = api.current_user_id()
    )
  ORDER BY
    CASE r.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
    r.created_at DESC
  LIMIT 200;
$$;
GRANT EXECUTE ON FUNCTION private.secret_access_request_rows TO authenticator, authenticated;

CREATE OR REPLACE FUNCTION private.pending_access_requests_for_admin()
RETURNS TABLE (
  id uuid,
  project_id uuid,
  project_name text,
  secret_id uuid,
  secret_key text,
  user_id uuid,
  email text,
  name text,
  reason text,
  created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT r.id, r.project_id, p.name, r.secret_id, COALESCE(s.key, ''),
         r.user_id, u.email, u.name, r.reason, r.created_at
  FROM api.secret_access_requests r
  JOIN api.projects p ON p.id = r.project_id
  JOIN private.users u ON u.id = r.user_id
  LEFT JOIN api.secrets s ON s.id = r.secret_id
  WHERE r.status = 'pending'
    AND api.can_admin_project(r.project_id)
  ORDER BY r.created_at ASC
  LIMIT 100;
$$;
GRANT EXECUTE ON FUNCTION private.pending_access_requests_for_admin TO authenticator, authenticated;

-- PostgREST needs table privileges via authenticator switching roles
GRANT ALL ON ALL TABLES IN SCHEMA api TO authenticator;
GRANT USAGE ON SCHEMA private TO authenticated;

COMMENT ON SCHEMA api IS 'PostgREST + RLS secret store';
