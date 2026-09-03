-- ── Architecture Overview ──────────────────────────────────────────────
--
-- WHAT: Squashed fresh-install baseline for the Secret Store.
--
-- WHY:  Single baseline for new databases; existing databases upgrade via
--       numbered NNNN_ migrations applied at startup by app/core/migrations.py.
--
-- SECURITY MODEL:
--   Three-schema design:
--     api      — PostgREST-facing tables and views; all access gated by RLS.
--     private  — Admin-only: users, auth, crypto keys, sessions. Never exposed
--                to PostgREST; accessed only via SECURITY DEFINER functions.
--     rbac     — Kubernetes-style role-based access control (roles, rules,
--                bindings). RLS-protected; bindings resolve the scope chain.
--
--   Role delegation (PostgREST pattern):
--     authenticator — App connection role. LOGIN, NOINHERIT. PostgREST connects
--                     as this role, then SET ROLE authenticated per request.
--     authenticated  — Logged-in user. Has USAGE on api/private/rbac schemas.
--                      RLS policies target this role.
--     anon           — Unauthenticated. Minimal access (OIDC/LDAP discovery).
--
--   How RLS works:
--     1. PostgREST connects as `authenticator`.
--     2. On each request, it runs SET ROLE authenticated.
--     3. JWT claims are stored in request.jwt.claims (GUC).
--     4. api.current_user_id() reads the `sub` claim.
--     5. Policies call api.can(verb, resource, scope_kind, scope_id) which
--        walks rbac.bindings → rbac.role_rules → scope chain.
--     6. Global admins (private.users.is_global_admin) short-circuit to true.
--
--   FORCE ROW LEVEL SECURITY: Applied to all api tables so even table owners
--   (superuser aside) are subject to RLS when querying through the app.
--
-- Baseline is 0001 schema + 0002 RBAC, then unique later features
-- (0020 hardening, 0022+ shared/crypto/HSM/webhooks/meta). Historical
-- 0003–0019 copies are omitted: they duplicated this file and aborted
-- fresh initdb. Existing databases are not supported; recreate them.


-- ===== 0001_init.sql =====

-- Secret Store schema: teams → projects → secrets + memberships, RLS for PostgREST
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Schema Creation ────────────────────────────────────────────────────
--
-- WHAT: Three schemas for security-layer separation.
--
-- WHY:  PostgREST exposes only the `api` schema. `private` holds sensitive
--       data (passwords, keys, sessions) accessible only through DEFINER
--       functions. `rbac` isolates the authorization model.
--
--   api      — Teams, projects, secrets, audit, webhooks (PostgREST-facing).
--   private  — Users, auth, crypto, sessions, migration tracking.
--   rbac     — Roles, role_rules, bindings (Kubernetes-style RBAC).

CREATE SCHEMA api;
CREATE SCHEMA private;

-- ── PostgREST Role Delegation ──────────────────────────────────────────
--
-- WHAT: Three roles implementing the PostgREST authentication pattern.
--
-- WHY:  PostgREST needs a login role (authenticator) that can switch to
--       per-user roles (authenticated) via SET ROLE. This avoids giving
--       the app direct table access — all access flows through RLS.
--
--   authenticator — LOGIN role. PostgREST connects here. NOINHERIT so it
--                    cannot access api tables directly; must SET ROLE.
--   authenticated  — Logged-in user. RLS policies target this role.
--   anon           — Unauthenticated requests (OIDC/LDAP discovery only).
--
-- SECURITY: authenticator has USAGE on api but no direct table access.
--           GRANT anon, authenticated TO authenticator allows SET ROLE.
--           search_path locked to api,public — prevents schema injection.
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

-- ── Users (private schema) ─────────────────────────────────────────────
--
-- WHAT: User accounts with local password, LDAP, or OIDC authentication.
--
-- WHY:  private schema — never exposed to PostgREST. Flask app handles
--       auth; DB stores hashed credentials and 2FA state.
--
-- KEY COLUMNS:
--   password_hash     — bcrypt hash; NULL for LDAP/OIDC-only accounts.
--   is_global_admin   — Full cluster-wide access; short-circuits RLS.
--   auth_source       — 'local' | 'ldap' | 'oidc'; controls auth flow.
--   totp_secret_enc   — Fernet-encrypted TOTP secret (2FA).
--   disabled_at       — Soft-disable by global admin; blocks login.
--   email_verified_at — Set after email confirmation link clicked.
--
-- SECURITY: password_hash nullable for SSO users. disabled_at checked
--           at login, not at DB level (app enforces).
CREATE TABLE IF NOT EXISTS private.users (
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
  email_verified_at timestamptz,
  email_verify_token_hash text,
  email_verify_sent_at timestamptz,
  login_alerts boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ── TOTP Recovery Codes ────────────────────────────────────────────────
--
-- WHAT: One-time hashed recovery codes for TOTP lockout bypass.
--
-- WHY:  Users who lose their TOTP device need a recovery path. Codes are
--       hashed (not stored plaintext) and marked used_at when consumed.
--
-- INDEX: Partial index on unused codes for fast lookup during recovery.
CREATE TABLE IF NOT EXISTS private.totp_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS totp_recovery_codes_user_idx
  ON private.totp_recovery_codes (user_id)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS users_email_verify_token_idx
  ON private.users (email_verify_token_hash)
  WHERE email_verify_token_hash IS NOT NULL;

-- ── Server Settings ────────────────────────────────────────────────────
--
-- WHAT: Global configuration key-value store (classification, LDAP, SMTP,
--       branding, token lifetimes, TOTP enforcement).
--
-- WHY:  Admin-configurable without redeploy. Values are strings; app
--       parses/coerces to typed values.
--
-- SECURITY: private schema — only global admins can modify.
CREATE TABLE IF NOT EXISTS private.server_settings (
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
  ('smtp_from_name', 'Corvus'),
  ('smtp_login_alerts', 'false'),
  ('smtp_login_alerts_force', 'false'),
  ('brand_name', 'Corvus'),
  ('brand_tagline', 'Keep your secrets.'),
  ('totp_enforce_global_admins', 'false'),
  ('require_pat_expiry', 'false'),
  ('max_pat_lifetime_days', '3650'),
  ('require_machine_token_expiry', 'false'),
  ('max_machine_token_lifetime_days', '3650');

-- ── LDAP Role Maps ─────────────────────────────────────────────────────
--
-- WHAT: Maps LDAP groups to server roles (currently global_admin only).
--
-- WHY:  Enterprise SSO: LDAP group membership grants elevated access
--       without manual provisioning.
--
-- SECURITY: private schema. Role CHECK limits to 'global_admin'.
CREATE TABLE IF NOT EXISTS private.ldap_role_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ldap_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('global_admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ldap_group)
);

-- ── Teams ──────────────────────────────────────────────────────────────
--
-- WHAT: Top-level organizational unit. Contains projects, members, groups.
--
-- WHY:  Teams are the primary access-control boundary. Users are members
--       of teams; projects belong to teams; secrets belong to projects.
--
-- KEY COLUMNS:
--   created_by              — User who created the team (gets team-owner binding).
--   default_token_days      — Team-level machine token lifetime (null = server default).
--   classification_*        — Team-level classification banner override.
--   allow_reveal_requests   — Whether team members can request secret reveal access.
--
-- RELATIONSHIPS: FK created_by → private.users(id).
-- RLS: Members can SELECT; creator or global admin can INSERT;
--      team-owner/admin can UPDATE; team-owner can DELETE.
CREATE TABLE IF NOT EXISTS api.teams (
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
  classification_fg text NOT NULL DEFAULT '',
  allow_reveal_requests boolean NOT NULL DEFAULT true
);

-- ── Team LDAP Maps ─────────────────────────────────────────────────────
--
-- WHAT: Maps LDAP groups to team roles (owner/admin/member/viewer).
--
-- WHY:  Automatic team membership and role assignment from LDAP group
--       membership. No manual provisioning needed for directory-managed users.
--
-- RELATIONSHIPS: FK team_id → api.teams(id) CASCADE.
-- RLS: Team members can SELECT; team-owner/admin can write.
CREATE TABLE IF NOT EXISTS api.team_ldap_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  ldap_group text NOT NULL,
  role text NOT NULL REFERENCES rbac.roles (name),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, ldap_group)
);

-- ── Team Invites ───────────────────────────────────────────────────────
--
-- WHAT: Shareable invite links for team onboarding.
--
-- WHY:  Self-service team growth. Token is hashed; link contains raw token
--       that is hashed and compared. Expires and can be revoked.
--
-- RELATIONSHIPS: FK team_id → api.teams(id) CASCADE;
--                FK created_by → private.users(id) SET NULL.
-- INDEX: Partial index on active (non-revoked) invites per team.
-- RLS: team-owner/admin only for all operations.
CREATE TABLE IF NOT EXISTS api.team_invites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'team-member'
    CHECK (role IN ('team-admin', 'team-member', 'team-viewer')),
  expires_at timestamptz NOT NULL,
  created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS team_invites_team_idx ON api.team_invites (team_id) WHERE revoked_at IS NULL;

-- ── Team Join Requests ─────────────────────────────────────────────────
--
-- WHAT: Pending self-service join requests (created when user redeems invite).
--
-- WHY:  Invite redemption creates a request that team admins approve/reject.
--       Prevents automatic membership without oversight.
--
-- RELATIONSHIPS: FK team_id → api.teams(id) CASCADE;
--                FK invite_id → api.team_invites(id) SET NULL;
--                FK user_id → private.users(id) CASCADE;
--                FK resolved_by → private.users(id) SET NULL.
-- INDEX: Unique partial index on pending (team_id, user_id) — one pending
--        request per user per team.
-- RLS: Admins see all; users see their own. INSERT by self; UPDATE by admin.
CREATE TABLE IF NOT EXISTS api.team_join_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  invite_id uuid REFERENCES api.team_invites(id) ON DELETE SET NULL,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'team-member'
    CHECK (role IN ('team-admin', 'team-member', 'team-viewer')),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolved_by uuid REFERENCES private.users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS team_join_requests_pending_uidx
  ON api.team_join_requests (team_id, user_id) WHERE status = 'pending';

-- ── Projects ───────────────────────────────────────────────────────────
--
-- WHAT: Bitwarden-style access control surface within a team.
--
-- WHY:  Projects group secrets and define access boundaries. Team members
--       get project access via RBAC bindings at team or project scope.
--
-- KEY COLUMNS:
--   require_reveal_approval  — Secrets in this project require admin approval
--                              before plaintext reveal (unless per-secret override).
--   default_access_mode      — 'inherit' (team/project RBAC applies) or
--                              'restricted' (only secret-scope bindings apply).
--
-- RELATIONSHIPS: FK team_id → api.teams(id) CASCADE.
-- CONSTRAINT: UNIQUE (team_id, name) — project names unique within team.
-- RLS: Team members can SELECT; team-owner/admin/member can INSERT;
--      project admins can UPDATE; team-owner/admin can DELETE.
CREATE TABLE IF NOT EXISTS api.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  -- When true, secrets inherit require-approval for reveal (unless per-secret override)
  require_reveal_approval boolean NOT NULL DEFAULT false,
  default_access_mode text NOT NULL DEFAULT 'inherit'
    CHECK (default_access_mode IN ('inherit', 'restricted')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, name)
);

-- ── Groups ─────────────────────────────────────────────────────────────
--
-- WHAT: Team-scoped groups for bulk access assignment (manual or directory-synced).
--
-- WHY:  Instead of binding each user individually, bind a group to a role.
--       Groups can be manual, LDAP-synced, or OIDC-synced via external_key.
--
-- KEY COLUMNS:
--   source        — 'manual' | 'ldap' | 'oidc'; how membership is managed.
--   external_key  — Directory group identifier (DN/CN/claim) for sync.
--
-- RELATIONSHIPS: FK team_id → api.teams(id) CASCADE.
-- CONSTRAINT: UNIQUE (team_id, name); unique external_key per team+source.
-- INDEX: Partial unique index on (team_id, source, external_key) for
--        directory-synced groups.
-- RLS: Team members can SELECT; team-owner/admin can write.
CREATE TABLE IF NOT EXISTS api.groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  name text NOT NULL,
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap', 'oidc')),
  -- When source is ldap/oidc, directory group token (DN/CN/claim) for membership sync
  external_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, name)
);
CREATE UNIQUE INDEX IF NOT EXISTS groups_external_key_uidx
  ON api.groups (team_id, source, external_key)
  WHERE external_key IS NOT NULL AND source IN ('ldap', 'oidc');

CREATE TABLE IF NOT EXISTS api.group_members (
  group_id uuid NOT NULL REFERENCES api.groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  source text NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'ldap', 'oidc')),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_members_user_idx ON api.group_members (user_id);

-- ── Group Members ──────────────────────────────────────────────────────
--
-- WHAT: Many-to-many membership between groups and users.
--
-- WHY:  Groups are subjects in RBAC bindings. This table resolves
--       Group bindings to individual users during authorization.
--
-- RELATIONSHIPS: FK group_id → api.groups(id) CASCADE;
--                FK user_id → private.users(id) CASCADE.
-- PRIMARY KEY: (group_id, user_id) — no duplicate memberships.
-- INDEX: On user_id for reverse lookup (which groups is user in?).
-- RLS: Team members can SELECT; team-owner/admin can write;
--      users can remove themselves.

-- ── Org Audit ──────────────────────────────────────────────────────────
--
-- WHAT: Audit log for membership and organizational changes (not secret values).
--
-- WHY:  Track who changed what in teams, projects, and access control.
--       Separate from secret_audit which tracks secret lifecycle events.
--
-- KEY COLUMNS:
--   action       — What happened (member_added, role_changed, etc.).
--   detail       — Human-readable context.
--   actor_email  — Email of the actor (redundant with user_id for resilience).
--
-- RELATIONSHIPS: FK team_id → api.teams(id) CASCADE;
--                FK project_id → api.projects(id) CASCADE;
--                FK user_id → private.users(id) SET NULL.
-- INDEXES: On (team_id, created_at DESC) and (project_id, created_at DESC)
--          for timeline queries.
-- RLS: Team members can read team-scoped rows; project readers can read
--      project-scoped rows. INSERT only via SECURITY DEFINER function.
CREATE TABLE IF NOT EXISTS api.org_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES api.teams(id) ON DELETE CASCADE,
  project_id uuid REFERENCES api.projects(id) ON DELETE CASCADE,
  action text NOT NULL,
  detail text NOT NULL DEFAULT '',
  user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
  actor_email text NOT NULL DEFAULT '',
  -- Squashed from 0012: network context for post-incident forensics.
  ip_address text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS org_audit_team_created_idx ON api.org_audit (team_id, created_at DESC);
CREATE INDEX IF NOT EXISTS org_audit_project_created_idx ON api.org_audit (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS org_audit_user_idx ON api.org_audit (user_id, created_at DESC);

-- ── Folders ────────────────────────────────────────────────────────────
--
-- WHAT: Optional hierarchy within a project (labels[group]; e.g. team/env).
--
-- WHY:  Move (not copy) secrets into folders; gate folder contents with
--       folder bindings without redefining project membership.
--
-- RELATIONSHIPS: FK project_id → api.projects(id) CASCADE.
-- CONSTRAINT: UNIQUE (project_id, name) — folder names unique within project.
-- RLS: SELECT via can_read_project; write via can_admin_project.
CREATE TABLE IF NOT EXISTS api.folders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  parent_id uuid,
  name text NOT NULL CHECK (name <> '' AND name NOT IN ('.', '..') AND name !~ '[\\/]'),
  path text NOT NULL CHECK (path <> '' AND path !~ '(^/|/$|//|[\\])'),
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

-- ── Secrets ────────────────────────────────────────────────────────────
--
-- WHAT: Encrypted secret key-value pairs within a project.
--
-- WHY:  Core data model. value_enc is Fernet ciphertext from Flask app.
--       note is intentional plaintext for labels/search only.
--
-- SOFT DELETE: deleted_at marks deletion; live rows unique on (project_id, key)
--              outside folders and (project_id, folder_id, key) inside one.
--              Deleted secrets visible only to users with write access.
--
-- KEY COLUMNS:
--   value_enc          — Fernet ciphertext (never exposed to authenticated role).
--   note               — Plaintext label/description (NOT encrypted).
--   kind               — Secret type: plain, database, certificate, ssh, kv.
--   expires_at         — Hard expiry (optional).
--   rotation_*         — Rotation tracking (interval, owner, next due).
--   requires_approval  — Per-secret override of project reveal approval.
--   access_mode        — 'inherit' (RBAC applies) or 'restricted' (secret bindings only).
--   last_accessed_*    — Reveal tracking (system-set, not user-editable).
--
-- RELATIONSHIPS: FK project_id → api.projects(id) CASCADE;
--                FK last_accessed_by → private.users(id) SET NULL.
-- INDEX: Unique partial index on (project_id, key) WHERE deleted_at IS NULL.
-- RLS: Access via api.can_access_secret_row() — checks RBAC + access_mode.
CREATE TABLE IF NOT EXISTS api.secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  folder_id uuid,
  key text NOT NULL,
  value_enc text NOT NULL,
  note text NOT NULL DEFAULT '',  -- non-sensitive; not encrypted
  kind text NOT NULL DEFAULT 'plain'
    CHECK (kind IN ('plain', 'database', 'certificate', 'ssh', 'kv')),
  expires_at timestamptz,        -- hard expiry (optional)
  rotation_interval_days integer CHECK (rotation_interval_days IS NULL OR rotation_interval_days > 0),
  rotation_owner text,
  rotation_next_at timestamptz,
  rotated_at timestamptz,
  -- NULL = inherit project.require_reveal_approval; true/false = override
  requires_approval boolean,
  -- Per-secret access tighter than project membership (see api.can_access_secret)
  access_mode text NOT NULL DEFAULT 'inherit'
    CHECK (access_mode IN ('inherit', 'restricted')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  -- Set on successful reveal (system fields; not user-editable)
  last_accessed_at timestamptz,
  last_accessed_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  crypto_provider text NOT NULL DEFAULT 'master'
    CHECK (crypto_provider IN ('master', 'project'))
);
CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_key_live
  ON api.secrets (project_id, key) WHERE deleted_at IS NULL AND folder_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_folder_key_live
  ON api.secrets (project_id, folder_id, key) WHERE deleted_at IS NULL AND folder_id IS NOT NULL;
-- Folder membership is project-scoped: a secret's folder must belong to the
-- same project. Deleting a non-empty folder is refused (RESTRICT).
ALTER TABLE api.secrets DROP CONSTRAINT IF EXISTS secrets_project_folder_fk;
ALTER TABLE api.secrets
  ADD CONSTRAINT secrets_project_folder_fk
  FOREIGN KEY (project_id, folder_id)
  REFERENCES api.folders(project_id, id) ON DELETE RESTRICT;

-- ── Secret Metadata ────────────────────────────────────────────────────
--
-- WHAT: User-defined custom key-value labels on secrets (searchable, plaintext).
--
-- WHY:  Enrich secrets with context (environment, owner, service) without
--       putting sensitive data in the note field.
--
-- RELATIONSHIPS: FK secret_id → api.secrets(id) CASCADE.
-- PRIMARY KEY: (secret_id, key) — one value per key per secret.
-- CONSTRAINT: key must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.
-- INDEXES: On key and value for search/filter.
-- RLS: Read via can_access_secret('read'); write via can_access_secret('write').
CREATE TABLE IF NOT EXISTS api.secret_meta (
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  key text NOT NULL
    CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  value text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (secret_id, key)
);
CREATE INDEX IF NOT EXISTS secret_meta_key_idx ON api.secret_meta (key);
CREATE INDEX IF NOT EXISTS secret_meta_value_idx ON api.secret_meta (value);

-- Per-secret access: use secret-scope rbac.bindings for restricted mode


-- ── Secret Pins & Recent ───────────────────────────────────────────────
--
-- WHAT: Per-user favorites (pins) and recently-accessed tracking.
--
-- WHY:  UX convenience — quick access to frequently-used secrets.
--       secret_recent auto-populated on reveal; pins are manual.
--
-- RELATIONSHIPS: FK user_id → private.users(id) CASCADE;
--                FK secret_id → api.secrets(id) CASCADE.
-- PRIMARY KEY: (user_id, secret_id) — one pin/recent entry per user per secret.
-- INDEX: On (user_id, accessed_at DESC) for "recently accessed" queries.
-- RLS: Self-only (user_id = current_user_id) + secret must be readable.
CREATE TABLE IF NOT EXISTS api.secret_pins (
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, secret_id)
);

CREATE TABLE IF NOT EXISTS api.secret_recent (
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  accessed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, secret_id)
);
CREATE INDEX IF NOT EXISTS secret_recent_user_accessed_idx
  ON api.secret_recent (user_id, accessed_at DESC);

-- ── Secret Versions ────────────────────────────────────────────────────
--
-- WHAT: History of previous ciphertext values when a secret is updated.
--
-- WHY:  Audit trail and rollback capability. Trigger auto-fills on value
--       change; clients cannot INSERT directly (revoked).
--
-- RELATIONSHIPS: FK secret_id → api.secrets(id) CASCADE.
-- INDEX: On (secret_id, created_at DESC) for version timeline.
-- RLS: SELECT only if parent secret is readable. INSERT/UPDATE/DELETE
--      revoked from authenticated; only SECURITY DEFINER trigger writes.
CREATE TABLE IF NOT EXISTS api.secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
  value_enc text NOT NULL,
  note text NOT NULL DEFAULT '',
  crypto_provider text NOT NULL DEFAULT 'master'
    CHECK (crypto_provider IN ('master', 'project')),
  created_at timestamptz NOT NULL DEFAULT now()  -- when this version was superseded
);
CREATE INDEX IF NOT EXISTS secret_versions_secret_created_idx
  ON api.secret_versions (secret_id, created_at DESC);

-- ── Triggers: updated_at & version archive ─────────────────────────────
--
-- WHAT: Two BEFORE UPDATE triggers on api.secrets.
--
-- 1. touch_updated_at() — Sets updated_at = now() on every row change.
--    SECURITY INVOKER (default). Simple timestamp maintenance.
--
-- 2. archive_secret_version() — Saves old value_enc to secret_versions
--    when ciphertext changes. SECURITY DEFINER + row_security = off so
--    writers cannot bypass or forge history. search_path locked to
--    pg_catalog,api,private to prevent schema injection.
CREATE OR REPLACE FUNCTION api.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS secrets_touch_updated_at ON api.secrets;
CREATE TRIGGER secrets_touch_updated_at
  BEFORE UPDATE ON api.secrets
  FOR EACH ROW EXECUTE FUNCTION api.touch_updated_at();

-- Archive previous ciphertext when value changes (DEFINER: writers cannot forge history).
-- Trigger fires BEFORE UPDATE on api.secrets. If value_enc changed, inserts
-- the old row into secret_versions.
--
-- Input:  Trigger (OLD/NEW row from api.secrets)
-- Output: trigger — NEW row
-- Example: (trigger — not called directly)
CREATE OR REPLACE FUNCTION api.archive_secret_version()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api, private
SET row_security = off AS $$
BEGIN
  IF OLD.value_enc IS DISTINCT FROM NEW.value_enc THEN
    INSERT INTO api.secret_versions (secret_id, value_enc, note, crypto_provider)
    VALUES (OLD.id, OLD.value_enc, OLD.note, COALESCE(OLD.crypto_provider, 'master'));
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS secrets_archive_version ON api.secrets;
CREATE TRIGGER secrets_archive_version
  BEFORE UPDATE ON api.secrets
  FOR EACH ROW EXECUTE FUNCTION api.archive_secret_version();

-- ── Secret Audit ───────────────────────────────────────────────────────
--
-- WHAT: Audit log for secret lifecycle events (create, update, reveal,
--       delete, restore, purge, machine_upsert, export, access requests).
--
-- WHY:  Compliance and forensics. Every secret action is recorded with
--       actor identity from JWT (never trusted from caller).
--
-- KEY COLUMNS:
--   secret_id    — NULL after permanent purge (secret_key preserved).
--   actor_email  — Redundant with user_id for resilience after user deletion.
--   action       — Constrained to known lifecycle events.
--
-- RELATIONSHIPS: FK project_id → api.projects(id) CASCADE;
--                FK user_id → private.users(id) SET NULL.
-- INDEX: On (project_id, created_at DESC) for timeline queries.
-- RLS: SELECT via can_read_project. INSERT revoked from authenticated;
--      only private.audit_secret() (SECURITY DEFINER) writes.
CREATE TABLE IF NOT EXISTS api.secret_audit (
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
  -- Squashed from 0012: network context for post-incident forensics.
  ip_address text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS secret_audit_project_created_idx
  ON api.secret_audit (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS secret_audit_secret_idx
  ON api.secret_audit (secret_id, created_at DESC);

-- ── Secret Access Requests ─────────────────────────────────────────────
--
-- WHAT: Reveal access approval workflow. Non-admins request; admins approve/deny.
--
-- WHY:  Four-eyes principle for sensitive secrets. Users without reveal
--       permission can request temporary access with a reason.
--
-- KEY COLUMNS:
--   status           — 'pending' | 'approved' | 'denied'.
--   reason           — User's justification for access.
--   approved_until   — Time-limited grant; NULL = indefinite.
--   resolved_by/at   — Who approved/denied and when.
--
-- RELATIONSHIPS: FK project_id → api.projects(id) CASCADE;
--                FK secret_id → api.secrets(id) CASCADE;
--                FK user_id → private.users(id) CASCADE;
--                FK resolved_by → private.users(id) SET NULL.
-- INDEXES: Unique partial on (secret_id, user_id) WHERE pending;
--          On (project_id, status, created_at) for admin queue;
--          On (secret_id, user_id, approved_until) WHERE approved for fast grant check.
-- RLS: Admins see all; users see their own. INSERT by self; UPDATE by admin.
--      DELETE revoked — resolve via status UPDATE only.
CREATE TABLE IF NOT EXISTS api.secret_access_requests (
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
CREATE UNIQUE INDEX IF NOT EXISTS secret_access_requests_pending_uidx
  ON api.secret_access_requests (secret_id, user_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS secret_access_requests_project_status_idx
  ON api.secret_access_requests (project_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS secret_access_requests_grant_idx
  ON api.secret_access_requests (secret_id, user_id, approved_until)
  WHERE status = 'approved';

-- ── Machine Tokens ─────────────────────────────────────────────────────
--
-- WHAT: Service accounts for automation (OpenShift External Secrets Operator,
--       CI/CD pipelines). Token-based auth, not user-based.
--
-- WHY:  Machines need secret access without human credentials. Tokens are
--       hashed (SHA-256); prefix shown in UI for identification.
--
-- KEY COLUMNS:
--   token_hash   — SHA-256 hash of the raw token (never stored plaintext).
--   token_prefix — First chars of raw token for UI identification (unique).
--   role         — 'service-read' (metadata only) | 'service-reveal' (plaintext)
--                  | 'service-write' (read + upsert + delete).
--   expires_at   — Optional expiry; NULL = never expires.
--
-- RELATIONSHIPS: FK project_id → api.projects(id) CASCADE.
-- RLS: SELECT via can_read_project; INSERT/DELETE via can_admin_project.
--      token_hash column not SELECTable by authenticated (revoked).
--
-- SECURITY: Machine helpers bypass RLS — token hash + expiry is the gate.
--           Functions are SECURITY DEFINER, granted to authenticator only.
CREATE TABLE IF NOT EXISTS api.machine_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_hash text NOT NULL,
  token_prefix text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'service-reveal'
    CHECK (role IN ('service-read', 'service-reveal', 'service-write')),
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ── Machine Token Scopes ───────────────────────────────────────────────
--
-- WHAT: Per-token secret key allow-list (fine-grained access control).
--
-- WHY:  Limit a machine token to specific secrets, not the whole project.
--       Supports exact key match OR shell-style glob patterns (* and ?).
--
-- CONSTRAINT: Exactly one of secret_key or key_pattern must be set (CHECK).
-- INDEXES: Unique partial on exact keys; unique partial on patterns;
--          On token_id for reverse lookup.
-- RLS: SELECT via can_read_project(parent token's project);
--      INSERT/DELETE via can_admin_project.
CREATE TABLE IF NOT EXISTS api.machine_token_scope (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_id uuid NOT NULL REFERENCES api.machine_tokens(id) ON DELETE CASCADE,
  secret_key text,
  key_pattern text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (
      secret_key IS NOT NULL AND btrim(secret_key) <> '' AND key_pattern IS NULL
    ) OR (
      key_pattern IS NOT NULL AND btrim(key_pattern) <> '' AND secret_key IS NULL
    )
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS machine_token_scope_exact_uidx
  ON api.machine_token_scope (token_id, secret_key) WHERE secret_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS machine_token_scope_pattern_uidx
  ON api.machine_token_scope (token_id, key_pattern) WHERE key_pattern IS NOT NULL;
CREATE INDEX IF NOT EXISTS machine_token_scope_token_idx ON api.machine_token_scope (token_id);

-- ── Login Failures ─────────────────────────────────────────────────────
--
-- WHAT: Login failure tracking for throttle/lockout (Flask app; shared across workers).
--
-- WHY:  Brute-force protection. App checks recent failures per email and
--       delays or blocks login after threshold.
--
-- RELATIONSHIPS: No FKs — email is text, not linked to users table
--                (works for failed attempts on non-existent accounts too).
-- INDEX: On (email, created_at) for recent-failure count queries.
-- SECURITY: private schema — not exposed to PostgREST.
CREATE TABLE IF NOT EXISTS private.login_failures (
  id bigserial PRIMARY KEY,
  email text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS login_failures_email_created_idx
  ON private.login_failures (email, created_at);

-- ── Helpers: current user from JWT claim ──
-- Extracts the user id (sub claim) from the PostgREST JWT.
--
-- Input:  none (reads request.jwt.claims setting)
-- Output: uuid — user id or NULL
-- Example: SELECT api.current_user_id();
CREATE OR REPLACE FUNCTION api.current_user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
$$;

-- Global admin: full access across teams/projects.
-- Checks the is_global_admin flag on the user row.
--
-- Input:  none (uses current user from JWT)
-- Output: boolean
-- Example: SELECT api.is_global_admin();
CREATE OR REPLACE FUNCTION api.is_global_admin() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(
    (SELECT is_global_admin FROM private.users WHERE id = api.current_user_id()),
    false
  );
$$;

-- ── RLS Enablement ─────────────────────────────────────────────────────
--
-- WHAT: ENABLE ROW LEVEL SECURITY on all api tables.
--
-- WHY:  RLS must be enabled before policies can be created. Policies are
--       defined later (after auth functions like api.can() exist).
--
-- NOTE: Policies reference RBAC functions defined in the rbac section below.
--       This file is squashed — all definitions are present in order.
ALTER TABLE api.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_ldap_maps ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.team_join_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_recent ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.org_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_meta ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.secret_access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.machine_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.machine_token_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.folders ENABLE ROW LEVEL SECURITY;

-- ── Table Grants & Revocations ─────────────────────────────────────────
--
-- WHAT: Baseline privileges for authenticated role, with targeted revocations.
--
-- WHY:  Default: authenticated gets CRUD on all api tables. Then we revoke
--       specific operations that must go through SECURITY DEFINER functions:
--
--   REVOKE INSERT on secret_audit, org_audit — audit rows must be written
--       by DEFINER functions (private.audit_secret, private.audit_org) which
--       derive actor identity from JWT, not from caller-supplied values.
--
--   REVOKE INSERT/UPDATE/DELETE on secret_versions — version history is
--       trigger-managed only. Writers cannot forge or delete history.
--
--   REVOKE DELETE on secret_access_requests — requests are resolved via
--       status UPDATE (approved/denied), not deleted. Preserves audit trail.
--
-- SECURITY: Defense-in-depth. Even if RLS policy has a gap, these revocations
--           prevent direct table manipulation.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA api TO authenticated;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA api TO authenticated, anon;
-- Audit rows must not be forgeable via PostgREST / authenticated INSERT
REVOKE INSERT ON api.secret_audit FROM authenticated;
REVOKE INSERT ON api.org_audit FROM authenticated;
-- L1: secret version history only via SECURITY DEFINER trigger
REVOKE INSERT, UPDATE, DELETE ON api.secret_versions FROM authenticated;
-- Access requests: no client DELETE (resolve via UPDATE)
REVOKE DELETE ON api.secret_access_requests FROM authenticated;

-- ── FORCE ROW LEVEL SECURITY ───────────────────────────────────────────
--
-- WHAT: FORCE RLS on key api tables so table owners are also subject to RLS.
--
-- WHY:  PostgreSQL table owners bypass RLS by default. PostgREST connects
--       as authenticator → SET ROLE authenticated, but if the DB superuser
--       or table owner queries directly, RLS would be skipped. FORCE RLS
--       ensures even owners go through policies (superuser still bypasses
--       by PostgreSQL design — app must use db.as_user, not db.connect_admin).
--
-- TABLES: All user-facing api tables. private tables don't need FORCE RLS
--         because they're not exposed to PostgREST at all.
ALTER TABLE api.teams FORCE ROW LEVEL SECURITY;
ALTER TABLE api.projects FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_meta FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_access_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE api.machine_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE api.machine_token_scope FORCE ROW LEVEL SECURITY;
ALTER TABLE api.groups FORCE ROW LEVEL SECURITY;
ALTER TABLE api.group_members FORCE ROW LEVEL SECURITY;
ALTER TABLE api.folders FORCE ROW LEVEL SECURITY;

-- Auth helpers (SECURITY DEFINER; Flask/anon only)
-- Never auto-promote first registrant; GLOBAL_ADMIN_EMAIL / BOOTSTRAP_ADMIN_EMAIL does that in app.
--
-- Input:  p_email    (text: email address, case-insensitive),
--         p_password (text: plaintext password, hashed with bcrypt),
--         p_name     (text: display name; defaults to '' if NULL)
-- Output: uuid — new user id
-- Example: SELECT private.register_user('alice@example.com', 's3cret', 'Alice');
CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public, pg_catalog AS $$
DECLARE uid uuid;
BEGIN
  INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
  VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), false, 'local')
  RETURNING id INTO uid;
  RETURN uid;
END;
$$;

-- Verify a local-account password and return the user row on success.
-- Only matches users with a non-null password_hash and disabled_at IS NULL.
--
-- Input:  p_email    (text: email address, case-insensitive),
--         p_password (text: plaintext password to check)
-- Output: TABLE(id uuid, email text, name text, is_global_admin boolean) — empty if invalid
-- Example: SELECT * FROM private.verify_user('alice@example.com', 's3cret');
DROP FUNCTION IF EXISTS private.verify_user(text, text);
CREATE OR REPLACE FUNCTION private.verify_user(p_email text, p_password text)
RETURNS TABLE (id uuid, email text, name text, is_global_admin boolean, email_verified_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public, pg_catalog AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email, u.name, u.is_global_admin, u.email_verified_at FROM private.users u
  WHERE u.email = lower(p_email)
    AND u.password_hash IS NOT NULL
    AND u.disabled_at IS NULL
    AND u.password_hash = crypt(p_password, u.password_hash);
END;
$$;

-- Change password (local accounts only; requires current password).
-- Password must be at least 8 characters. Returns false if old password is wrong.
--
-- Input:  p_user (uuid: user id),
--         p_old  (text: current plaintext password),
--         p_new  (text: new plaintext password, min 8 chars)
-- Output: boolean — true if password was changed, false if old password didn't match
-- Example: SELECT private.change_password('<user-uuid>', 'oldpass', 'newpass123');
CREATE OR REPLACE FUNCTION private.change_password(
  p_user uuid, p_old text, p_new text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public, pg_catalog AS $$
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

-- Set password after verified reset (local accounts only).
-- Does not require the old password; caller must have verified the reset token.
-- Password must be at least 8 characters.
--
-- Input:  p_user (uuid: user id),
--         p_new  (text: new plaintext password, min 8 chars)
-- Output: boolean — true if password was set, false if user not found / not local
-- Example: SELECT private.set_local_password('<user-uuid>', 'newpass123');
CREATE OR REPLACE FUNCTION private.set_local_password(p_user uuid, p_new text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public, pg_catalog AS $$
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
CREATE TABLE IF NOT EXISTS private.user_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  user_agent text NOT NULL DEFAULT '',
  ip text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS user_sessions_user_active_idx
  ON private.user_sessions (user_id, last_seen_at DESC)
  WHERE revoked_at IS NULL;

-- One-time password reset tokens (store only hash)
CREATE TABLE IF NOT EXISTS private.password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
  ON private.password_reset_tokens (user_id)
  WHERE used_at IS NULL;

-- Provision / refresh LDAP user (no password stored; never auto-promote admin).
-- Creates the user if not found, otherwise updates name and sets auth_source to 'ldap'.
--
-- Input:  p_email (text: email address, case-insensitive),
--         p_name  (text: display name from LDAP; empty string preserves existing)
-- Output: uuid — user id (existing or newly created)
-- Example: SELECT private.upsert_ldap_user('bob@example.com', 'Bob Smith');
CREATE OR REPLACE FUNCTION private.upsert_ldap_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public, pg_catalog AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source,
                               email_verified_at)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'ldap', now())
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = 'ldap',
        email_verified_at = COALESCE(email_verified_at, now())
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;

-- Provision / refresh OIDC SSO user (no password stored).
-- Creates the user if not found. If user exists with a local password, keeps
-- auth_source 'local' so they can still use password login; otherwise sets 'oidc'.
--
-- Input:  p_email (text: email address, case-insensitive),
--         p_name  (text: display name from OIDC; empty string preserves existing)
-- Output: uuid — user id (existing or newly created)
-- Example: SELECT private.upsert_oidc_user('carol@example.com', 'Carol Jones');
CREATE OR REPLACE FUNCTION private.upsert_oidc_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public, pg_catalog AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source,
                               email_verified_at)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'oidc', now())
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = CASE
          WHEN auth_source = 'local' AND password_hash IS NOT NULL THEN auth_source
          ELSE 'oidc'
        END,
        email_verified_at = COALESCE(email_verified_at, now())
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;

-- Global role maps from OIDC groups
CREATE TABLE IF NOT EXISTS private.oidc_role_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oidc_group text NOT NULL,
  role text NOT NULL CHECK (role IN ('global_admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (oidc_group)
);

-- Team membership maps from OIDC groups
CREATE TABLE IF NOT EXISTS api.team_oidc_maps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
  oidc_group text NOT NULL,
  role text NOT NULL REFERENCES rbac.roles (name),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (team_id, oidc_group)
);
ALTER TABLE api.team_oidc_maps ENABLE ROW LEVEL SECURITY;
-- Policies for team_oidc_maps defined in 02-rbac.sql
GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_oidc_maps TO authenticated;
GRANT ALL ON api.team_oidc_maps TO authenticator;

-- Personal access tokens (user-scoped)
CREATE TABLE IF NOT EXISTS private.personal_access_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS personal_access_tokens_user_idx
  ON private.personal_access_tokens (user_id, created_at DESC);

-- Squashed from 0002_cli_session_tokens.sql: single-use CLI login handoff
-- tokens (SSO for headless CLIs). Short-lived, hashed at rest, consumed once.
CREATE TABLE IF NOT EXISTS private.cli_session_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cli_session_tokens_user_idx
  ON private.cli_session_tokens (user_id, created_at DESC);

-- private.create_team defined in 02-rbac.sql (inserts into rbac.bindings)

-- User directory: not granted to authenticated (prevents full-user enumeration via PostgREST)
CREATE OR REPLACE VIEW api.user_directory AS
  SELECT id, email, name, is_global_admin, created_at FROM private.users;
-- Global admin / app admin path only
GRANT SELECT ON api.user_directory TO authenticator;

-- Lookup user by email for add-member (does not list all users).
--
-- Input:  p_email (text: email address, case-insensitive)
-- Output: uuid — user id or NULL
-- Example: SELECT private.lookup_user('alice@example.com');
CREATE OR REPLACE FUNCTION private.lookup_user(p_email text)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = private
SET row_security = off AS $$
  SELECT id FROM private.users WHERE email = lower(p_email) LIMIT 1;
$$;

-- private.team_member_rows and private.project_member_rows defined in 02-rbac.sql
-- (query rbac.bindings instead of legacy team_members/project_members)

-- ── Functions that call RBAC auth helpers (defined in 02-rbac.sql) ──
-- These functions are LANGUAGE plpgsql (not LANGUAGE sql) because PostgreSQL
-- validates LANGUAGE sql bodies at creation time. Since the RBAC auth
-- functions (is_team_member, can_access_secret, can_admin_project) are defined
-- in 02-rbac.sql (applied after this file), LANGUAGE sql would fail.
-- LANGUAGE plpgsql defers body validation to execution time.

-- Team groups listing (group team roles live in rbac.bindings, not api.groups)
-- Calls api.is_team_member() — defined in 02-rbac.sql.
--
-- Input:  p_team (uuid: team id)
-- Output: TABLE(id, name, source, external_key, member_count, created_at)
-- Example: SELECT * FROM private.team_group_rows('<team-uuid>');
CREATE OR REPLACE FUNCTION private.team_group_rows(p_team uuid)
RETURNS TABLE (
  id uuid,
  name text,
  source text,
  external_key text,
  member_count bigint,
  created_at timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
  SELECT g.id, g.name, g.source, g.external_key,
         (SELECT count(*) FROM api.group_members gm WHERE gm.group_id = g.id),
         g.created_at
  FROM api.groups g
  WHERE g.team_id = p_team
    AND api.is_team_member(p_team)
  ORDER BY g.name;
END;
$$;

-- List group members for a team group. Calls api.is_team_member() — defined
-- in 02-rbac.sql.
--
-- Input:  p_group (uuid: group id)
-- Output: TABLE(user_id, email, name, source)
-- Example: SELECT * FROM private.group_member_rows('<group-uuid>');
CREATE OR REPLACE FUNCTION private.group_member_rows(p_group uuid)
RETURNS TABLE (user_id uuid, email text, name text, source text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email, u.name, gm.source
  FROM api.group_members gm
  JOIN private.users u ON u.id = gm.user_id
  JOIN api.groups g ON g.id = gm.group_id
  WHERE gm.group_id = p_group
    AND api.is_team_member(g.team_id)
  ORDER BY u.email;
END;
$$;

-- private.project_group_role_rows defined in 02-rbac.sql (queries rbac.bindings)

-- Custom metadata rows for a secret. Calls api.can_access_secret() —
-- defined in 02-rbac.sql.
--
-- Input:  p_secret (uuid: secret id)
-- Output: TABLE(key, value, updated_at)
-- Example: SELECT * FROM private.secret_meta_rows('<secret-uuid>');
DROP FUNCTION IF EXISTS private.secret_meta_rows(uuid);
CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)
RETURNS TABLE (key text, value text, updated_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
  SELECT m.key, m.value, m.updated_at
  FROM api.secret_meta m
  JOIN api.secrets s ON s.id = m.secret_id
  WHERE m.secret_id = p_secret
    AND api.can_access_secret(p_secret, 'read')
  ORDER BY m.key;
END;
$$;

-- Record last reveal access (does not change updated_at of secret value).
-- Calls api.can_access_secret() — defined in 02-rbac.sql.
--
-- Input:  p_secret (uuid: secret id)
-- Output: void
-- Example: SELECT private.touch_secret_access('<secret-uuid>');
CREATE OR REPLACE FUNCTION private.touch_secret_access(p_secret uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  IF p_secret IS NULL OR api.current_user_id() IS NULL THEN
    RETURN;
  END IF;
  IF NOT api.can_access_secret(p_secret, 'reveal') THEN
    RETURN;
  END IF;
  UPDATE api.secrets
     SET last_accessed_at = now(),
         last_accessed_by = api.current_user_id()
   WHERE id = p_secret AND deleted_at IS NULL;
END;
$$;

-- Org / membership audit insert (JWT actor only).
-- Actor is always derived from JWT claims; p_user_id is ignored.
--
-- Input:  p_team (uuid, nullable), p_project (uuid, nullable),
--         p_action (text), p_detail (text, default ''), p_actor_email (text, nullable)
-- Output: void
-- Example: SELECT private.audit_org('<team-uuid>', NULL, 'member_added', 'alice@example.com');
-- Squashed from 0012: audit_org records client network context for
-- post-incident forensics. Existing callers keep working (new args default).
CREATE OR REPLACE FUNCTION private.audit_org(
  p_team uuid,
  p_project uuid,
  p_action text,
  p_detail text DEFAULT '',
  p_actor_email text DEFAULT NULL,
  p_ip_address text DEFAULT '',
  p_user_agent text DEFAULT ''
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private, pg_catalog AS $$
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
  INSERT INTO api.org_audit (team_id, project_id, action, detail, user_id, actor_email, ip_address, user_agent)
  VALUES (p_team, p_project, p_action, COALESCE(p_detail, ''), uid, email, COALESCE(p_ip_address, ''), COALESCE(p_user_agent, ''));
END;
$$;
GRANT EXECUTE ON FUNCTION private.audit_org(uuid, uuid, text, text, text, text, text) TO authenticator, authenticated;

-- Resolve invite token → team (SECURITY DEFINER; hash is the gate).
--
-- Input:  p_hash (text: SHA-256 hash of the invite token)
-- Output: TABLE(invite_id, team_id, team_name, role, expires_at) or empty
-- Example: SELECT * FROM private.lookup_invite('<sha256-hash>');
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

-- Audit insert for secret actions (JWT actor only).
-- p_user_id is ignored: actor is always taken from JWT claims (defense-in-depth).
-- Machine/system callers with no JWT leave user_id NULL and set p_actor_email.
--
-- Input:  p_project (uuid), p_secret_id (uuid, nullable), p_secret_key (text),
--         p_action (text), p_user_id (uuid, ignored), p_actor_email (text, nullable)
-- Output: void
-- Example: SELECT private.audit_secret('<project-uuid>', '<secret-uuid>', 'API_KEY', 'revealed');
-- Squashed from 0012: audit_secret records client network context for
-- post-incident forensics. Existing callers keep working (new args default).
CREATE OR REPLACE FUNCTION private.audit_secret(
  p_project uuid,
  p_secret_id uuid,
  p_secret_key text,
  p_action text,
  p_user_id uuid DEFAULT NULL,
  p_actor_email text DEFAULT NULL,
  p_ip_address text DEFAULT '',
  p_user_agent text DEFAULT ''
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private, pg_catalog AS $$
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
  INSERT INTO api.secret_audit (project_id, secret_id, secret_key, user_id, actor_email, action, ip_address, user_agent)
  VALUES (p_project, p_secret_id, COALESCE(p_secret_key, ''), uid, email, p_action, COALESCE(p_ip_address, ''), COALESCE(p_user_agent, ''));
END;
$$;
GRANT EXECUTE ON FUNCTION private.audit_secret(uuid, uuid, text, text, uuid, text, text, text) TO authenticator, authenticated;

-- ── Machine/ESO helpers (bypass RLS; token hash is the gate) ──
-- These SECURITY DEFINER functions validate machine tokens and read/write
-- secrets on behalf of automation. Gated on token hash + expiry, not RLS.
-- Granted to authenticator only (not authenticated) so users cannot call
-- them directly via PostgREST.

-- Validate a machine token (hash + expiry) for a project.
--
-- Input:  p_project (uuid: project id),
--         p_hash    (text: SHA-256 hash of the token)
-- Output: boolean — true if token is valid and not expired
-- Example: SELECT private.auth_machine('<project-uuid>', '<sha256-hash>');
CREATE OR REPLACE FUNCTION private.auth_machine(p_project uuid, p_hash text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
  SELECT EXISTS (
    SELECT 1 FROM api.machine_tokens
    WHERE project_id = p_project AND token_hash = p_hash
      AND (expires_at IS NULL OR expires_at > now())
  );
$$;

-- Return the machine token role: 'service-read', 'service-reveal', or 'service-write'.
--
-- Input:  p_project (uuid: project id),
--         p_hash    (text: SHA-256 hash of the token)
-- Output: text — role name or NULL if token not found
-- Example: SELECT private.machine_role('<project-uuid>', '<sha256-hash>');
CREATE OR REPLACE FUNCTION private.machine_role(p_project uuid, p_hash text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
  SELECT role FROM api.machine_tokens
  WHERE project_id = p_project AND token_hash = p_hash
    AND (expires_at IS NULL OR expires_at > now())
  LIMIT 1;
$$;

-- Label for audit actor_email (e.g. "eso-pull:ss_abc12xyz").
--
-- Input:  p_project (uuid: project id),
--         p_hash    (text: SHA-256 hash of the token)
-- Output: text — "<token-name>:<token-prefix>" or "token:<prefix>"
-- Example: SELECT private.machine_token_label('<project-uuid>', '<sha256-hash>');
CREATE OR REPLACE FUNCTION private.machine_token_label(p_project uuid, p_hash text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
  SELECT COALESCE(NULLIF(btrim(name), ''), 'token') || ':' || token_prefix
  FROM api.machine_tokens
  WHERE project_id = p_project AND token_hash = p_hash
    AND (expires_at IS NULL OR expires_at > now())
  LIMIT 1;
$$;

-- Shell-style glob (* ?) → SQL LIKE pattern (escape % and _).
-- Backslash, % and _ are escaped; * becomes % and ? becomes _.
--
-- Input:  p_glob (text: shell-style glob pattern, e.g. 'API_*')
-- Output: text — SQL LIKE pattern, e.g. 'API\_%'
-- Example: SELECT private.glob_to_like('API_*');  → 'API\_%'
CREATE OR REPLACE FUNCTION private.glob_to_like(p_glob text)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog AS $$
DECLARE s text;
BEGIN
  s := replace(p_glob, E'\\', E'\\\\');
  s := replace(s, '%', E'\\%');
  s := replace(s, '_', E'\\_');
  s := replace(s, '*', '%');
  s := replace(s, '?', '_');
  RETURN s;
END;
$$;

-- Check if a machine token is allowed to access a specific secret key.
-- Empty allow-list denies access; restricted secrets need an exact key match.
-- Unscoped tokens get an explicit '*' so inherit keys keep working.
--
-- Input:  p_project (uuid: project id),
--         p_hash    (text: SHA-256 hash of the token),
--         p_key     (text: secret key to check)
-- Output: boolean — true if the key is allowed
-- Example: SELECT private.machine_key_allowed('<project-uuid>', '<hash>', 'API_KEY');
CREATE OR REPLACE FUNCTION private.machine_key_allowed(
  p_project uuid, p_hash text, p_key text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
  SELECT CASE
    WHEN p_key IS NULL OR btrim(p_key) = '' THEN false
    WHEN NOT private.auth_machine(p_project, p_hash) THEN false
    WHEN NOT EXISTS (
      SELECT 1
      FROM api.machine_token_scope sc
      JOIN api.machine_tokens t ON t.id = sc.token_id
      WHERE t.project_id = p_project
        AND t.token_hash = p_hash
        AND (t.expires_at IS NULL OR t.expires_at > now())
    ) THEN false
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL
        AND COALESCE(s.access_mode, 'inherit') = 'restricted'
    ) THEN EXISTS (
      SELECT 1
      FROM api.machine_token_scope sc
      JOIN api.machine_tokens t ON t.id = sc.token_id
      WHERE t.project_id = p_project
        AND t.token_hash = p_hash
        AND (t.expires_at IS NULL OR t.expires_at > now())
        AND sc.secret_key IS NOT NULL AND sc.secret_key = p_key
    )
    WHEN EXISTS (
      SELECT 1
      FROM api.machine_token_scope sc
      JOIN api.machine_tokens t ON t.id = sc.token_id
      WHERE t.project_id = p_project
        AND t.token_hash = p_hash
        AND (t.expires_at IS NULL OR t.expires_at > now())
        AND (
          (sc.secret_key IS NOT NULL AND sc.secret_key = p_key)
          OR (
            sc.key_pattern IS NOT NULL
            AND p_key LIKE private.glob_to_like(sc.key_pattern) ESCAPE E'\\'
          )
        )
    ) THEN true
    ELSE false
  END;
$$;

GRANT EXECUTE ON FUNCTION private.glob_to_like TO authenticator;

-- Get a single secret's encrypted value (ciphertext) for a machine token.
-- Respects key allow-list. Does not decrypt. service-read tokens cannot fetch.
--
-- Input:  p_project (uuid), p_hash (text), p_key (text: secret key)
-- Output: text — value_enc (Fernet ciphertext) or NULL if not allowed/found
-- Example: SELECT private.machine_get_enc('<project-uuid>', '<hash>', 'API_KEY');
CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN NULL;
  END IF;
  IF private.machine_role(p_project, p_hash) = 'service-read' THEN
    RETURN NULL;
  END IF;
  RETURN (
    SELECT value_enc FROM api.secrets
    WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
  );
END;
$$;

-- Get a single secret row (metadata + ciphertext) for a machine token.
-- Respects key allow-list. service-read tokens cannot fetch.
--
-- Input:  p_project (uuid), p_hash (text), p_key (text: secret key)
-- Output: TABLE(id, key, value_enc, note, kind, expires_at, rotation_interval_days,
--               rotation_owner, rotation_next_at, rotated_at, created_at, updated_at,
--               crypto_provider)
-- Example: SELECT * FROM private.machine_get_row('<project-uuid>', '<hash>', 'API_KEY');
DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
RETURNS TABLE (
  id uuid, key text, value_enc text, note text, kind text,
  expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
  rotation_next_at timestamptz, rotated_at timestamptz,
  created_at timestamptz, updated_at timestamptz,
  crypto_provider text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN;
  END IF;
  IF private.machine_role(p_project, p_hash) = 'service-read' THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
           s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
           s.created_at, s.updated_at, s.crypto_provider
    FROM api.secrets s
    WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
END;
$$;

-- List all secret key+ciphertext pairs for a machine token.
-- Respects key allow-list.
--
-- Input:  p_project (uuid), p_hash (text)
-- Output: TABLE(key, value_enc)
-- Example: SELECT * FROM private.machine_list_enc('<project-uuid>', '<hash>');
DROP FUNCTION IF EXISTS private.machine_list_enc(uuid, text);
CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
RETURNS TABLE (key text, value_enc text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.key, s.value_enc FROM api.secrets s
    WHERE s.project_id = p_project AND s.deleted_at IS NULL
      AND private.machine_key_allowed(p_project, p_hash, s.key);
END;
$$;

-- List secret metadata (no ciphertext) for a machine token.
-- Optional q filter matches key, note, or custom metadata.
--
-- Input:  p_project (uuid), p_hash (text), p_q (text: optional search; default NULL)
-- Output: TABLE(id, key, note, kind, expires_at, created_at, updated_at)
-- Example: SELECT * FROM private.machine_list_meta('<project-uuid>', '<hash>', 'api');
DROP FUNCTION IF EXISTS private.machine_list_meta(uuid, text, text);
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
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
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
      AND private.machine_key_allowed(p_project, p_hash, s.key)
      AND (
        q IS NULL
        OR s.key ILIKE ('%' || q || '%')
        OR s.note ILIKE ('%' || q || '%')
        OR EXISTS (
          SELECT 1 FROM api.secret_meta m
          WHERE m.secret_id = s.id
            AND (m.key ILIKE ('%' || q || '%') OR m.value ILIKE ('%' || q || '%'))
        )
      )
    ORDER BY s.key;
END;
$$;

-- Soft-delete a secret via machine token (service-write role only).
-- Respects key allow-list.
--
-- Input:  p_project (uuid), p_hash (text), p_key (text: secret key)
-- Output: uuid — deleted secret id, or NULL if not allowed/not found
-- Example: SELECT private.machine_delete('<project-uuid>', '<hash>', 'API_KEY');
CREATE OR REPLACE FUNCTION private.machine_delete(
  p_project uuid, p_hash text, p_key text
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE sid uuid;
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
    RETURN NULL;
  END IF;
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
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

-- Create or update a secret via machine token (service-write role only).
-- Respects key allow-list. Archives previous ciphertext on value change.
--
-- Input:  p_project (uuid), p_hash (text), p_key (text),
--         p_value_enc (text: Fernet-encrypted value), p_note (text: optional)
-- Output: uuid — secret id
-- Example: SELECT private.machine_upsert_enc('<project-uuid>', '<hash>', 'API_KEY', '<enc>', 'rotated');
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
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE
  sid uuid;
  k text := COALESCE(NULLIF(btrim(p_kind), ''), 'plain');
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
    RETURN NULL;
  END IF;
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
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
-- private.create_team granted in 02-rbac.sql
-- private.lookup_user: Flask (as_user → authenticated) + authenticator; not in
-- PostgREST db-schemas (api only) so not callable as RPC over PostgREST.
GRANT EXECUTE ON FUNCTION private.lookup_user TO authenticator, authenticated;
REVOKE EXECUTE ON FUNCTION private.lookup_user FROM PUBLIC;
-- private.team_member_rows and private.project_member_rows granted in 02-rbac.sql
GRANT EXECUTE ON FUNCTION private.team_group_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.group_member_rows TO authenticator, authenticated;
-- private.project_group_role_rows granted in 02-rbac.sql
GRANT EXECUTE ON FUNCTION private.secret_meta_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.touch_secret_access TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.audit_org TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.lookup_invite TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.audit_secret TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.auth_machine TO authenticator;
GRANT EXECUTE ON FUNCTION private.glob_to_like TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_key_allowed TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_role TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_token_label TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_enc TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_enc TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_meta TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_delete TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_upsert_enc TO authenticator;
GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon;
-- Authorization function grants in 02-rbac.sql

-- Effective policy: secret.requires_approval overrides project default.
-- NULL on secret → inherit project.require_reveal_approval.
-- true/false on secret → override.
--
-- Input:  sid (uuid: secret id)
-- Output: boolean — true if reveal requires admin approval
-- Example: SELECT api.secret_requires_approval('<secret-uuid>');
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

-- api.can_reveal_secret defined in 02-rbac.sql (RBAC reveal + approval layer)

-- List reveal access requests for a project. Calls api.can_admin_project()
-- and api.current_user_id() — can_admin_project is defined in 02-rbac.sql.
--
-- Input:  p_project (uuid: project id)
-- Output: TABLE(id, secret_id, secret_key, user_id, email, name, status,
--               reason, created_at, resolved_at, approved_until, resolver_email)
-- Example: SELECT * FROM private.secret_access_request_rows('<project-uuid>');
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
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
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
END;
$$;
GRANT EXECUTE ON FUNCTION private.secret_access_request_rows TO authenticator, authenticated;

-- List pending access requests for all projects the current user can admin.
-- Calls api.can_admin_project() — defined in 02-rbac.sql.
--
-- Input:  none (uses current user from JWT)
-- Output: TABLE(id, project_id, project_name, secret_id, secret_key,
--               user_id, email, name, reason, created_at)
-- Example: SELECT * FROM private.pending_access_requests_for_admin();
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
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
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
END;
$$;
GRANT EXECUTE ON FUNCTION private.pending_access_requests_for_admin TO authenticator, authenticated;

-- PostgREST needs table privileges via authenticator switching roles
GRANT ALL ON ALL TABLES IN SCHEMA api TO authenticator;
GRANT USAGE ON SCHEMA private TO authenticated;

COMMENT ON SCHEMA api IS 'PostgREST + RLS secret store';

-- ── Schema migration tracking (admin-only) ────────────────────────────────
-- Records applied migration versions + checksums. Written by the app
-- migration runner (app/migrations.py); private schema is not exposed to
-- PostgREST, so only the admin role manages this table.
CREATE TABLE IF NOT EXISTS private.schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now(),
  checksum text NOT NULL,
  applied_by text,
  application_name text
);

REVOKE ALL ON private.schema_migrations FROM authenticator, authenticated, anon;


-- ===== 0002_rbac.sql =====

-- ── RBAC: Kubernetes-Style Authorization ───────────────────────────────
--
-- WHAT: Role-Based Access Control modeled after Kubernetes RBAC.
--       Subjects (User/Group/ServiceAccount) → Roles → Bindings → Scopes.
--
-- WHY:  Replaced legacy per-table membership with a unified authorization
--       model. One system handles team, project, secret, and cluster access.
--
-- MODEL:
--   rbac.roles       — Named roles (global-admin, team-owner, project-read, etc.)
--   rbac.role_rules  — Policy rules per role: resources[] × verbs[]
--                      e.g., resources=['secrets'], verbs=['get','list','reveal']
--                      Wildcard '*' matches any resource or verb.
--   rbac.bindings    — Links a subject to a role at a scope.
--                      subject_kind: 'User' | 'Group' | 'ServiceAccount'
--                      scope_kind:   'cluster' | 'team' | 'project' | 'secret'
--
-- SCOPE CHAIN (ancestry):
--   secret → project → team → cluster
--   A binding at 'team' scope applies to all projects and secrets in that team.
--   A binding at 'secret' scope applies only to that specific secret.
--
-- AUTHORIZATION FLOW:
--   1. api.can(verb, resource, scope_kind, scope_id) is called.
--   2. Global admin check → short-circuit to true.
--   3. Deleted secret check → reject.
--   4. Resolve subjects: api.rbac_subjects() → ('User', uid) + ('Group', gid)×N
--   5. Walk scope chain: api.rbac_scope_chain() → all ancestor scopes.
--   6. Join bindings × role_rules × subjects × scopes.
--   7. api.rbac_rule_matches() checks resource/verb against rule arrays.
--   8. Any match → true; no match → false.
--
-- SECURITY: rbac schema has RLS + FORCE RLS. Bindings are validated by
--           trigger (rbac.validate_binding_scope) to prevent role/scope
--           mismatches (e.g., team-owner role at project scope).

CREATE SCHEMA rbac;
GRANT USAGE ON SCHEMA rbac TO authenticator, authenticated, anon;

-- ── RBAC Roles ─────────────────────────────────────────────────────────
--
-- WHAT: Named roles with optional description and built_in flag.
--
-- WHY:  Roles are the permission sets that bindings reference. built_in
--       roles are seeded by rbac.ensure_builtin_roles() and cannot be
--       deleted by users.
--
-- RLS: SELECT for all authenticated; write for global admins only.
CREATE TABLE IF NOT EXISTS rbac.roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  built_in boolean NOT NULL DEFAULT false,
  -- Which scope_kind values this role may be bound at. Replaces the old
  -- by-name convention (team-%/project-%/...) scattered through app code.
  scopes text[] NOT NULL DEFAULT '{}'
    CHECK (scopes <@ ARRAY['cluster', 'team', 'project', 'folder', 'secret']),
  -- Directory-map precedence ("highest wins"); 0 = never auto-assigned.
  precedence int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ── RBAC Role Rules ────────────────────────────────────────────────────
--
-- WHAT: Policy rules defining what resources and verbs a role permits.
--       Kubernetes-style: one row = one PolicyRule (resources[] × verbs[]).
--
-- WHY:  Decouples permissions from role names. A role can have multiple
--       rules (e.g., read projects + write secrets). Wildcard '*' in
--       resources or verbs matches anything.
--
-- EXAMPLE: global-admin → resources=['*'], verbs=['*']
--          team-member → resources=['projects','secrets'], verbs=['get','list','create','update']
--
-- RELATIONSHIPS: FK role_id → rbac.roles(id) CASCADE.
-- INDEX: On role_id for rule lookup during authorization.
-- RLS: SELECT for all authenticated; write for global admins only.
CREATE TABLE IF NOT EXISTS rbac.role_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
  resources text[] NOT NULL,
  verbs text[] NOT NULL,
  CHECK (cardinality(resources) >= 1),
  CHECK (cardinality(verbs) >= 1)
);
CREATE INDEX IF NOT EXISTS role_rules_role_idx ON rbac.role_rules(role_id);

-- ── RBAC Bindings (RoleBindings) ───────────────────────────────────────
--
-- WHAT: Links a subject (User/Group/ServiceAccount) to a role at a scope.
--
-- WHY:  This is the authorization graph. A binding says "this subject has
--       this role's permissions at this scope."
--
-- KEY COLUMNS:
--   subject_kind  — 'User' (direct), 'Group' (via group_members),
--                   'ServiceAccount' (machine tokens).
--   subject_id    — UUID of the user, group, or machine token.
--   scope_kind    — 'cluster' (global), 'team', 'project', 'folder', 'secret'.
--   scope_id      — NULL for cluster; UUID for team/project/secret.
--   source        — 'manual' | 'ldap' | 'oidc'; how the binding was created.
--   created_by    — User who created the binding (audit).
--
-- CONSTRAINTS:
--   - Cluster scope requires NULL scope_id; non-cluster requires non-NULL.
--   - Unique index prevents duplicate (role, subject, scope) bindings.
--
-- INDEXES:
--   bindings_subject_idx  — Fast lookup: "what bindings does this subject have?"
--   bindings_scope_idx    — Fast lookup: "what bindings apply at this scope?"
--   bindings_role_idx     — Fast lookup: "who has this role?"
--   bindings_unique_idx   — Prevents duplicate bindings.
--
-- RLS: SELECT for scope managers or self; write via can_manage_rbac().
-- TRIGGER: validate_binding_scope() enforces role/scope compatibility
--          (e.g., team-owner role only at team scope).
-- TRIGGER: guard_last_team_owner_binding() prevents removing the last
--          team-owner, ensuring teams always have an owner.
CREATE TABLE IF NOT EXISTS rbac.bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
  subject_kind text NOT NULL
    CHECK (subject_kind IN ('User', 'Group', 'ServiceAccount')),
  subject_id uuid NOT NULL,
  -- cluster | team | project | folder | secret
  scope_kind text NOT NULL
    CHECK (scope_kind IN ('cluster', 'team', 'project', 'folder', 'secret')),
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

  -- auditor (cluster scope)
  INSERT INTO rbac.roles (name, description, built_in)
  VALUES ('auditor', 'Read-only access to audit logs across the organization', true)
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

  -- Role scope assignment (drives UI dropdowns, binding validation, and
  -- directory-map rank — replaces the old team-%/project-% name convention).
  UPDATE rbac.roles SET scopes = ARRAY['cluster'], precedence = 0
   WHERE name IN ('global-admin', 'audit-viewer');
  UPDATE rbac.roles SET scopes = ARRAY['team'], precedence = 4 WHERE name = 'team-owner';
  UPDATE rbac.roles SET scopes = ARRAY['team'], precedence = 3 WHERE name = 'team-admin';
  UPDATE rbac.roles SET scopes = ARRAY['team'], precedence = 2 WHERE name = 'team-member';
  UPDATE rbac.roles SET scopes = ARRAY['team'], precedence = 1 WHERE name = 'team-viewer';
  UPDATE rbac.roles SET scopes = ARRAY['team'], precedence = 0 WHERE name = 'team-audit-viewer';
  UPDATE rbac.roles SET scopes = ARRAY['project'], precedence = 0 WHERE name LIKE 'project-%';
  UPDATE rbac.roles SET scopes = ARRAY['folder', 'secret'], precedence = 0 WHERE name LIKE 'secret-%';
  UPDATE rbac.roles SET scopes = ARRAY['project', 'folder', 'secret'], precedence = 0 WHERE name LIKE 'service-%';
  UPDATE rbac.roles SET scopes = ARRAY['team', 'project', 'folder', 'secret'], precedence = 0 WHERE name = 'auditor';
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
-- Chain resolution now includes the folder level between secret and project.
CREATE OR REPLACE FUNCTION api.rbac_scope_chain(
  p_scope_kind text,
  p_scope_id uuid
) RETURNS TABLE(scope_kind text, scope_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, rbac, pg_catalog
SET row_security = off AS $$
DECLARE
  v_project uuid;
  v_folder uuid;
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
    SELECT s.folder_id, s.project_id INTO v_folder, v_project
    FROM api.secrets s WHERE s.id = p_scope_id;
    IF v_folder IS NOT NULL THEN
      scope_kind := 'folder'; scope_id := v_folder; RETURN NEXT;
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
    scope_kind := 'folder'; scope_id := p_scope_id; RETURN NEXT;
    SELECT f.project_id INTO v_project FROM api.folders f WHERE f.id = p_scope_id;
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
LANGUAGE sql IMMUTABLE SECURITY INVOKER AS $$
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
-- Superseded by the folder-aware can_access_secret_row below (7 args with
-- v_folder/v_subject). Dropped so the old 5-arg form cannot shadow it.
DROP FUNCTION IF EXISTS api.can_access_secret_row(uuid, uuid, text, text, timestamptz);

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
--   1. Deleted secrets cannot be revealed (restore requires write access).
--   2. Global admins and project admins always pass.
--   3. Must be able to see the secret (read).
--   4. If an approved access request exists, pass.
--   5. If reveal ACL grants it and no approval needed, pass.
--
-- Input:  sid (uuid: secret id)
-- Output: boolean — true if reveal allowed now
-- Example: SELECT api.can_reveal_secret('<secret-uuid>');
CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
    WHEN NOT EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid AND s.deleted_at IS NULL
    ) THEN false
    WHEN api.is_global_admin() THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid
        AND s.deleted_at IS NULL
        AND api.can_admin_project(s.project_id)
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'read') THEN false
    WHEN EXISTS (
      SELECT 1 FROM api.secret_access_requests r
      WHERE r.secret_id = sid
        AND r.user_id = api.current_user_id()
        AND r.status = 'approved'
        AND r.approved_until IS NOT NULL
        AND r.approved_until > now()
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
    WHEN NOT COALESCE(api.secret_requires_approval(sid), false) THEN true
    ELSE false
  END;
$$;

GRANT EXECUTE ON FUNCTION api.can_reveal_secret TO authenticated, anon;

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
    SELECT 'folder', f.id,
      COALESCE(p3.name, '') || ' / ' || f.name
      FROM api.folders f LEFT JOIN api.projects p3 ON p3.id = f.project_id
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

-- Secrets: project admins pass; folder-bound secrets check folder bindings;
-- restricted mode uses secret bindings; otherwise inherit project/team RBAC.
CREATE OR REPLACE FUNCTION api.can_access_secret_row(
  sid uuid,
  pid uuid,
  mode text,
  need text DEFAULT 'read',
  deleted_at timestamptz DEFAULT NULL,
  v_folder uuid DEFAULT NULL,
  v_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL OR pid IS NULL THEN false
    WHEN deleted_at IS NOT NULL THEN false
    WHEN need IS NULL OR need NOT IN ('read', 'reveal', 'write') THEN false
    WHEN api.can_admin_project(pid) THEN true
    -- Folder bindings grant access additively; when they do not match,
    -- evaluation falls through to the inherit/restricted checks below.
    WHEN v_folder IS NOT NULL
     AND api.rbac_folder_binding_allows(v_folder, need, v_subject) THEN true
    WHEN COALESCE(mode, 'inherit') = 'restricted' THEN
      api.rbac_secret_binding_allows(sid, need, v_subject)
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

-- ── RLS Policies (created after auth functions exist) ──────────────────
--
-- WHAT: Row-Level Security policies for every api table.
--
-- WHY:  Policies must be defined after RBAC auth functions (api.can(),
--       api.is_team_member(), etc.) exist, since policies reference them.
--
-- SECURITY STRATEGY:
--   1. Global admins short-circuit: api.is_global_admin() → true on most tables.
--   2. Scoped access uses recursive RBAC: api.can(verb, resource, scope, id)
--      walks the scope chain (secret → project → team → cluster).
--   3. authenticator bypasses RLS for system tasks (audit writes, auth sync).
--   4. anon has minimal access (OIDC/LDAP discovery, health checks).
--
-- CONVENTION:
--   - Policies target the `authenticated` role (SET ROLE from JWT).
--   - SELECT policies use USING clause.
--   - INSERT policies use WITH CHECK clause.
--   - UPDATE/DELETE policies use both USING (old row) and WITH CHECK (new row).
--   - Secret access uses api.can_access_secret_row() which handles both
--     'inherit' mode (full RBAC scope chain) and 'restricted' mode
--     (secret-scope bindings only).
--
-- POLICY NAMING: <table>_<operation> (e.g., teams_select, secrets_insert).
--                Abbreviated names where long (tlm = team_ldap_maps,
--                tom = team_oidc_maps, gm = group_members, mt = machine_tokens,
--                mts = machine_token_scope).

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
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );
DROP POLICY IF EXISTS secret_pins_insert ON api.secret_pins;
CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
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
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );
DROP POLICY IF EXISTS secret_recent_insert ON api.secret_recent;
CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
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
    AND api.can_admin_project(project_id)
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
  WITH CHECK (api.can_admin_project(project_id));
DROP POLICY IF EXISTS mt_delete ON api.machine_tokens;
CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
  USING (api.can_admin_project(project_id));

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
      WHERE t.id = token_id AND api.can_admin_project(t.project_id)
    )
  );
DROP POLICY IF EXISTS mts_delete ON api.machine_token_scope;
CREATE POLICY mts_delete ON api.machine_token_scope FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_admin_project(t.project_id)
    )
  );


-- ===== 0020_security_hardening.sql =====

-- 0020_security_hardening
-- FORCE RLS, hardened search_path, policy hardening


DROP POLICY IF EXISTS projects_update ON api.projects;
CREATE POLICY projects_update ON api.projects FOR UPDATE TO authenticated
          USING (api.can_admin_project(id));

REVOKE INSERT, UPDATE, DELETE ON api.secret_versions FROM authenticated;

REVOKE ALL ON api.user_directory FROM anon;

ALTER TABLE api.teams FORCE ROW LEVEL SECURITY;

ALTER TABLE api.projects FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secrets FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secret_versions FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secret_meta FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secret_access_requests FORCE ROW LEVEL SECURITY;

ALTER TABLE api.machine_tokens FORCE ROW LEVEL SECURITY;

ALTER TABLE api.groups FORCE ROW LEVEL SECURITY;

ALTER TABLE api.group_members FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION private.lookup_user(p_email text)
        RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, private
        SET row_security = off AS $$
          SELECT id FROM private.users WHERE email = lower(p_email) LIMIT 1;
        $$;

REVOKE EXECUTE ON FUNCTION private.lookup_user FROM PUBLIC;


-- ===== 0021_machine_token_scopes.sql =====

-- 0021_machine_token_scopes
-- machine token key scopes + scope-aware machine helpers

CREATE TABLE IF NOT EXISTS api.machine_token_scope (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          token_id uuid NOT NULL REFERENCES api.machine_tokens(id) ON DELETE CASCADE,
          secret_key text,
          key_pattern text,
          created_at timestamptz NOT NULL DEFAULT now(),
          CHECK (
            (
              secret_key IS NOT NULL AND btrim(secret_key) <> '' AND key_pattern IS NULL
            ) OR (
              key_pattern IS NOT NULL AND btrim(key_pattern) <> '' AND secret_key IS NULL
            )
          )
        );

CREATE UNIQUE INDEX IF NOT EXISTS machine_token_scope_exact_uidx
          ON api.machine_token_scope (token_id, secret_key) WHERE secret_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS machine_token_scope_pattern_uidx
          ON api.machine_token_scope (token_id, key_pattern) WHERE key_pattern IS NOT NULL;

CREATE INDEX IF NOT EXISTS machine_token_scope_token_idx
          ON api.machine_token_scope (token_id);

ALTER TABLE api.machine_token_scope ENABLE ROW LEVEL SECURITY;

ALTER TABLE api.machine_token_scope FORCE ROW LEVEL SECURITY;


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
              WHERE t.id = token_id AND api.can_admin_project(t.project_id)
            )
          );


DROP POLICY IF EXISTS mts_delete ON api.machine_token_scope;
CREATE POLICY mts_delete ON api.machine_token_scope FOR DELETE TO authenticated
          USING (
            EXISTS (
              SELECT 1 FROM api.machine_tokens t
              WHERE t.id = token_id AND api.can_admin_project(t.project_id)
            )
          );

GRANT SELECT, INSERT, DELETE ON api.machine_token_scope TO authenticated;

GRANT ALL ON api.machine_token_scope TO authenticator;

-- Shell-style glob (* ?) → SQL LIKE pattern (escape % and _).
        --
        -- Input:  p_glob (text: shell-style glob, e.g. 'API_*')
        -- Output: text — SQL LIKE pattern, e.g. 'API\_%'
        -- Example: SELECT private.glob_to_like('API_*');
        CREATE OR REPLACE FUNCTION private.glob_to_like(p_glob text)
        RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT
        SET search_path = pg_catalog AS $$
        DECLARE s text;
        BEGIN
          s := replace(p_glob, E'\\', E'\\\\');
          s := replace(s, '%', E'\\%');
          s := replace(s, '_', E'\\_');
          s := replace(s, '*', '%');
          s := replace(s, '?', '_');
          RETURN s;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_key_allowed(
          p_project uuid, p_hash text, p_key text
        ) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
          SELECT CASE
            WHEN p_key IS NULL OR btrim(p_key) = '' THEN false
            WHEN NOT private.auth_machine(p_project, p_hash) THEN false
            WHEN NOT EXISTS (
              SELECT 1
              FROM api.machine_token_scope sc
              JOIN api.machine_tokens t ON t.id = sc.token_id
              WHERE t.project_id = p_project
                AND t.token_hash = p_hash
                AND (t.expires_at IS NULL OR t.expires_at > now())
            ) THEN true
            WHEN EXISTS (
              SELECT 1
              FROM api.machine_token_scope sc
              JOIN api.machine_tokens t ON t.id = sc.token_id
              WHERE t.project_id = p_project
                AND t.token_hash = p_hash
                AND (t.expires_at IS NULL OR t.expires_at > now())
                AND (
                  (sc.secret_key IS NOT NULL AND sc.secret_key = p_key)
                  OR (
                    sc.key_pattern IS NOT NULL
                    AND p_key LIKE private.glob_to_like(sc.key_pattern) ESCAPE E'\\'
                  )
                )
            ) THEN true
            ELSE false
          END;
        $$;

GRANT EXECUTE ON FUNCTION private.glob_to_like TO authenticator;

GRANT EXECUTE ON FUNCTION private.machine_key_allowed TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
        RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN NULL;
          END IF;
          RETURN (
            SELECT value_enc FROM api.secrets
            WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
          );
        END;
        $$;

DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
        RETURNS TABLE (
          id uuid, key text, value_enc text, note text, kind text,
          expires_at timestamptz, created_at timestamptz, updated_at timestamptz
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at, s.created_at, s.updated_at
            FROM api.secrets s
            WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
        END;
        $$;

DROP FUNCTION IF EXISTS private.machine_list_enc(uuid, text);
CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
        RETURNS TABLE (key text, value_enc text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.key, s.value_enc FROM api.secrets s
            WHERE s.project_id = p_project AND s.deleted_at IS NULL
              AND private.machine_key_allowed(p_project, p_hash, s.key);
        END;
        $$;

DROP FUNCTION IF EXISTS private.machine_list_meta(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_list_meta(
          p_project uuid, p_hash text, p_q text DEFAULT NULL
        )
        RETURNS TABLE (
          id uuid, key text, note text, kind text,
          expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
          rotation_next_at timestamptz, rotated_at timestamptz,
          created_at timestamptz, updated_at timestamptz, metadata jsonb
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        DECLARE q text := NULLIF(btrim(COALESCE(p_q, '')), '');
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.note, s.kind, s.expires_at,
                   s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
                   s.created_at, s.updated_at,
                   COALESCE(
                     (SELECT jsonb_object_agg(m.key, m.value)
                      FROM api.secret_meta m
                      WHERE m.secret_id = s.id),
                     '{}'::jsonb
                   ) AS metadata
            FROM api.secrets s
            WHERE s.project_id = p_project
              AND s.deleted_at IS NULL
              AND private.machine_key_allowed(p_project, p_hash, s.key)
              AND (
                q IS NULL
                OR s.key ILIKE ('%' || q || '%')
                OR s.note ILIKE ('%' || q || '%')
                OR EXISTS (
                  SELECT 1 FROM api.secret_meta m
                  WHERE m.secret_id = s.id
                    AND (m.key ILIKE ('%' || q || '%') OR m.value ILIKE ('%' || q || '%'))
                )
              )
            ORDER BY s.key;
        END;
        $$;
GRANT EXECUTE ON FUNCTION private.machine_list_meta TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_delete(
          p_project uuid, p_hash text, p_key text
        )
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        DECLARE sid uuid;
        BEGIN
          IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
            RETURN NULL;
          END IF;
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN NULL;
          END IF;
          IF p_key IS NULL OR btrim(p_key) = '' THEN
            RETURN NULL;
          END IF;
          UPDATE api.secrets
          SET deleted_at = now
          WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
          RETURNING id INTO sid;
          RETURN sid;
        END;
        $$;

-- 0006 dropped the stale 8-arg machine_upsert_enc (no provider); the 9-arg
-- form below is canonical. The DROP is a no-op on fresh installs.
DROP FUNCTION IF EXISTS
  private.machine_upsert_enc(uuid, text, text, text, text, text, timestamptz, boolean);


-- ===== 0022_shared_with_me.sql =====

-- 0022_shared_with_me
-- Secrets shared via secret-scope bindings with non-team users.
-- Adds a list helper and lets grantees SELECT the owning project/team labels.

CREATE OR REPLACE FUNCTION private.shared_with_me_secret_rows()
RETURNS TABLE(
  id uuid,
  key text,
  note text,
  kind text,
  project_id uuid,
  project_name text,
  team_id uuid,
  team_name text,
  access_mode text,
  updated_at timestamptz,
  expires_at timestamptz,
  rotation_interval_days integer,
  rotation_owner text,
  rotation_next_at timestamptz,
  rotated_at timestamptz,
  role_name text
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
  SELECT DISTINCT ON (s.id)
    s.id,
    s.key,
    s.note,
    s.kind,
    p.id AS project_id,
    p.name AS project_name,
    t.id AS team_id,
    t.name AS team_name,
    s.access_mode,
    s.updated_at,
    s.expires_at,
    s.rotation_interval_days,
    s.rotation_owner,
    s.rotation_next_at,
    s.rotated_at,
    r.name AS role_name
  FROM api.rbac_subjects(api.current_user_id()) sub
  JOIN rbac.bindings b
    ON b.subject_kind = sub.subject_kind
   AND b.subject_id = sub.subject_id
   AND b.scope_kind = 'secret'
  JOIN rbac.roles r ON r.id = b.role_id
  JOIN api.secrets s ON s.id = b.scope_id AND s.deleted_at IS NULL
  JOIN api.projects p ON p.id = s.project_id
  JOIN api.teams t ON t.id = p.team_id
  WHERE NOT api.is_team_member(p.team_id)
    AND NOT COALESCE(api.secret_requires_approval(s.id), false)
    AND api.can_access_secret_row(
      s.id, s.project_id, s.access_mode, 'read', NULL
    )
  ORDER BY s.id, r.name;
$$;

GRANT EXECUTE ON FUNCTION private.shared_with_me_secret_rows
  TO authenticator, authenticated;

DROP POLICY IF EXISTS teams_select ON api.teams;
CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
  USING (
    api.is_global_admin()
    OR api.is_team_member(id)
    -- Shared-secret grantees need the team label on secret views / Shared secrets
    OR EXISTS (
      SELECT 1
      FROM api.projects p
      JOIN api.secrets s ON s.project_id = p.id AND s.deleted_at IS NULL
      WHERE p.team_id = teams.id
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS projects_select ON api.projects;
CREATE POLICY projects_select ON api.projects FOR SELECT TO authenticated
  USING (
    api.is_team_member(team_id)
    -- Shared-secret grantees can open the secret view (JOIN projects)
    OR EXISTS (
      SELECT 1
      FROM api.secrets s
      WHERE s.project_id = projects.id
        AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );


-- ===== 0023_shared_recent_pins.sql =====

-- 0023_shared_recent_pins
-- Pins and recently-accessed rows must allow secret-scope grantees, not only
-- project members. Viewing a shared secret used to fail RLS on secret_recent
-- INSERT and abort the rest of the view transaction.

DROP POLICY IF EXISTS secret_pins_select ON api.secret_pins;
CREATE POLICY secret_pins_select ON api.secret_pins FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS secret_pins_insert ON api.secret_pins;
CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS secret_recent_select ON api.secret_recent;
CREATE POLICY secret_recent_select ON api.secret_recent FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS secret_recent_insert ON api.secret_recent;
CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );


-- ===== 0024_project_crypto.sql =====

-- Per-project Bring-Your-Own-Key (BYOK) support.
--
-- Each project may have a dedicated data-encryption key (DEK). The DEK is a
-- random Fernet key, stored wrapped ("enveloped") by the app MASTER_KEY in
-- private.project_crypto_keys — the raw DEK is never stored. Secret values
-- encrypted with a project DEK are marked ``crypto_provider='project'``;
-- values still encrypted with the app master key (legacy / non-BYOK) are
-- marked ``crypto_provider='master'``. Secret version snapshots carry the same
-- marker so history stays decryptable.
--
-- Added only: new tables and columns. Existing baseline DDL is untouched
-- (the runner never re-applies 0001/0002).

CREATE TABLE IF NOT EXISTS private.project_crypto_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  -- DEK wrapped by MASTER_KEY (Fernet); never store the raw key.
  key_enc text NOT NULL,
  -- Key material origin: 'local' (generated & stored server-side) now;
  -- 'kms' later.
  key_provider text NOT NULL DEFAULT 'local',
  -- Future: external key reference (e.g. KMS ARN / URI) when key_provider=kms.
  kms_key_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id)
);

REVOKE ALL ON private.project_crypto_keys FROM authenticator, authenticated, anon;

-- Which key encrypted this secret's value_enc: 'master' (app key) or 'project'
-- (this project's DEK). Defaults to 'master' for existing rows.
ALTER TABLE api.secrets
  ADD COLUMN IF NOT EXISTS crypto_provider text NOT NULL DEFAULT 'master';

ALTER TABLE api.secret_versions
  ADD COLUMN IF NOT EXISTS crypto_provider text NOT NULL DEFAULT 'master';

-- Copy the provider into archived versions so history can be decrypted.
CREATE OR REPLACE FUNCTION api.archive_secret_version()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api, private
SET row_security = off AS $$
BEGIN
  IF OLD.value_enc IS DISTINCT FROM NEW.value_enc THEN
    INSERT INTO api.secret_versions (secret_id, value_enc, note, crypto_provider)
    VALUES (OLD.id, OLD.value_enc, OLD.note, OLD.crypto_provider);
  END IF;
  RETURN NEW;
END;
$$;

-- Machine read helper returns the provider so the app can pick the right key.
-- Return type changed (added crypto_provider) → drop old signature first.
DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
        RETURNS TABLE (
          id uuid, key text, value_enc text, note text, kind text,
          expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
          rotation_next_at timestamptz, rotated_at timestamptz,
          created_at timestamptz, updated_at timestamptz,
          crypto_provider text
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
                   s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
                   s.created_at, s.updated_at, s.crypto_provider
            FROM api.secrets s
            WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
        END;
        $$;
GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;

-- Machine bulk value listing also reports per-row provider (return type changed
-- → drop the old 3-column form first).
DROP FUNCTION IF EXISTS private.machine_list_enc(uuid, text);
CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
        RETURNS TABLE (key text, value_enc text, crypto_provider text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          IF private.machine_role(p_project, p_hash) = 'service-read' THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.key, s.value_enc, s.crypto_provider FROM api.secrets s
            WHERE s.project_id = p_project AND s.deleted_at IS NULL
              AND private.machine_key_allowed(p_project, p_hash, s.key);
        END;
        $$;

-- Squashed from 0006/0007/0008: folder-aware upsert (slash keys materialize
-- folders), provider-tagged writes, conflict targets matching the folder
-- split partial indexes. v_folder_id avoids shadowing secrets.folder_id.
CREATE OR REPLACE FUNCTION private.machine_upsert_enc(
  p_project uuid,
  p_hash text,
  p_key text,
  p_value_enc text,
  p_note text,
  p_kind text DEFAULT 'plain',
  p_expires_at timestamptz DEFAULT NULL,
  p_set_expires boolean DEFAULT false,
  p_crypto_provider text DEFAULT 'master'
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE
  sid uuid;
  k text := COALESCE(NULLIF(btrim(p_kind), ''), 'plain');
  parts text[];
  folder_segments text[];
  v_folder_id uuid;
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
    RETURN NULL;
  END IF;
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN NULL;
  END IF;
  IF p_key IS NULL OR btrim(p_key) = '' OR p_value_enc IS NULL THEN
    RETURN NULL;
  END IF;
  IF k NOT IN ('plain', 'database', 'certificate', 'ssh', 'kv') THEN
    k := 'plain';
  END IF;

  -- Parse key into folder segments + leaf name
  parts := string_to_array(p_key, '/');
  IF array_length(parts, 1) > 1 THEN
    folder_segments := parts[1:array_length(parts, 1) - 1];
    FOR i IN 1 .. array_length(folder_segments, 1) LOOP
      v_folder_id := private.materialize_folder_path(
        p_project,
        CASE WHEN i = 1 THEN NULL ELSE v_folder_id END,
        folder_segments[i],
        (SELECT array_to_string(folder_segments[1:i], '/'))
      );
    END LOOP;
    INSERT INTO api.secrets (project_id, folder_id, key, value_enc, note, kind, expires_at, crypto_provider)
    VALUES (
      p_project, v_folder_id, p_key, p_value_enc, COALESCE(p_note, ''), k,
      CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END,
      CASE WHEN p_crypto_provider IN ('master', 'project') THEN p_crypto_provider ELSE 'master' END
    )
    ON CONFLICT (project_id, folder_id, key) WHERE folder_id IS NOT NULL AND deleted_at IS NULL DO UPDATE
      SET value_enc = EXCLUDED.value_enc,
          note = EXCLUDED.note,
          kind = EXCLUDED.kind,
          crypto_provider = EXCLUDED.crypto_provider,
          expires_at = CASE
            WHEN p_set_expires THEN p_expires_at
            ELSE api.secrets.expires_at
          END
    RETURNING id INTO sid;
  ELSE
    INSERT INTO api.secrets (project_id, key, value_enc, note, kind, expires_at, crypto_provider)
    VALUES (
      p_project, p_key, p_value_enc, COALESCE(p_note, ''), k,
      CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END,
      CASE WHEN p_crypto_provider IN ('master', 'project') THEN p_crypto_provider ELSE 'master' END
    )
    ON CONFLICT (project_id, key) WHERE folder_id IS NULL AND deleted_at IS NULL DO UPDATE
      SET value_enc = EXCLUDED.value_enc,
          note = EXCLUDED.note,
          kind = EXCLUDED.kind,
          crypto_provider = EXCLUDED.crypto_provider,
          expires_at = CASE
            WHEN p_set_expires THEN p_expires_at
            ELSE api.secrets.expires_at
          END
    RETURNING id INTO sid;
  END IF;
  RETURN sid;
END;
$$;

-- The 9-arg overload is a distinct function: it needs its own grant
-- (the earlier bare GRANT attached to the 8-arg form only). ESO write
-- paths call this overload as authenticator.
GRANT EXECUTE ON FUNCTION
  private.machine_upsert_enc(uuid, text, text, text, text, text, timestamptz, boolean, text)
  TO authenticator;

-- Squashed from 0009_machine_set_meta.sql: privileged helper for persisting
-- agent-supplied secret metadata (validated key allow-list enforced in app).
CREATE OR REPLACE FUNCTION private.machine_set_meta(
  p_project uuid,
  p_hash text,
  p_key text,
  p_meta_key text,
  p_meta_value text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE
  v_secret_id uuid;
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
    RAISE EXCEPTION 'machine_set_meta requires service-write';
  END IF;
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RAISE EXCEPTION 'machine_set_meta: key not allowed';
  END IF;
  SELECT id INTO v_secret_id
  FROM api.secrets
  WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL;
  IF v_secret_id IS NULL THEN
    RAISE EXCEPTION 'machine_set_meta: secret not found';
  END IF;
  INSERT INTO api.secret_meta (secret_id, key, value)
  VALUES (v_secret_id, p_meta_key, COALESCE(p_meta_value, ''))
  ON CONFLICT (secret_id, key) DO UPDATE SET value = EXCLUDED.value;
END;
$$;
GRANT EXECUTE ON FUNCTION private.machine_set_meta TO authenticator;

-- ===== 0025_project_key_provider.sql =====

-- Expose a project's BYOK key provider to authenticated readers for list badges.
--
-- The app needs to show an "HSM" / "BYOK" indicator in project lists without
-- leaking the wrapped DEK in private.project_crypto_keys. This SECURITY DEFINER
-- helper returns only the ``key_provider`` string, gated on project read access.

CREATE OR REPLACE FUNCTION api.project_key_provider(p_project uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT k.key_provider
  FROM private.project_crypto_keys k
  WHERE k.project_id = p_project
    AND (api.is_global_admin() OR api.can_read_project(p_project));
$$;

GRANT EXECUTE ON FUNCTION api.project_key_provider(uuid) TO authenticator, authenticated, anon;


-- ===== 0026_project_key_providers.sql =====

-- Batch key-provider lookup for project lists (avoids N+1 per-project calls).
--
-- Same gating as api.project_key_provider(): only reveals the provider string
-- for projects the current user can read (or for global admins).

CREATE OR REPLACE FUNCTION api.project_key_providers(p_ids uuid[])
RETURNS TABLE(project_id uuid, key_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
    SELECT k.project_id, k.key_provider
    FROM private.project_crypto_keys k
    JOIN api.projects p ON p.id = k.project_id
    WHERE k.project_id = ANY(p_ids)
      AND (api.is_global_admin() OR api.can_read_project(k.project_id));
END;
$$;

GRANT EXECUTE ON FUNCTION api.project_key_providers(uuid[]) TO authenticator, authenticated, anon;

-- ===== 0027_hsm_slots.sql =====

-- Multi-HSM slots: named PKCS#11 URL configurations for BYOK.
--
-- A project's crypto key may link to a named slot (hsm_slot_id) instead of
-- relying on the global env-var HSM config. The app resolves the slot's
-- PKCS#11 URL and opens a session against that module/token.

CREATE TABLE IF NOT EXISTS private.hsm_slots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  pkcs11_url text NOT NULL,
  description text NOT NULL DEFAULT '',
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON private.hsm_slots FROM authenticator, authenticated, anon;

ALTER TABLE private.project_crypto_keys
  ADD COLUMN IF NOT EXISTS hsm_slot_id uuid
    REFERENCES private.hsm_slots(id) ON DELETE SET NULL;

-- List all slots (defaults first, then by name). Any authenticated user may
-- read slot names/URLs; the answers never include a PIN (redacted at render).
CREATE OR REPLACE FUNCTION api.list_hsm_slots()
RETURNS TABLE (
  id uuid, name text, pkcs11_url text, description text,
  is_default boolean, created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT s.id, s.name, s.pkcs11_url, s.description, s.is_default, s.created_at
  FROM private.hsm_slots s
  ORDER BY s.is_default DESC, s.name;
$$;

GRANT EXECUTE ON FUNCTION api.list_hsm_slots() TO authenticator, authenticated, anon;

-- Resolve a slot's PKCS#11 URL (used by the crypto layer to unwrap DEKs).
CREATE OR REPLACE FUNCTION api.hsm_slot_url(p_slot_id uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT s.pkcs11_url FROM private.hsm_slots s WHERE s.id = p_slot_id;
$$;

GRANT EXECUTE ON FUNCTION api.hsm_slot_url(uuid) TO authenticator, authenticated, anon;

-- Create or update a slot (global admins only). Setting is_default=true clears
-- the flag on every other slot first. Returns the slot id.
CREATE OR REPLACE FUNCTION api.hsm_slot_upsert(
  p_id uuid,
  p_name text,
  p_url text,
  p_description text DEFAULT '',
  p_is_default boolean DEFAULT false
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
DECLARE v_id uuid;
BEGIN
  IF NOT api.is_global_admin() THEN
    RAISE EXCEPTION 'global admin required';
  END IF;
  IF p_id IS NULL THEN
    IF p_is_default THEN
      UPDATE private.hsm_slots SET is_default = false WHERE is_default;
    END IF;
    INSERT INTO private.hsm_slots (name, pkcs11_url, description, is_default)
    VALUES (btrim(p_name), p_url, COALESCE(p_description, ''), COALESCE(p_is_default, false))
    RETURNING id INTO v_id;
  ELSE
    IF p_is_default THEN
      UPDATE private.hsm_slots SET is_default = false WHERE is_default AND id <> p_id;
    END IF;
    UPDATE private.hsm_slots
    SET name = btrim(p_name),
        pkcs11_url = p_url,
        description = COALESCE(p_description, ''),
        is_default = COALESCE(p_is_default, false),
        updated_at = now()
    WHERE id = p_id
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION api.hsm_slot_upsert(uuid, text, text, text, boolean)
  TO authenticator, authenticated, anon;

-- Delete a slot (global admin only); blocks when projects still reference it.
CREATE OR REPLACE FUNCTION api.hsm_slot_delete(p_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  IF NOT api.is_global_admin() THEN
    RAISE EXCEPTION 'global admin required';
  END IF;
  IF EXISTS (
    SELECT 1 FROM private.project_crypto_keys k WHERE k.hsm_slot_id = p_id
  ) THEN
    RAISE EXCEPTION 'slot is in use by one or more projects';
  END IF;
  DELETE FROM private.hsm_slots WHERE id = p_id;
END;
$$;

GRANT EXECUTE ON FUNCTION api.hsm_slot_delete(uuid) TO authenticator, authenticated, anon;

-- ===== 0028_hsm_rls_hardening.sql =====

CREATE OR REPLACE FUNCTION api.list_hsm_slots()
RETURNS TABLE (
  id uuid, name text, pkcs11_url text, description text,
  is_default boolean, created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
  SELECT s.id, s.name,
         CASE WHEN api.is_global_admin() THEN s.pkcs11_url ELSE NULL END,
         s.description, s.is_default, s.created_at
  FROM private.hsm_slots s
  ORDER BY s.is_default DESC, s.name;
$$;

REVOKE EXECUTE ON FUNCTION api.list_hsm_slots() FROM anon;
GRANT EXECUTE ON FUNCTION api.list_hsm_slots() TO authenticated;

REVOKE EXECUTE ON FUNCTION api.hsm_slot_url(uuid)
  FROM anon, authenticated, authenticator;
REVOKE EXECUTE ON FUNCTION api.hsm_slot_upsert(uuid, text, text, text, boolean) FROM anon;
REVOKE EXECUTE ON FUNCTION api.hsm_slot_delete(uuid) FROM anon;

CREATE OR REPLACE FUNCTION api.hsm_slot_upsert(
  p_id uuid,
  p_name text,
  p_url text,
  p_description text DEFAULT '',
  p_is_default boolean DEFAULT false
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
DECLARE v_id uuid;
BEGIN
  IF NOT api.is_global_admin() THEN
    RAISE EXCEPTION 'global admin required';
  END IF;
  IF p_id IS NULL THEN
    IF p_is_default THEN
      UPDATE private.hsm_slots SET is_default = false WHERE is_default;
    END IF;
    INSERT INTO private.hsm_slots (name, pkcs11_url, description, is_default)
    VALUES (btrim(p_name), p_url, COALESCE(p_description, ''), COALESCE(p_is_default, false))
    RETURNING id INTO v_id;
  ELSE
    IF EXISTS (
      SELECT 1 FROM private.project_crypto_keys
      WHERE hsm_slot_id = p_id
    ) AND EXISTS (
      SELECT 1 FROM private.hsm_slots
      WHERE id = p_id AND pkcs11_url IS DISTINCT FROM p_url
    ) THEN
      RAISE EXCEPTION 'cannot change the URL of a slot used by project keys; create a new slot and migrate the projects';
    END IF;
    IF p_is_default THEN
      UPDATE private.hsm_slots SET is_default = false WHERE is_default AND id <> p_id;
    END IF;
    UPDATE private.hsm_slots
    SET name = btrim(p_name),
        pkcs11_url = p_url,
        description = COALESCE(p_description, ''),
        is_default = COALESCE(p_is_default, false),
        updated_at = now()
    WHERE id = p_id
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION api.rbac_subjects(p_user uuid DEFAULT NULL)
RETURNS TABLE(subject_kind text, subject_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
  WITH u AS (
    SELECT CASE
      WHEN p_user IS NULL
        OR p_user IS NOT DISTINCT FROM api.current_user_id()
        OR api.is_global_admin()
      THEN COALESCE(p_user, api.current_user_id())
      ELSE NULL::uuid
    END AS id
  )
  SELECT 'User'::text, u.id FROM u WHERE u.id IS NOT NULL
  UNION ALL
  SELECT 'Group'::text, gm.group_id
  FROM u
  JOIN api.group_members gm ON gm.user_id = u.id;
$$;

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
DECLARE uid uuid := COALESCE(p_subject, api.current_user_id());
DECLARE v_verb text := lower(btrim(COALESCE(p_verb, '')));
DECLARE v_res text := lower(btrim(COALESCE(p_resource, '')));
DECLARE ok boolean;
BEGIN
  IF p_subject IS NOT NULL
     AND p_subject IS DISTINCT FROM api.current_user_id()
     AND NOT api.is_global_admin() THEN
    RETURN false;
  END IF;
  IF uid IS NULL OR v_verb = '' OR v_res = '' THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1 FROM private.users WHERE id = uid AND is_global_admin
  ) THEN
    RETURN true;
  END IF;
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

REVOKE EXECUTE ON FUNCTION api.rbac_subjects(uuid) FROM anon;


-- ===== 0029_rls_boundary_hardening.sql =====

-- RLS and privilege-boundary hardening.
--
-- 0028 revoked selected functions from named roles, but PostgreSQL grants
-- EXECUTE on newly-created functions to PUBLIC by default. Remove that
-- implicit surface before applying the narrower grants below.

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rbac FROM PUBLIC;

-- The only rbac-schema function intentionally callable by the application
-- connection is the startup role seeder.
GRANT EXECUTE ON FUNCTION rbac.ensure_builtin_roles() TO authenticator;

REVOKE EXECUTE ON FUNCTION api.hsm_slot_url(uuid)
  FROM PUBLIC, anon, authenticated, authenticator;
REVOKE EXECUTE ON FUNCTION api.list_hsm_slots()
  FROM PUBLIC, anon;

-- Do not expose token verifiers through the PostgREST table. The application
-- already selects the metadata columns explicitly; token_hash remains usable
-- by privileged server-side code.
REVOKE SELECT ON api.machine_tokens FROM authenticated;
-- Squashed from 0011/0013: operator label for the tokens tab.
ALTER TABLE api.machine_tokens
  ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
GRANT SELECT (
  id, project_id, name, token_prefix, role, expires_at, created_at, last_used_at, description
) ON api.machine_tokens TO authenticated;

-- All API tables must apply RLS even when queried by their table owner. The
-- database superuser still bypasses RLS by design; user-scoped application
-- paths must use db.as_user rather than db.connect_admin.
ALTER TABLE api.team_ldap_maps FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_oidc_maps FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_invites FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_join_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_pins FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_recent FORCE ROW LEVEL SECURITY;
ALTER TABLE api.org_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_audit FORCE ROW LEVEL SECURITY;

-- Access requests must always point at a secret in the same project, and the
-- request identity/target cannot be rewritten after creation.
CREATE OR REPLACE FUNCTION api.guard_secret_access_request()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM api.secrets s
    WHERE s.id = NEW.secret_id
      AND s.project_id = NEW.project_id
  ) THEN
    RAISE EXCEPTION 'secret does not belong to request project';
  END IF;

  IF TG_OP = 'INSERT'
     AND (NEW.status <> 'pending'
          OR NEW.resolved_at IS NOT NULL
          OR NEW.resolved_by IS NOT NULL
          OR NEW.approved_until IS NOT NULL) THEN
    RAISE EXCEPTION 'new access requests must be pending and unresolved';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'access request identity fields cannot be changed';
    END IF;
    IF OLD.status <> 'pending' AND NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'resolved access requests cannot change status';
    END IF;
    IF NEW.status = 'pending'
       AND (NEW.resolved_at IS NOT NULL
            OR NEW.resolved_by IS NOT NULL
            OR NEW.approved_until IS NOT NULL) THEN
      RAISE EXCEPTION 'pending access requests cannot have resolution fields';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_secret_access_request ON api.secret_access_requests;
CREATE TRIGGER guard_secret_access_request
BEFORE INSERT OR UPDATE ON api.secret_access_requests
FOR EACH ROW EXECUTE FUNCTION api.guard_secret_access_request();

DROP POLICY IF EXISTS secret_access_requests_insert ON api.secret_access_requests;
CREATE POLICY secret_access_requests_insert ON api.secret_access_requests
FOR INSERT TO authenticated
WITH CHECK (
  user_id = api.current_user_id()
  AND api.can_read_project(project_id)
  AND EXISTS (
    SELECT 1 FROM api.secrets s
    WHERE s.id = secret_id
      AND s.project_id = project_id
      AND s.deleted_at IS NULL
  )
);

DROP POLICY IF EXISTS secret_access_requests_update ON api.secret_access_requests;
CREATE POLICY secret_access_requests_update ON api.secret_access_requests
FOR UPDATE TO authenticated
USING (api.can_admin_project(project_id))
WITH CHECK (api.can_admin_project(project_id));

-- ── Folders: authorization ─────────────────────────────────────────────
-- Folder bindings participate in authorization (folder scope sits between
-- secret and project in the scope chain).
CREATE OR REPLACE FUNCTION api.rbac_folder_binding_allows(
  p_folder uuid,
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
    WHERE b.scope_kind = 'folder'
      AND b.scope_id = p_folder
      AND (
        CASE lower(COALESCE(p_need, ''))
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
      )
  );
$$;

-- Authorize a folder row: project admins pass through; restricted folders
-- check folder bindings only; otherwise the scope chain (folder → project →
-- team) decides. Restores 0003_secret_folders.sql semantics.
CREATE OR REPLACE FUNCTION api.can_access_folder(
  p_folder_id uuid,
  p_need text DEFAULT 'read',
  v_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
  SELECT COALESCE((
    SELECT CASE
      WHEN api.can_admin_project(f.project_id) THEN true
      WHEN f.access_mode = 'restricted' THEN api.rbac_folder_binding_allows(f.id, p_need, v_subject)
      WHEN p_need = 'write' THEN (
        api.can('update', 'secrets', 'folder', f.id, v_subject)
        OR api.can('create', 'secrets', 'folder', f.id, v_subject)
        OR api.can('admin', 'secrets', 'folder', f.id, v_subject)
        OR api.can('*', '*', 'folder', f.id, v_subject)
      )
      ELSE (
        api.can('get', 'secrets', 'folder', f.id, v_subject)
        OR api.can('list', 'secrets', 'folder', f.id, v_subject)
        OR api.can('reveal', 'secrets', 'folder', f.id, v_subject)
        OR api.can('update', 'secrets', 'folder', f.id, v_subject)
        OR api.can('admin', 'secrets', 'folder', f.id, v_subject)
        OR api.can('*', '*', 'folder', f.id, v_subject)
      )
    END
    FROM api.folders f WHERE f.id = p_folder_id
  ), false);
$$;

GRANT EXECUTE ON FUNCTION api.can_access_folder TO authenticated, anon;

-- Idempotent single-level folder ensure (SECURITY DEFINER so folder upserts
-- during secret creation bypass RLS; the single authorizing check on
-- api.secrets controls write access). The app calls once per path segment.
CREATE OR REPLACE FUNCTION private.materialize_folder_path(
  p_project_id uuid,
  p_parent_id uuid,
  p_name text,
  p_path text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
DECLARE v_id uuid;
BEGIN
    INSERT INTO api.folders (project_id, parent_id, name, path)
    VALUES (p_project_id, p_parent_id, p_name, p_path)
    ON CONFLICT (project_id, path) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
GRANT EXECUTE ON FUNCTION private.materialize_folder_path TO authenticator, authenticated;


-- Squashed from 0003_secret_folders.sql (write access stays at project
-- writer level, not admin).
CREATE POLICY folders_select ON api.folders
FOR SELECT TO authenticated USING (api.can_access_folder(id, 'read'));
CREATE POLICY folders_insert ON api.folders
FOR INSERT TO authenticated
WITH CHECK (api.can_write_project(project_id));
CREATE POLICY folders_update ON api.folders
FOR UPDATE TO authenticated
USING (api.can_write_project(project_id))
WITH CHECK (api.can_write_project(project_id));
CREATE POLICY folders_delete ON api.folders
FOR DELETE TO authenticated USING (api.can_admin_project(project_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON api.folders TO authenticated;

-- Enforce the role/scope contract at the database boundary. The UI performs
-- the same validation, but PostgREST writes must not be able to bypass it.
-- Role scope compatibility is data-driven (rbac.roles.scopes), not by name.
CREATE OR REPLACE FUNCTION rbac.validate_binding_scope()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
DECLARE role_name text;
DECLARE role_scopes text[];
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

  SELECT name, scopes INTO role_name, role_scopes FROM rbac.roles WHERE id = NEW.role_id;
  IF role_name IS NULL THEN
    RAISE EXCEPTION 'binding role does not exist';
  END IF;
  IF NOT (NEW.scope_kind = ANY (COALESCE(role_scopes, '{}'))) THEN
    RAISE EXCEPTION 'role % cannot be assigned at scope %', role_name, NEW.scope_kind;
  END IF;

  IF role_name = 'team-owner' AND NEW.scope_kind = 'team' THEN
    IF invoker IN ('authenticator', 'authenticated', 'anon') THEN
      IF NOT api.is_global_admin()
         AND api.team_role(NEW.scope_id) IS DISTINCT FROM 'team-owner'
         AND EXISTS (
           SELECT 1 FROM rbac.bindings b
           JOIN rbac.roles r ON r.id = b.role_id
           WHERE b.scope_kind = 'team'
             AND b.scope_id = NEW.scope_id
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

-- ── Directory maps cannot grant team-owner unless caller is owner ─────
CREATE OR REPLACE FUNCTION api.guard_team_dir_map()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NEW.role = 'team-owner'
     AND session_user IN ('authenticator', 'authenticated', 'anon')
     AND NOT api.is_global_admin()
     AND api.team_role(NEW.team_id) IS DISTINCT FROM 'team-owner' THEN
    RAISE EXCEPTION 'only a team owner can map team-owner';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_team_ldap_map ON api.team_ldap_maps;
CREATE TRIGGER guard_team_ldap_map
BEFORE INSERT OR UPDATE ON api.team_ldap_maps
FOR EACH ROW EXECUTE FUNCTION api.guard_team_dir_map();

DROP TRIGGER IF EXISTS guard_team_oidc_map ON api.team_oidc_maps;
CREATE TRIGGER guard_team_oidc_map
BEFORE INSERT OR UPDATE ON api.team_oidc_maps
FOR EACH ROW EXECUTE FUNCTION api.guard_team_dir_map();

-- ── Pin secret identity / access_mode ──────────────────────────────────
CREATE OR REPLACE FUNCTION api.guard_secret_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id THEN
    RAISE EXCEPTION 'secret identity fields cannot be changed';
  END IF;
  IF NEW.access_mode IS DISTINCT FROM OLD.access_mode
     OR NEW.requires_approval IS DISTINCT FROM OLD.requires_approval THEN
    IF NOT api.can_admin_project(OLD.project_id) THEN
      RAISE EXCEPTION 'only a project admin can change access_mode or requires_approval';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_secret_update ON api.secrets;
CREATE TRIGGER guard_secret_update
BEFORE UPDATE ON api.secrets
FOR EACH ROW EXECUTE FUNCTION api.guard_secret_update();

-- ── Pin project.team_id ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION api.guard_project_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id THEN
    RAISE EXCEPTION 'project id cannot be changed';
  END IF;
  IF NEW.team_id IS DISTINCT FROM OLD.team_id THEN
    IF session_user IN ('authenticator', 'authenticated', 'anon')
       AND NOT (
         api.team_role(OLD.team_id) IN ('team-owner', 'team-admin')
         AND api.team_role(NEW.team_id) IN ('team-owner', 'team-admin')
       ) THEN
      RAISE EXCEPTION 'project team_id cannot be changed';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_project_update ON api.projects;
CREATE TRIGGER guard_project_update
BEFORE UPDATE ON api.projects
FOR EACH ROW EXECUTE FUNCTION api.guard_project_update();

-- ── Machine tokens: project-admin only (RLS policies) ──────────────────
DROP POLICY IF EXISTS mt_insert ON api.machine_tokens;
CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
  WITH CHECK (api.can_admin_project(project_id));

DROP POLICY IF EXISTS mt_delete ON api.machine_tokens;
CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
  USING (api.can_admin_project(project_id));

DROP POLICY IF EXISTS mts_insert ON api.machine_token_scope;
CREATE POLICY mts_insert ON api.machine_token_scope FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_admin_project(t.project_id)
    )
  );

DROP POLICY IF EXISTS mts_delete ON api.machine_token_scope;
CREATE POLICY mts_delete ON api.machine_token_scope FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_admin_project(t.project_id)
    )
  );

-- ── Team reveal requests ───────────────────────────────────────────────
CREATE OR REPLACE FUNCTION api.team_allows_reveal_requests(pid uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(t.allow_reveal_requests, true)
  FROM api.projects p
  JOIN api.teams t ON t.id = p.team_id
  WHERE p.id = pid;
$$;

GRANT EXECUTE ON FUNCTION api.team_allows_reveal_requests TO authenticated, anon;

-- ── Ciphertext is not a table column for authenticated ─────────────────
REVOKE SELECT (value_enc) ON api.secrets FROM authenticated;
REVOKE SELECT (value_enc) ON api.secret_versions FROM authenticated;

CREATE OR REPLACE FUNCTION private.secret_enc(p_id uuid)
RETURNS TABLE (value_enc text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF p_id IS NULL OR NOT api.can_reveal_secret(p_id) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.value_enc, s.crypto_provider
    FROM api.secrets s
    WHERE s.id = p_id AND s.deleted_at IS NULL;
END;
$$;

CREATE OR REPLACE FUNCTION private.secret_version_enc(p_version uuid, p_secret uuid)
RETURNS TABLE (value_enc text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF p_version IS NULL OR p_secret IS NULL OR NOT api.can_reveal_secret(p_secret) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT v.value_enc, v.crypto_provider
    FROM api.secret_versions v
    WHERE v.id = p_version AND v.secret_id = p_secret;
END;
$$;

CREATE OR REPLACE FUNCTION private.project_reveal_enc_rows(p_project uuid)
RETURNS TABLE (id uuid, key text, value_enc text, note text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF p_project IS NULL OR NOT api.can_read_project(p_project) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.value_enc, s.note, s.crypto_provider
    FROM api.secrets s
    WHERE s.project_id = p_project
      AND s.deleted_at IS NULL
      AND api.can_reveal_secret(s.id)
    ORDER BY s.key;
END;
$$;

GRANT EXECUTE ON FUNCTION private.secret_enc TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.secret_version_enc TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.project_reveal_enc_rows TO authenticator, authenticated;

-- ── Webhooks core schema ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api.webhooks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    url text NOT NULL,
    secret_token text NOT NULL,
    events text[] NOT NULL DEFAULT '{}',
    scope_kind text NOT NULL CHECK (scope_kind IN ('cluster', 'team', 'project')),
    scope_id uuid,
    active boolean NOT NULL DEFAULT true,
    ssl_verify boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE api.webhooks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhooks_select ON api.webhooks;
CREATE POLICY webhooks_select ON api.webhooks FOR SELECT TO authenticated
  USING (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id));

DROP POLICY IF EXISTS webhooks_write ON api.webhooks;
CREATE POLICY webhooks_write ON api.webhooks FOR ALL TO authenticated
  USING (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id))
  WITH CHECK (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON api.webhooks TO authenticated;

-- Delivery queue (internal)
CREATE TABLE IF NOT EXISTS private.webhook_delivery_queue (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id uuid NOT NULL REFERENCES api.webhooks(id) ON DELETE CASCADE,
    payload jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz
);

CREATE INDEX IF NOT EXISTS webhook_queue_retry_idx ON private.webhook_delivery_queue (next_retry_at, locked_until);

-- Delivery log (api-level, RLS-exposed)
CREATE TABLE IF NOT EXISTS api.webhook_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id uuid NOT NULL REFERENCES api.webhooks(id) ON DELETE CASCADE,
  event text NOT NULL,
  ok boolean NOT NULL,
  status_code integer,
  error text NOT NULL DEFAULT '',
  duration_ms integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_recent_idx
  ON api.webhook_deliveries (webhook_id, created_at DESC);

ALTER TABLE api.webhook_deliveries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhook_deliveries_select ON api.webhook_deliveries;
CREATE POLICY webhook_deliveries_select ON api.webhook_deliveries FOR SELECT TO authenticated
  USING (
    api.is_global_admin()
    OR EXISTS (
      SELECT 1 FROM api.webhooks w
      WHERE w.id = webhook_id
        AND api.can_manage_rbac(w.scope_kind, w.scope_id)
    )
  );

GRANT SELECT ON api.webhook_deliveries TO authenticated;

-- ── Webhook enqueue logic ──────────────────────────────────────────────
CREATE OR REPLACE FUNCTION private.enqueue_webhooks(
    p_scope_kind text,
    p_scope_id uuid,
    p_event text,
    p_payload jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
DECLARE
    v_webhook_id uuid;
BEGIN
    FOR v_webhook_id IN
        SELECT id FROM api.webhooks
        WHERE active = true
          AND p_event = ANY(events)
          AND (
            (scope_kind = 'cluster')
            OR (scope_kind = 'team' AND scope_id = (
                CASE
                    WHEN p_scope_kind = 'team' THEN p_scope_id
                    WHEN p_scope_kind = 'project' THEN (SELECT team_id FROM api.projects WHERE id = p_scope_id)
                END
            ))
            OR (scope_kind = 'project' AND p_scope_kind = 'project' AND scope_id = p_scope_id)
          )
    LOOP
        INSERT INTO private.webhook_delivery_queue (webhook_id, payload)
        VALUES (v_webhook_id, p_payload);
    END LOOP;
END;
$$;

-- Trigger enqueuing on secret audit
CREATE OR REPLACE FUNCTION private.tr_webhook_secret_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
BEGIN
    PERFORM private.enqueue_webhooks(
        'project',
        NEW.project_id,
        'secret.' || NEW.action,
        jsonb_build_object(
            'event', 'secret.' || NEW.action,
            'project_id', NEW.project_id,
            'secret_id', NEW.secret_id,
            'secret_key', NEW.secret_key,
            'actor_email', NEW.actor_email,
            'timestamp', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_webhook_secret_audit ON api.secret_audit;
CREATE TRIGGER tr_webhook_secret_audit
AFTER INSERT ON api.secret_audit
FOR EACH ROW EXECUTE FUNCTION private.tr_webhook_secret_audit();

-- Trigger enqueuing on org audit
CREATE OR REPLACE FUNCTION private.tr_webhook_org_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
BEGIN
    PERFORM private.enqueue_webhooks(
        CASE WHEN NEW.project_id IS NOT NULL THEN 'project' ELSE 'team' END,
        COALESCE(NEW.project_id, NEW.team_id),
        'org.' || NEW.action,
        jsonb_build_object(
            'event', 'org.' || NEW.action,
            'team_id', NEW.team_id,
            'project_id', NEW.project_id,
            'action', NEW.action,
            'detail', NEW.detail,
            'actor_email', NEW.actor_email,
            'timestamp', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_webhook_org_audit ON api.org_audit;
CREATE TRIGGER tr_webhook_org_audit
AFTER INSERT ON api.org_audit
FOR EACH ROW EXECUTE FUNCTION private.tr_webhook_org_audit();

-- ── Team / Project metadata ────────────────────────────────────────────
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

-- Merged read view for projects: inherited metadata flows down from team.
-- Precedence on key collision: team > project. Adds a source column.
--
-- Input:  project_id (uuid)
-- Output: TABLE(key, value, updated_at, source)
-- Example: SELECT * FROM private.project_meta_rows('<project-uuid>');
CREATE OR REPLACE FUNCTION private.project_meta_rows(p_project uuid)
RETURNS TABLE(key text, value text, updated_at timestamptz, source text)
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = api, private
SET row_security = off AS $$
WITH scope AS (
    SELECT p.team_id AS team_id
    FROM api.projects p
    WHERE p.id = p_project
),
own AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.project_meta m
    WHERE m.project_id = p_project
),
tm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.team_meta m
    JOIN scope ON scope.team_id = m.team_id
),
merged AS (
    SELECT key, value, updated_at, 'team' AS source FROM tm
    UNION ALL
    SELECT key, value, updated_at, 'project' AS source FROM own
)
SELECT DISTINCT ON (key) key, value, updated_at, source
FROM merged
WHERE api.can_read_project(p_project)
ORDER BY key, source = 'project'
$$;

GRANT EXECUTE ON FUNCTION private.project_meta_rows TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.guard_meta_precedence() TO authenticator, authenticated;

-- Merged read view for secrets: inherited metadata flows down.
-- Precedence on key collision: team > project > secret.
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

-- ── private DEFINER functions are not PUBLIC ───────────────────────────
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA private TO authenticator;

GRANT EXECUTE ON FUNCTION private.lookup_user TO authenticated;
GRANT EXECUTE ON FUNCTION private.team_group_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.group_member_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.secret_meta_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.touch_secret_access TO authenticated;
GRANT EXECUTE ON FUNCTION private.audit_org TO authenticated;
GRANT EXECUTE ON FUNCTION private.audit_secret TO authenticated;
GRANT EXECUTE ON FUNCTION private.lookup_invite TO authenticated;
GRANT EXECUTE ON FUNCTION private.secret_access_request_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.pending_access_requests_for_admin TO authenticated;
GRANT EXECUTE ON FUNCTION private.team_member_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.project_member_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.project_group_role_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.shared_with_me_secret_rows TO authenticated;

-- ── Unauthenticated DEFINER oracles ────────────────────────────────────
REVOKE EXECUTE ON FUNCTION api.rbac_scope_chain(text, uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION api.rbac_rule_matches(text[], text[], text, text) FROM anon;
REVOKE EXECUTE ON FUNCTION api.my_access_rows() FROM anon;
REVOKE EXECUTE ON FUNCTION api.project_key_provider(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION api.project_key_providers(uuid[]) FROM anon;
REVOKE EXECUTE ON FUNCTION api.rbac_secret_binding_allows(uuid, text, uuid) FROM anon;

-- ── FORCE RLS on remaining tables ──────────────────────────────────────
ALTER TABLE api.team_ldap_maps FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_oidc_maps FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_invites FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_join_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_pins FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_recent FORCE ROW LEVEL SECURITY;
ALTER TABLE api.org_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_audit FORCE ROW LEVEL SECURITY;

-- ── Final cleanup: remove obsolete functions, default privs ────────────

ALTER DEFAULT PRIVILEGES IN SCHEMA api
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA rbac
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Fresh-install marker. The application rejects an existing pre-squash schema
-- when this marker is absent instead of silently treating it as current.
CREATE TABLE IF NOT EXISTS private.squashed_baseline_marker (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO private.squashed_baseline_marker (id)
VALUES (true)
ON CONFLICT DO NOTHING;

-- 0024's machine_get_row omits the service-read ciphertext guard; restore it.
-- Squashed: also aggregate secret metadata (machine_meta_in_list).
DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
RETURNS TABLE (
  id uuid, key text, value_enc text, note text, kind text,
  expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
  rotation_next_at timestamptz, rotated_at timestamptz,
  created_at timestamptz, updated_at timestamptz,
  crypto_provider text, metadata jsonb
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN;
  END IF;
  IF private.machine_role(p_project, p_hash) = 'service-read' THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
           s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
           s.created_at, s.updated_at, s.crypto_provider,
           COALESCE(
             (SELECT jsonb_object_agg(m.key, m.value)
              FROM api.secret_meta m
              WHERE m.secret_id = s.id),
             '{}'::jsonb
           ) AS metadata
    FROM api.secrets s
    WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
END;
$$;
GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;
