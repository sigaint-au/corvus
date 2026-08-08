"""Idempotent schema upgrades for existing database volumes."""
import logging

from config import DATABASE_ADMIN_URL, bootstrap_admin_email
import db

log = logging.getLogger(__name__)

# Session-level advisory lock key for ensure_schema (arbitrary stable int4 pair).
_ENSURE_LOCK_K1 = 834201
_ENSURE_LOCK_K2 = 1


def ensure_schema():
    """Apply idempotent DDL upgrades for existing database volumes.

    init.sql runs only on first volume create; this function re-applies
    additive migrations (columns, tables, RLS policies, functions) under a
    session advisory lock so concurrent workers cannot race. Requires a
    superuser DSN via DATABASE_ADMIN_URL. May promote the bootstrap admin
    email and backfill secret kinds after statements succeed.

    Args:
        None.

    Returns:
        None. Logs success; re-raises on failure after logging.

    Raises:
        RuntimeError: If DATABASE_ADMIN_URL is not set.
        Exception: Any database error while applying statements (re-raised).

    Example:
        >>> # ensure_schema()  # call once at app startup
        >>> # schema ensure complete (logged)
    """
    if not DATABASE_ADMIN_URL:
        # Do not fall back to the app/authenticator role — policy DDL would fail
        # and hide misconfiguration. Compose sets DATABASE_ADMIN_URL explicitly.
        raise RuntimeError(
            "DATABASE_ADMIN_URL is not set; schema upgrades require a superuser DSN"
        )

    stmts = [
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS is_global_admin boolean NOT NULL DEFAULT false
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS disabled_at timestamptz
        """,
        """
        CREATE TABLE IF NOT EXISTS private.server_settings (
          key text PRIMARY KEY,
          value text NOT NULL DEFAULT ''
        )
        """,
        """
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
        ON CONFLICT (key) DO NOTHING
        """,
        """
        CREATE OR REPLACE FUNCTION api.is_global_admin() RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT COALESCE(
            (SELECT is_global_admin FROM private.users WHERE id = api.current_user_id()),
            false
          );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.is_team_member(tid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin() OR EXISTS (
            SELECT 1 FROM api.team_members
            WHERE team_id = tid AND user_id = api.current_user_id()
          );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.team_role(tid uuid) RETURNS text
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT CASE
            WHEN api.is_global_admin() THEN 'owner'
            ELSE (SELECT role FROM api.team_members
                  WHERE team_id = tid AND user_id = api.current_user_id())
          END;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.can_read_project(pid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin()
            OR EXISTS (
              SELECT 1 FROM api.project_members
              WHERE project_id = pid AND user_id = api.current_user_id()
            )
            OR (
              NOT EXISTS (
                SELECT 1 FROM api.project_members
                WHERE project_id = pid AND user_id = api.current_user_id()
              )
              AND EXISTS (
                SELECT 1 FROM api.projects p
                JOIN api.team_members tm ON tm.team_id = p.team_id
                WHERE p.id = pid AND tm.user_id = api.current_user_id()
              )
            );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.can_write_project(pid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin()
            OR EXISTS (
              SELECT 1 FROM api.projects p
              JOIN api.team_members tm ON tm.team_id = p.team_id
              WHERE p.id = pid AND tm.user_id = api.current_user_id()
                AND tm.role IN ('owner', 'admin')
            )
            OR EXISTS (
              SELECT 1 FROM api.project_members
              WHERE project_id = pid AND user_id = api.current_user_id()
                AND role IN ('admin', 'write')
            )
            OR (
              NOT EXISTS (
                SELECT 1 FROM api.project_members
                WHERE project_id = pid AND user_id = api.current_user_id()
              )
              AND EXISTS (
                SELECT 1 FROM api.projects p
                JOIN api.team_members tm ON tm.team_id = p.team_id
                WHERE p.id = pid AND tm.user_id = api.current_user_id()
                  AND tm.role = 'member'
              )
            );
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION api.can_admin_project(pid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT api.is_global_admin()
            OR EXISTS (
              SELECT 1 FROM api.projects p
              JOIN api.team_members tm ON tm.team_id = p.team_id
              WHERE p.id = pid AND tm.user_id = api.current_user_id()
                AND tm.role IN ('owner', 'admin')
            )
            OR EXISTS (
              SELECT 1 FROM api.project_members
              WHERE project_id = pid AND user_id = api.current_user_id()
                AND role = 'admin'
            );
        $$
        """,
        "GRANT EXECUTE ON FUNCTION api.can_read_project TO authenticated, anon",
        "GRANT EXECUTE ON FUNCTION api.can_write_project TO authenticated, anon",
        "GRANT EXECUTE ON FUNCTION api.can_admin_project TO authenticated, anon",
        # team_members / ldap maps: rename read-only → viewer (drop role CHECKs, migrate, re-add)
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'api' AND t.relname = 'team_members'
              AND c.contype = 'c'
              AND pg_get_constraintdef(c.oid) ILIKE '%role%'
          LOOP
            EXECUTE format('ALTER TABLE api.team_members DROP CONSTRAINT %I', r.conname);
          END LOOP;
        END $$
        """,
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'api' AND t.relname = 'team_ldap_maps'
              AND c.contype = 'c'
              AND pg_get_constraintdef(c.oid) ILIKE '%role%'
          LOOP
            EXECUTE format('ALTER TABLE api.team_ldap_maps DROP CONSTRAINT %I', r.conname);
          END LOOP;
        END $$
        """,
        "UPDATE api.team_members SET role = 'viewer' WHERE role = 'read-only'",
        "UPDATE api.team_ldap_maps SET role = 'viewer' WHERE role = 'read-only'",
        """
        DO $$ BEGIN
          ALTER TABLE api.team_members
            ADD CONSTRAINT team_members_role_check
            CHECK (role IN ('owner', 'admin', 'member', 'viewer'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.team_ldap_maps
            ADD CONSTRAINT team_ldap_maps_role_check
            CHECK (role IN ('owner', 'admin', 'member', 'viewer'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        "DROP POLICY IF EXISTS projects_insert ON api.projects",
        """
        CREATE POLICY projects_insert ON api.projects FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('owner', 'admin', 'member'))
        """,
        "DROP POLICY IF EXISTS projects_update ON api.projects",
        """
        CREATE POLICY projects_update ON api.projects FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin', 'member'))
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'
        """,
        # Fresh installs may already have a CHECK without 'oidc'; always re-bind.
        """
        DO $$ BEGIN
          ALTER TABLE private.users DROP CONSTRAINT IF EXISTS users_auth_source_check;
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'private' AND t.relname = 'users'
              AND c.contype = 'c'
              AND pg_get_constraintdef(c.oid) ILIKE '%auth_source%'
          LOOP
            EXECUTE format('ALTER TABLE private.users DROP CONSTRAINT %I', r.conname);
          END LOOP;
          ALTER TABLE private.users
            ADD CONSTRAINT users_auth_source_check
            CHECK (auth_source IN ('local', 'ldap', 'oidc'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        DO $$ BEGIN
          ALTER TABLE private.users ALTER COLUMN password_hash DROP NOT NULL;
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        DECLARE uid uuid;
        BEGIN
          INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
          VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), false, 'local')
          RETURNING id INTO uid;
          RETURN uid;
        END;
        $$
        """,
        "DROP FUNCTION IF EXISTS private.verify_user(text, text)",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.upsert_ldap_user TO authenticator",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.upsert_oidc_user TO authenticator",
        """
        CREATE TABLE IF NOT EXISTS private.personal_access_tokens (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          name text NOT NULL,
          token_hash text NOT NULL,
          token_prefix text NOT NULL,
          expires_at timestamptz,
          last_used_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (token_hash)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS personal_access_tokens_user_idx
          ON private.personal_access_tokens (user_id, created_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS private.ldap_role_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('global_admin')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (ldap_group)
        )
        """,
        """
        ALTER TABLE api.team_members
          ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual'
        """,
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'api' AND t.relname = 'team_members'
              AND c.contype = 'c'
              AND pg_get_constraintdef(c.oid) ILIKE '%source%'
              AND pg_get_constraintdef(c.oid) NOT ILIKE '%role%'
          LOOP
            EXECUTE format('ALTER TABLE api.team_members DROP CONSTRAINT %I', r.conname);
          END LOOP;
          ALTER TABLE api.team_members
            ADD CONSTRAINT team_members_source_check
            CHECK (source IN ('manual', 'ldap', 'oidc'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        CREATE TABLE IF NOT EXISTS api.team_ldap_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (team_id, ldap_group)
        )
        """,
        "ALTER TABLE api.team_ldap_maps ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS tlm_select ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_select ON api.team_ldap_maps FOR SELECT TO authenticated
          USING (api.is_team_member(team_id))
        """,
        "DROP POLICY IF EXISTS tlm_insert ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_insert ON api.team_ldap_maps FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS tlm_update ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_update ON api.team_ldap_maps FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS tlm_delete ON api.team_ldap_maps",
        """
        CREATE POLICY tlm_delete ON api.team_ldap_maps FOR DELETE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_ldap_maps TO authenticated",
        "GRANT ALL ON api.team_ldap_maps TO authenticator",
        """
        CREATE TABLE IF NOT EXISTS private.oidc_role_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          oidc_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('global_admin')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (oidc_group)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS api.team_oidc_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          oidc_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (team_id, oidc_group)
        )
        """,
        "ALTER TABLE api.team_oidc_maps ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS tom_select ON api.team_oidc_maps",
        """
        CREATE POLICY tom_select ON api.team_oidc_maps FOR SELECT TO authenticated
          USING (api.is_team_member(team_id))
        """,
        "DROP POLICY IF EXISTS tom_insert ON api.team_oidc_maps",
        """
        CREATE POLICY tom_insert ON api.team_oidc_maps FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS tom_update ON api.team_oidc_maps",
        """
        CREATE POLICY tom_update ON api.team_oidc_maps FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS tom_delete ON api.team_oidc_maps",
        """
        CREATE POLICY tom_delete ON api.team_oidc_maps FOR DELETE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_oidc_maps TO authenticated",
        "GRANT ALL ON api.team_oidc_maps TO authenticator",
        "DROP FUNCTION IF EXISTS private.get_setting(text)",
        "DROP FUNCTION IF EXISTS private.set_setting(text, text)",
        "DROP FUNCTION IF EXISTS private.all_settings()",
        "DROP VIEW IF EXISTS api.user_directory",
        """
        CREATE VIEW api.user_directory AS
          SELECT id, email, name, is_global_admin, created_at FROM private.users
        """,
        # No SELECT for authenticated — prevents user enumeration via PostgREST
        "REVOKE ALL ON api.user_directory FROM authenticated",
        "GRANT SELECT ON api.user_directory TO authenticator",
        "GRANT ALL ON api.user_directory TO authenticator",
        "GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon",
        """
        CREATE OR REPLACE FUNCTION private.lookup_user(p_email text)
        RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = private
        SET row_security = off AS $$
          SELECT id FROM private.users WHERE email = lower(p_email) LIMIT 1;
        $$
        """,
        "GRANT USAGE ON SCHEMA private TO authenticator, authenticated",
        "GRANT EXECUTE ON FUNCTION private.lookup_user TO authenticator, authenticated",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.team_member_rows TO authenticator, authenticated",
        # teams SELECT for global admin (recreate policy safely)
        "DROP POLICY IF EXISTS teams_select ON api.teams",
        """
        CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
          USING (api.is_global_admin() OR api.is_team_member(id))
        """,
        "DROP POLICY IF EXISTS teams_insert ON api.teams",
        """
        CREATE POLICY teams_insert ON api.teams FOR INSERT TO authenticated
          WITH CHECK (created_by = api.current_user_id() OR api.is_global_admin())
        """,
        # team_members INSERT: owners/admins only (no self-join escape hatch).
        # Team creators use SECURITY DEFINER private.create_team instead.
        "DROP POLICY IF EXISTS tm_insert ON api.team_members",
        """
        CREATE POLICY tm_insert ON api.team_members FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        # Soft-delete for secrets (trash + restore)
        """
        ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS deleted_at timestamptz
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.secrets DROP CONSTRAINT IF EXISTS secrets_project_id_key_key;
        EXCEPTION WHEN undefined_object THEN NULL;
        END $$
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_key_live
          ON api.secrets (project_id, key) WHERE deleted_at IS NULL
        """,
        """
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
        $$
        """,
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator",
        """
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
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.machine_list_meta(
          p_project uuid, p_hash text, p_q text DEFAULT NULL
        )
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.machine_list_meta TO authenticator",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.machine_delete TO authenticator",
        # Secret audit log
        """
        CREATE TABLE IF NOT EXISTS api.secret_audit (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
          secret_id uuid,
          secret_key text NOT NULL DEFAULT '',
          user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
          actor_email text NOT NULL DEFAULT '',
          action text NOT NULL DEFAULT 'created',
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.secret_audit DROP CONSTRAINT IF EXISTS secret_audit_action_check;
          ALTER TABLE api.secret_audit
            ADD CONSTRAINT secret_audit_action_check
            CHECK (action IN (
              'created', 'updated', 'revealed', 'deleted', 'restored', 'purged',
              'machine_upsert', 'exported'
            ));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        CREATE INDEX IF NOT EXISTS secret_audit_project_created_idx
          ON api.secret_audit (project_id, created_at DESC)
        """,
        "ALTER TABLE api.secret_audit ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS secret_audit_select ON api.secret_audit",
        """
        CREATE POLICY secret_audit_select ON api.secret_audit FOR SELECT TO authenticated
          USING (api.can_read_project(project_id))
        """,
        "DROP POLICY IF EXISTS secret_audit_insert ON api.secret_audit",
        "REVOKE INSERT ON api.secret_audit FROM authenticated",
        "GRANT SELECT ON api.secret_audit TO authenticated",
        "GRANT ALL ON api.secret_audit TO authenticator",
        """
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
            'machine_upsert', 'exported'
          ) THEN
            RAISE EXCEPTION 'invalid audit action: %', p_action;
          END IF;
          -- Never trust caller-supplied p_user_id; always derive from JWT
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
          INSERT INTO api.secret_audit
            (project_id, secret_id, secret_key, user_id, actor_email, action)
          VALUES (p_project, p_secret_id, COALESCE(p_secret_key, ''), uid, email, p_action);
        END;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.audit_secret TO authenticator, authenticated",
        # login lockout + token expiry
        """
        CREATE TABLE IF NOT EXISTS private.login_failures (
          id bigserial PRIMARY KEY,
          email text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS login_failures_email_created_idx
          ON private.login_failures (email, created_at)
        """,
        """
        ALTER TABLE api.machine_tokens
          ADD COLUMN IF NOT EXISTS expires_at timestamptz
        """,
        """
        ALTER TABLE api.machine_tokens
          ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'read-only'
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.machine_tokens
            ADD CONSTRAINT machine_tokens_token_prefix_key UNIQUE (token_prefix);
        EXCEPTION WHEN duplicate_table OR duplicate_object OR unique_violation THEN NULL;
        END $$
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.machine_tokens DROP CONSTRAINT IF EXISTS machine_tokens_role_check;
          ALTER TABLE api.machine_tokens
            ADD CONSTRAINT machine_tokens_role_check
            CHECK (role IN ('read-only', 'write'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.auth_machine(p_project uuid, p_hash text)
        RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
          SELECT EXISTS (
            SELECT 1 FROM api.machine_tokens
            WHERE project_id = p_project AND token_hash = p_hash
              AND (expires_at IS NULL OR expires_at > now())
          );
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.auth_machine TO authenticator",
        """
        CREATE OR REPLACE FUNCTION private.machine_role(p_project uuid, p_hash text)
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
          SELECT role FROM api.machine_tokens
          WHERE project_id = p_project AND token_hash = p_hash
            AND (expires_at IS NULL OR expires_at > now())
          LIMIT 1;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.machine_role TO authenticator",
        """
        CREATE OR REPLACE FUNCTION private.machine_token_label(p_project uuid, p_hash text)
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
          SELECT COALESCE(NULLIF(btrim(name), ''), 'token') || ':' || token_prefix
          FROM api.machine_tokens
          WHERE project_id = p_project AND token_hash = p_hash
            AND (expires_at IS NULL OR expires_at > now())
          LIMIT 1;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.machine_token_label TO authenticator",
        # Drop 5-arg overload from older volumes before creating extended signature.
        "DROP FUNCTION IF EXISTS private.machine_upsert_enc(uuid, text, text, text, text)",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.machine_upsert_enc TO authenticator",
        # Machine tokens: project readers may SELECT; only writers INSERT/DELETE
        "DROP POLICY IF EXISTS mt_select ON api.machine_tokens",
        """
        CREATE POLICY mt_select ON api.machine_tokens FOR SELECT TO authenticated
          USING (api.can_read_project(project_id))
        """,
        "DROP POLICY IF EXISTS mt_insert ON api.machine_tokens",
        """
        CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
          WITH CHECK (api.can_write_project(project_id))
        """,
        "DROP POLICY IF EXISTS mt_delete ON api.machine_tokens",
        """
        CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
          USING (api.can_write_project(project_id))
        """,
        # secrets.updated_at maintained by trigger (not app-layer now())
        """
        CREATE OR REPLACE FUNCTION api.touch_updated_at()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          NEW.updated_at := now();
          RETURN NEW;
        END;
        $$
        """,
        "DROP TRIGGER IF EXISTS secrets_touch_updated_at ON api.secrets",
        """
        CREATE TRIGGER secrets_touch_updated_at
          BEFORE UPDATE ON api.secrets
          FOR EACH ROW EXECUTE FUNCTION api.touch_updated_at()
        """,
        # Secret kind (explicit; not inferred from note tags)
        """
        ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'plain'
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.secrets DROP CONSTRAINT IF EXISTS secrets_kind_check;
          ALTER TABLE api.secrets
            ADD CONSTRAINT secrets_kind_check
            CHECK (kind IN ('plain', 'database', 'certificate', 'ssh', 'kv'));
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$
        """,
        # Secret versioning + expiry / rotation hints
        """
        ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS expires_at timestamptz
        """,
        """
        CREATE TABLE IF NOT EXISTS api.secret_versions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          value_enc text NOT NULL,
          note text NOT NULL DEFAULT '',
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS secret_versions_secret_created_idx
          ON api.secret_versions (secret_id, created_at DESC)
        """,
        """
        CREATE OR REPLACE FUNCTION api.archive_secret_version()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.value_enc IS DISTINCT FROM NEW.value_enc THEN
            INSERT INTO api.secret_versions (secret_id, value_enc, note)
            VALUES (OLD.id, OLD.value_enc, OLD.note);
          END IF;
          RETURN NEW;
        END;
        $$
        """,
        "DROP TRIGGER IF EXISTS secrets_archive_version ON api.secrets",
        """
        CREATE TRIGGER secrets_archive_version
          BEFORE UPDATE ON api.secrets
          FOR EACH ROW EXECUTE FUNCTION api.archive_secret_version()
        """,
        "ALTER TABLE api.secret_versions ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS secret_versions_select ON api.secret_versions",
        """
        CREATE POLICY secret_versions_select ON api.secret_versions FOR SELECT TO authenticated
          USING (
            EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND api.can_read_project(s.project_id)
            )
          )
        """,
        "DROP POLICY IF EXISTS secret_versions_insert ON api.secret_versions",
        """
        CREATE POLICY secret_versions_insert ON api.secret_versions FOR INSERT TO authenticated
          WITH CHECK (
            EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND api.can_write_project(s.project_id)
            )
          )
        """,
        "GRANT SELECT, INSERT ON api.secret_versions TO authenticated",
        "GRANT ALL ON api.secret_versions TO authenticator",
        # Team settings + invites + org audit + project members helpers
        """
        ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS default_token_days int
        """,
        # Cap default_token_days (drop legacy check if present, then re-add bounded)
        """
        DO $$ BEGIN
          ALTER TABLE api.teams DROP CONSTRAINT IF EXISTS teams_default_token_days_check;
        EXCEPTION WHEN undefined_object THEN NULL;
        END $$
        """,
        """
        ALTER TABLE api.teams
          ADD CONSTRAINT teams_default_token_days_check
          CHECK (
            default_token_days IS NULL
            OR (default_token_days > 0 AND default_token_days <= 3650)
          )
        """,
        """
        ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_enabled boolean
        """,
        """
        ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_text text NOT NULL DEFAULT ''
        """,
        """
        ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_color text NOT NULL DEFAULT ''
        """,
        """
        ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_fg text NOT NULL DEFAULT ''
        """,
        """
        CREATE TABLE IF NOT EXISTS api.team_invites (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          token_hash text NOT NULL UNIQUE,
          role text NOT NULL DEFAULT 'member'
            CHECK (role IN ('admin', 'member', 'viewer')),
          expires_at timestamptz NOT NULL,
          created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          revoked_at timestamptz
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS team_invites_team_idx
          ON api.team_invites (team_id) WHERE revoked_at IS NULL
        """,
        """
        CREATE TABLE IF NOT EXISTS api.team_join_requests (
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
        )
        """,
        # Migrate invite/join role read-only → viewer after tables exist
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT t.relname AS tbl, c.conname
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'api'
              AND t.relname IN ('team_invites', 'team_join_requests')
              AND c.contype = 'c'
              AND pg_get_constraintdef(c.oid) ILIKE '%role%'
              AND pg_get_constraintdef(c.oid) NOT ILIKE '%status%'
          LOOP
            EXECUTE format('ALTER TABLE api.%I DROP CONSTRAINT %I', r.tbl, r.conname);
          END LOOP;
        END $$
        """,
        "UPDATE api.team_invites SET role = 'viewer' WHERE role = 'read-only'",
        "UPDATE api.team_join_requests SET role = 'viewer' WHERE role = 'read-only'",
        """
        DO $$ BEGIN
          ALTER TABLE api.team_invites
            ADD CONSTRAINT team_invites_role_check
            CHECK (role IN ('admin', 'member', 'viewer'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        DO $$ BEGIN
          ALTER TABLE api.team_join_requests
            ADD CONSTRAINT team_join_requests_role_check
            CHECK (role IN ('admin', 'member', 'viewer'));
        EXCEPTION WHEN others THEN NULL;
        END $$
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS team_join_requests_pending_uidx
          ON api.team_join_requests (team_id, user_id) WHERE status = 'pending'
        """,
        """
        CREATE TABLE IF NOT EXISTS api.org_audit (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid REFERENCES api.teams(id) ON DELETE CASCADE,
          project_id uuid REFERENCES api.projects(id) ON DELETE CASCADE,
          action text NOT NULL,
          detail text NOT NULL DEFAULT '',
          user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
          actor_email text NOT NULL DEFAULT '',
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS org_audit_team_created_idx
          ON api.org_audit (team_id, created_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS org_audit_project_created_idx
          ON api.org_audit (project_id, created_at DESC)
        """,
        """
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
        $$
        """,
        "DROP TRIGGER IF EXISTS team_members_guard_last_owner ON api.team_members",
        """
        CREATE TRIGGER team_members_guard_last_owner
          BEFORE UPDATE OR DELETE ON api.team_members
          FOR EACH ROW EXECUTE FUNCTION api.guard_last_team_owner()
        """,
        "ALTER TABLE api.team_invites ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE api.team_join_requests ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE api.org_audit ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS team_invites_select ON api.team_invites",
        """
        CREATE POLICY team_invites_select ON api.team_invites FOR SELECT TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS team_invites_insert ON api.team_invites",
        """
        CREATE POLICY team_invites_insert ON api.team_invites FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS team_invites_update ON api.team_invites",
        """
        CREATE POLICY team_invites_update ON api.team_invites FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS team_invites_delete ON api.team_invites",
        """
        CREATE POLICY team_invites_delete ON api.team_invites FOR DELETE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS team_join_requests_select ON api.team_join_requests",
        """
        CREATE POLICY team_join_requests_select ON api.team_join_requests FOR SELECT TO authenticated
          USING (
            api.team_role(team_id) IN ('owner', 'admin')
            OR user_id = api.current_user_id()
          )
        """,
        "DROP POLICY IF EXISTS team_join_requests_insert ON api.team_join_requests",
        """
        CREATE POLICY team_join_requests_insert ON api.team_join_requests FOR INSERT TO authenticated
          WITH CHECK (user_id = api.current_user_id())
        """,
        "DROP POLICY IF EXISTS team_join_requests_update ON api.team_join_requests",
        """
        CREATE POLICY team_join_requests_update ON api.team_join_requests FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('owner', 'admin'))
        """,
        "DROP POLICY IF EXISTS org_audit_select ON api.org_audit",
        """
        CREATE POLICY org_audit_select ON api.org_audit FOR SELECT TO authenticated
          USING (
            (team_id IS NOT NULL AND api.is_team_member(team_id))
            OR (project_id IS NOT NULL AND api.can_read_project(project_id))
          )
        """,
        "REVOKE INSERT ON api.org_audit FROM authenticated",
        "GRANT SELECT ON api.org_audit TO authenticated",
        "GRANT ALL ON api.org_audit TO authenticator",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_invites TO authenticated",
        "GRANT SELECT, INSERT, UPDATE ON api.team_join_requests TO authenticated",
        "GRANT ALL ON api.team_invites TO authenticator",
        "GRANT ALL ON api.team_join_requests TO authenticator",
        "DROP POLICY IF EXISTS pm_insert ON api.project_members",
        """
        CREATE POLICY pm_insert ON api.project_members FOR INSERT TO authenticated
          WITH CHECK (api.can_admin_project(project_id))
        """,
        "DROP POLICY IF EXISTS pm_update ON api.project_members",
        """
        CREATE POLICY pm_update ON api.project_members FOR UPDATE TO authenticated
          USING (api.can_admin_project(project_id))
        """,
        "DROP POLICY IF EXISTS pm_delete ON api.project_members",
        """
        CREATE POLICY pm_delete ON api.project_members FOR DELETE TO authenticated
          USING (api.can_admin_project(project_id))
        """,
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.project_member_rows TO authenticator, authenticated",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.audit_org TO authenticator, authenticated",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.lookup_invite TO authenticator, authenticated",
        # Favorites + recently accessed secrets
        """
        CREATE TABLE IF NOT EXISTS api.secret_pins (
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          created_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (user_id, secret_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS api.secret_recent (
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          accessed_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (user_id, secret_id)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS secret_recent_user_accessed_idx
          ON api.secret_recent (user_id, accessed_at DESC)
        """,
        "ALTER TABLE api.secret_pins ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE api.secret_recent ENABLE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS secret_pins_select ON api.secret_pins",
        """
        CREATE POLICY secret_pins_select ON api.secret_pins FOR SELECT TO authenticated
          USING (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          )
        """,
        "DROP POLICY IF EXISTS secret_pins_insert ON api.secret_pins",
        """
        CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
          WITH CHECK (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          )
        """,
        "DROP POLICY IF EXISTS secret_pins_delete ON api.secret_pins",
        """
        CREATE POLICY secret_pins_delete ON api.secret_pins FOR DELETE TO authenticated
          USING (user_id = api.current_user_id())
        """,
        "DROP POLICY IF EXISTS secret_recent_select ON api.secret_recent",
        """
        CREATE POLICY secret_recent_select ON api.secret_recent FOR SELECT TO authenticated
          USING (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          )
        """,
        "DROP POLICY IF EXISTS secret_recent_insert ON api.secret_recent",
        """
        CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
          WITH CHECK (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          )
        """,
        "DROP POLICY IF EXISTS secret_recent_update ON api.secret_recent",
        """
        CREATE POLICY secret_recent_update ON api.secret_recent FOR UPDATE TO authenticated
          USING (user_id = api.current_user_id())
        """,
        "DROP POLICY IF EXISTS secret_recent_delete ON api.secret_recent",
        """
        CREATE POLICY secret_recent_delete ON api.secret_recent FOR DELETE TO authenticated
          USING (user_id = api.current_user_id())
        """,
        "GRANT SELECT, INSERT, DELETE ON api.secret_pins TO authenticated",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON api.secret_recent TO authenticated",
        "GRANT ALL ON api.secret_pins TO authenticator",
        "GRANT ALL ON api.secret_recent TO authenticator",
        # Password change / reset + server-side sessions
        """
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
        $$
        """,
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.change_password TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.set_local_password TO authenticator",
        """
        CREATE TABLE IF NOT EXISTS private.user_sessions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          created_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL,
          revoked_at timestamptz,
          user_agent text NOT NULL DEFAULT '',
          ip text NOT NULL DEFAULT ''
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS user_sessions_user_active_idx
          ON private.user_sessions (user_id, last_seen_at DESC)
          WHERE revoked_at IS NULL
        """,
        """
        CREATE TABLE IF NOT EXISTS private.password_reset_tokens (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          token_hash text NOT NULL UNIQUE,
          expires_at timestamptz NOT NULL,
          used_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
          ON private.password_reset_tokens (user_id)
          WHERE used_at IS NULL
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS totp_secret_enc text
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS totp_enabled_at timestamptz
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS disabled_at timestamptz
        """,
        """
        CREATE TABLE IF NOT EXISTS private.totp_recovery_codes (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          code_hash text NOT NULL,
          used_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS totp_recovery_codes_user_idx
          ON private.totp_recovery_codes (user_id)
          WHERE used_at IS NULL
        """,
    ]
    try:
        with db.connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            # Serialize workers so concurrent DROP POLICY / CREATE POLICY pairs
            # cannot race across gunicorn processes.
            cur.execute(
                "SELECT pg_advisory_lock(%s, %s)",
                (_ENSURE_LOCK_K1, _ENSURE_LOCK_K2),
            )
            try:
                for sql in stmts:
                    cur.execute(sql)
                # Bootstrap: only explicit GLOBAL_ADMIN_EMAIL / BOOTSTRAP_ADMIN_EMAIL
                # (never auto-promote the first registrant — race / takeover risk)
                boot = bootstrap_admin_email()
                if boot:
                    cur.execute(
                        "UPDATE private.users SET is_global_admin = true WHERE email = %s",
                        (boot,),
                    )
                _backfill_secret_kinds(cur)
            finally:
                cur.execute(
                    "SELECT pg_advisory_unlock(%s, %s)",
                    (_ENSURE_LOCK_K1, _ENSURE_LOCK_K2),
                )
        log.info("schema ensure complete")
    except Exception:
        log.exception("ensure_schema failed")
        raise


def _backfill_secret_kinds(cur) -> None:
    """Backfill api.secrets.kind from legacy note tags or value heuristics.

    One-shot migration helper: set kind from legacy note type: tags / value
    heuristics, then strip tags from notes. Safe to re-run — after the first
    pass only rows still matching type: (or empty kind) are candidates.

    Args:
        cur: Open admin DB cursor used to SELECT/UPDATE api.secrets.

    Returns:
        None. Logs how many rows were updated when any change was made.

    Example:
        >>> # with db.connect_admin(autocommit=True) as conn, conn.cursor() as cur:
        ... #     _backfill_secret_kinds(cur)
    """
    from secret_kinds import (
        detect_secret_kind,
        kind_from_legacy_note,
        normalize_kind,
        strip_legacy_type_tags,
    )
    import crypto

    try:
        cur.execute(
            """
            SELECT id, note, value_enc, kind
            FROM api.secrets
            WHERE note ~* 'type:'
               OR kind IS NULL
               OR kind = ''
            """
        )
    except Exception:
        # Column missing mid-migration (shouldn't happen after ADD COLUMN)
        return
    rows = cur.fetchall() or []
    if not rows:
        return
    updated = 0
    for row in rows:
        note = row.get("note") or ""
        kind = normalize_kind(row.get("kind") or "plain")
        legacy = kind_from_legacy_note(note)
        if legacy:
            kind = legacy
        elif kind == "plain":
            try:
                plain = crypto.decrypt(row["value_enc"])
            except Exception:
                plain = ""
            kind = detect_secret_kind(plain)
        clean = strip_legacy_type_tags(note)
        if kind != (row.get("kind") or "plain") or clean != note:
            cur.execute(
                """
                UPDATE api.secrets
                SET kind = %s, note = %s
                WHERE id = %s
                """,
                (kind, clean, str(row["id"])),
            )
            updated += 1
    if updated:
        log.info("backfilled kind/note for %s secret row(s)", updated)

