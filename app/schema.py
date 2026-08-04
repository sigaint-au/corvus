"""Idempotent schema upgrades for existing database volumes."""
import logging

from config import GLOBAL_ADMIN_EMAIL
import db

log = logging.getLogger(__name__)


def ensure_schema():
    """Idempotent upgrades for existing volumes (init.sql only runs once)."""
    stmts = [
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS is_global_admin boolean NOT NULL DEFAULT false
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
          ('ldap_enabled', 'false'),
          ('ldap_url', ''),
          ('ldap_start_tls', 'false'),
          ('ldap_bind_dn', ''),
          ('ldap_bind_password', ''),
          ('ldap_user_base', ''),
          ('ldap_user_filter', '(|(mail={login})(uid={login})(sAMAccountName={login}))'),
          ('ldap_email_attr', 'mail'),
          ('ldap_name_attr', 'displayName'),
          ('ldap_group_base', ''),
          ('ldap_group_filter', '(member={dn})'),
          ('ldap_use_memberof', 'true')
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
          SELECT api.is_global_admin() OR EXISTS (
            SELECT 1 FROM api.projects p
            JOIN api.team_members tm ON tm.team_id = p.team_id
            WHERE p.id = pid AND tm.user_id = api.current_user_id()
          ) OR EXISTS (
            SELECT 1 FROM api.project_members
            WHERE project_id = pid AND user_id = api.current_user_id()
          );
        $$
        """,
        """
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
        $$
        """,
        """
        ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'
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
        DECLARE first_user boolean;
        BEGIN
          SELECT NOT EXISTS (SELECT 1 FROM private.users) INTO first_user;
          INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
          VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), first_user, 'local')
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
            AND u.password_hash = crypt(p_password, u.password_hash);
        END;
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator",
        """
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
        $$
        """,
        "GRANT EXECUTE ON FUNCTION private.upsert_ldap_user TO authenticator",
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
        CREATE TABLE IF NOT EXISTS api.team_ldap_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
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
        CREATE OR REPLACE FUNCTION private.get_setting(p_key text)
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = private AS $$
          SELECT value FROM private.server_settings WHERE key = p_key;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.set_setting(p_key text, p_value text)
        RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = private AS $$
          INSERT INTO private.server_settings (key, value) VALUES (p_key, p_value)
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
        $$
        """,
        """
        CREATE OR REPLACE FUNCTION private.all_settings()
        RETURNS TABLE (key text, value text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = private AS $$
          SELECT s.key, s.value FROM private.server_settings s ORDER BY s.key;
        $$
        """,
        "DROP VIEW IF EXISTS api.user_directory",
        """
        CREATE VIEW api.user_directory AS
          SELECT id, email, name, is_global_admin, created_at FROM private.users
        """,
        "GRANT SELECT ON api.user_directory TO authenticated",
        "GRANT ALL ON api.user_directory TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.get_setting TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.set_setting TO authenticator",
        "GRANT EXECUTE ON FUNCTION private.all_settings TO authenticator",
        "GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon",
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
    ]
    try:
        with db.connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            for sql in stmts:
                cur.execute(sql)
            # Bootstrap: first user, or GLOBAL_ADMIN_EMAIL
            cur.execute(
                """
                UPDATE private.users SET is_global_admin = true
                WHERE id = (SELECT id FROM private.users ORDER BY created_at ASC LIMIT 1)
                  AND NOT EXISTS (SELECT 1 FROM private.users WHERE is_global_admin)
                """
            )
            if GLOBAL_ADMIN_EMAIL:
                cur.execute(
                    "UPDATE private.users SET is_global_admin = true WHERE email = %s",
                    (GLOBAL_ADMIN_EMAIL,),
                )
        log.info("schema ensure complete")
    except Exception as e:
        log.warning("ensure_schema failed (db not ready?): %s", e)

