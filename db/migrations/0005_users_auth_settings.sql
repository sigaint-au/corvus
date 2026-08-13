-- 0005_users_auth_settings
-- users auth columns, server settings, register/verify/upsert users

ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS is_global_admin boolean NOT NULL DEFAULT false;

ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS disabled_at timestamptz;

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
          ('smtp_from_name', 'Sigaint Secret Server'),
          ('smtp_login_alerts', 'false'),
          ('totp_enforce_global_admins', 'false')
        ON CONFLICT (key) DO NOTHING;

CREATE OR REPLACE FUNCTION api.is_global_admin() RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT COALESCE(
            (SELECT is_global_admin FROM private.users WHERE id = api.current_user_id()),
            false
          );
        $$;

GRANT EXECUTE ON FUNCTION api.can_read_project TO authenticated, anon;

GRANT EXECUTE ON FUNCTION api.can_write_project TO authenticated, anon;

GRANT EXECUTE ON FUNCTION api.can_admin_project TO authenticated, anon;

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
        END $$;

DO $$ BEGIN
          ALTER TABLE api.team_ldap_maps
            ADD CONSTRAINT team_ldap_maps_role_check
            CHECK (role IN ('team-owner', 'team-admin', 'team-member', 'team-viewer'));
        EXCEPTION WHEN others THEN NULL;
        END $$;

-- Migrate legacy role values to RBAC role names
        DO $$
        BEGIN
          IF to_regclass('api.team_ldap_maps') IS NOT NULL THEN
            UPDATE api.team_ldap_maps SET role = 'team-owner' WHERE role = 'owner';
            UPDATE api.team_ldap_maps SET role = 'team-admin' WHERE role = 'admin';
            UPDATE api.team_ldap_maps SET role = 'team-member' WHERE role = 'member';
            UPDATE api.team_ldap_maps SET role = 'team-viewer' WHERE role = 'viewer';
          END IF;
          IF to_regclass('api.team_oidc_maps') IS NOT NULL THEN
            UPDATE api.team_oidc_maps SET role = 'team-owner' WHERE role = 'owner';
            UPDATE api.team_oidc_maps SET role = 'team-admin' WHERE role = 'admin';
            UPDATE api.team_oidc_maps SET role = 'team-member' WHERE role = 'member';
            UPDATE api.team_oidc_maps SET role = 'team-viewer' WHERE role = 'viewer';
          END IF;
          IF to_regclass('api.team_invites') IS NOT NULL THEN
            UPDATE api.team_invites SET role = 'team-admin' WHERE role = 'admin';
            UPDATE api.team_invites SET role = 'team-member' WHERE role = 'member';
            UPDATE api.team_invites SET role = 'team-viewer' WHERE role = 'viewer';
          END IF;
          IF to_regclass('api.team_join_requests') IS NOT NULL THEN
            UPDATE api.team_join_requests SET role = 'team-admin' WHERE role = 'admin';
            UPDATE api.team_join_requests SET role = 'team-member' WHERE role = 'member';
            UPDATE api.team_join_requests SET role = 'team-viewer' WHERE role = 'viewer';
          END IF;
        END $$;

DROP POLICY IF EXISTS projects_insert ON api.projects;

CREATE POLICY projects_insert ON api.projects FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin', 'team-member'));

ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local';

DO $$ BEGIN
          ALTER TABLE private.users DROP CONSTRAINT IF EXISTS users_auth_source_check;
        EXCEPTION WHEN others THEN NULL;
        END $$;

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
        END $$;

DO $$ BEGIN
          ALTER TABLE private.users ALTER COLUMN password_hash DROP NOT NULL;
        EXCEPTION WHEN others THEN NULL;
        END $$;

-- Register a new local-auth user. Never auto-promotes to admin.
        --
        -- Input:  p_email    (text: email, case-insensitive),
        --         p_password (text: plaintext, hashed with bcrypt),
        --         p_name     (text: display name; '' if NULL)
        -- Output: uuid — new user id
        -- Example: SELECT private.register_user('alice@example.com', 's3cret', 'Alice');
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

DROP FUNCTION IF EXISTS private.verify_user(text, text);

-- Verify a local-account password; returns user row on success.
        --
        -- Input:  p_email    (text: email, case-insensitive),
        --         p_password (text: plaintext password to check)
        -- Output: TABLE(id, email, name, is_global_admin) — empty if invalid
        -- Example: SELECT * FROM private.verify_user('alice@example.com', 's3cret');
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

GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator;

-- Provision or refresh an LDAP user (no password stored).
        --
        -- Input:  p_email (text: email, case-insensitive),
        --         p_name  (text: display name from LDAP; '' preserves existing)
        -- Output: uuid — user id (existing or new)
        -- Example: SELECT private.upsert_ldap_user('bob@example.com', 'Bob Smith');
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

GRANT EXECUTE ON FUNCTION private.upsert_ldap_user TO authenticator;

-- Provision or refresh an OIDC SSO user (no password stored).
        -- Keeps auth_source 'local' if user has a local password.
        --
        -- Input:  p_email (text: email, case-insensitive),
        --         p_name  (text: display name from OIDC; '' preserves existing)
        -- Output: uuid — user id (existing or new)
        -- Example: SELECT private.upsert_oidc_user('carol@example.com', 'Carol Jones');
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

GRANT EXECUTE ON FUNCTION private.upsert_oidc_user TO authenticator;
