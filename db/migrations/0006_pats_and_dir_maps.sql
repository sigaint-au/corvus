-- 0006_pats_and_dir_maps
-- personal access tokens, LDAP/OIDC role maps, team dir maps

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
        );

CREATE INDEX IF NOT EXISTS personal_access_tokens_user_idx
          ON private.personal_access_tokens (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS private.ldap_role_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('global_admin')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (ldap_group)
        );

CREATE TABLE IF NOT EXISTS api.team_ldap_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          ldap_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (team_id, ldap_group)
        );

ALTER TABLE api.team_ldap_maps ENABLE ROW LEVEL SECURITY;

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

GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_ldap_maps TO authenticated;

GRANT ALL ON api.team_ldap_maps TO authenticator;

CREATE TABLE IF NOT EXISTS private.oidc_role_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          oidc_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('global_admin')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (oidc_group)
        );

CREATE TABLE IF NOT EXISTS api.team_oidc_maps (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          oidc_group text NOT NULL,
          role text NOT NULL CHECK (role IN ('team-owner', 'team-admin', 'team-member', 'team-viewer')),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (team_id, oidc_group)
        );

ALTER TABLE api.team_oidc_maps ENABLE ROW LEVEL SECURITY;

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

GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_oidc_maps TO authenticated;

GRANT ALL ON api.team_oidc_maps TO authenticator;

DROP FUNCTION IF EXISTS private.get_setting(text);

DROP FUNCTION IF EXISTS private.set_setting(text, text);

DROP FUNCTION IF EXISTS private.all_settings();

DROP VIEW IF EXISTS api.user_directory;

CREATE VIEW api.user_directory AS
          SELECT id, email, name, is_global_admin, created_at FROM private.users;

REVOKE ALL ON api.user_directory FROM authenticated;

GRANT SELECT ON api.user_directory TO authenticator;

GRANT ALL ON api.user_directory TO authenticator;

GRANT EXECUTE ON FUNCTION api.is_global_admin TO authenticated, anon;

CREATE OR REPLACE FUNCTION private.lookup_user(p_email text)
        RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = private
        SET row_security = off AS $$
          SELECT id FROM private.users WHERE email = lower(p_email) LIMIT 1;
        $$;

GRANT USAGE ON SCHEMA private TO authenticator, authenticated;

GRANT EXECUTE ON FUNCTION private.lookup_user TO authenticator, authenticated;
