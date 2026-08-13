-- 0019_row_acl_and_groups
-- row-based secret ACL, org RBAC groups

GRANT EXECUTE ON FUNCTION api.can_access_secret_row TO authenticated, anon;

GRANT EXECUTE ON FUNCTION api.can_access_secret TO authenticated, anon;

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

CREATE TABLE IF NOT EXISTS api.groups (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          name text NOT NULL,
          source text NOT NULL DEFAULT 'manual'
            CHECK (source IN ('manual', 'ldap', 'oidc')),
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

CREATE INDEX IF NOT EXISTS group_members_user_idx
          ON api.group_members (user_id);

DROP POLICY IF EXISTS secrets_insert ON api.secrets;

CREATE POLICY secrets_insert ON api.secrets FOR INSERT TO authenticated
          WITH CHECK (api.can_write_project(project_id));

DROP POLICY IF EXISTS secrets_select ON api.secrets;

CREATE POLICY secrets_select ON api.secrets FOR SELECT TO authenticated
          USING (
            (deleted_at IS NULL AND api.can_access_secret_row(id, project_id, access_mode, 'read', NULL))
            OR (deleted_at IS NOT NULL AND api.can_access_secret_row(id, project_id, access_mode, 'write', NULL))
          );

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

ALTER TABLE api.groups ENABLE ROW LEVEL SECURITY;

ALTER TABLE api.group_members ENABLE ROW LEVEL SECURITY;

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

CREATE OR REPLACE FUNCTION private.team_group_rows(p_team uuid)
        RETURNS TABLE (
          id uuid, name text, source text, external_key text,
          member_count bigint, created_at timestamptz
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
          WHERE g.team_id = p_team AND api.is_team_member(p_team)
          ORDER BY g.name;
        END;
        $$;

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
          WHERE gm.group_id = p_group AND api.is_team_member(g.team_id)
          ORDER BY u.email;
        END;
        $$;

GRANT EXECUTE ON FUNCTION api.project_role TO authenticated, anon;

GRANT EXECUTE ON FUNCTION private.team_group_rows TO authenticator, authenticated;

GRANT EXECUTE ON FUNCTION private.group_member_rows TO authenticator, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON api.groups TO authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON api.group_members TO authenticated;

GRANT ALL ON api.groups TO authenticator;

GRANT ALL ON api.group_members TO authenticator;
