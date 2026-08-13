-- 0007_teams_policies
-- teams select/insert RLS policies

DROP POLICY IF EXISTS teams_select ON api.teams;

CREATE POLICY teams_select ON api.teams FOR SELECT TO authenticated
          USING (api.is_global_admin() OR api.is_team_member(id));

DROP POLICY IF EXISTS teams_insert ON api.teams;

CREATE POLICY teams_insert ON api.teams FOR INSERT TO authenticated
          WITH CHECK (created_by = api.current_user_id() OR api.is_global_admin());
