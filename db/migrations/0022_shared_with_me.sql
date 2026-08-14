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
