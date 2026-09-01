-- Add folder scope label to effective_access_rows so the "Granted at" column
-- shows the folder path instead of raw "folder" text.

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
    SELECT 'folder', f.id, COALESCE(p2.name, '') || ' / ' || f.path
      FROM api.folders f LEFT JOIN api.projects p2 ON p2.id = f.project_id
    UNION ALL
    SELECT 'secret', s.id, COALESCE(p3.name, '') || ' / ' || s.key
      FROM api.secrets s LEFT JOIN api.projects p3 ON p3.id = s.project_id
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