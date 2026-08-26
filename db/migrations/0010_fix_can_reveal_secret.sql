-- 0008 passed an invalid need to can_access_secret (only read/reveal/write
-- are accepted), so the visibility check was always false and nobody could
-- decrypt — including global admins and team-owners. Admins short-circuit
-- first; everyone else must be able to see the secret (read) before a grant
-- or reveal ACL can apply.

CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
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
