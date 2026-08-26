-- Team-members and viewers can list secrets they cannot reveal. An approved
-- time-limited access request must be enough to show the value; previously
-- can_reveal_secret required reveal ACL first, so grants never helped.

CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
    WHEN NOT api.can_access_secret(sid, 'get') THEN false
    WHEN api.is_global_admin() THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid AND api.can_admin_project(s.project_id)
    ) THEN true
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
