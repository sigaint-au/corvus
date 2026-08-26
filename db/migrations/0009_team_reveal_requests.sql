-- Team owners can allow (default) or forbid members requesting a reveal
-- of secrets they can see but cannot open. Existing approved grants still work.

ALTER TABLE api.teams
  ADD COLUMN IF NOT EXISTS allow_reveal_requests boolean NOT NULL DEFAULT true;

CREATE OR REPLACE FUNCTION api.team_allows_reveal_requests(pid uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(t.allow_reveal_requests, true)
  FROM api.projects p
  JOIN api.teams t ON t.id = p.team_id
  WHERE p.id = pid;
$$;

GRANT EXECUTE ON FUNCTION api.team_allows_reveal_requests TO authenticated, anon;
