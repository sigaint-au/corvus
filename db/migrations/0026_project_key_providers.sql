-- Batch key-provider lookup for project lists (avoids N+1 per-project calls).
--
-- Same gating as api.project_key_provider(): only reveals the provider string
-- for projects the current user can read (or for global admins).

CREATE OR REPLACE FUNCTION api.project_key_providers(p_ids uuid[])
RETURNS TABLE(project_id uuid, key_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  RETURN QUERY
    SELECT k.project_id, k.key_provider
    FROM private.project_crypto_keys k
    JOIN api.projects p ON p.id = k.project_id
    WHERE k.project_id = ANY(p_ids)
      AND (api.is_global_admin() OR api.can_read_project(k.project_id));
END;
$$;

GRANT EXECUTE ON FUNCTION api.project_key_providers(uuid[]) TO authenticator, authenticated, anon;