-- Expose a project's BYOK key provider to authenticated readers for list badges.
--
-- The app needs to show an "HSM" / "BYOK" indicator in project lists without
-- leaking the wrapped DEK in private.project_crypto_keys. This SECURITY DEFINER
-- helper returns only the ``key_provider`` string, gated on project read access.

CREATE OR REPLACE FUNCTION api.project_key_provider(p_project uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT k.key_provider
  FROM private.project_crypto_keys k
  WHERE k.project_id = p_project
    AND (api.is_global_admin() OR api.can_read_project(p_project));
$$;

GRANT EXECUTE ON FUNCTION api.project_key_provider(uuid) TO authenticator, authenticated, anon;
