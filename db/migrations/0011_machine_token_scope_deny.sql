-- Machine tokens: empty allow-list denies; restricted secrets need an exact
-- key (globs including * do not cover them). Existing unscoped tokens get
-- an explicit * so inherit keys keep working. team-member / project-write
-- lose machine_tokens create/update (RLS was already admin-only in 0002).

INSERT INTO api.machine_token_scope (token_id, key_pattern)
SELECT t.id, '*'
FROM api.machine_tokens t
WHERE NOT EXISTS (
  SELECT 1 FROM api.machine_token_scope sc WHERE sc.token_id = t.id
);

CREATE OR REPLACE FUNCTION private.machine_key_allowed(
  p_project uuid, p_hash text, p_key text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
  SELECT CASE
    WHEN p_key IS NULL OR btrim(p_key) = '' THEN false
    WHEN NOT private.auth_machine(p_project, p_hash) THEN false
    WHEN NOT EXISTS (
      SELECT 1
      FROM api.machine_token_scope sc
      JOIN api.machine_tokens t ON t.id = sc.token_id
      WHERE t.project_id = p_project
        AND t.token_hash = p_hash
        AND (t.expires_at IS NULL OR t.expires_at > now())
    ) THEN false
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL
        AND COALESCE(s.access_mode, 'inherit') = 'restricted'
    ) THEN EXISTS (
      SELECT 1
      FROM api.machine_token_scope sc
      JOIN api.machine_tokens t ON t.id = sc.token_id
      WHERE t.project_id = p_project
        AND t.token_hash = p_hash
        AND (t.expires_at IS NULL OR t.expires_at > now())
        AND sc.secret_key IS NOT NULL AND sc.secret_key = p_key
    )
    WHEN EXISTS (
      SELECT 1
      FROM api.machine_token_scope sc
      JOIN api.machine_tokens t ON t.id = sc.token_id
      WHERE t.project_id = p_project
        AND t.token_hash = p_hash
        AND (t.expires_at IS NULL OR t.expires_at > now())
        AND (
          (sc.secret_key IS NOT NULL AND sc.secret_key = p_key)
          OR (
            sc.key_pattern IS NOT NULL
            AND p_key LIKE private.glob_to_like(sc.key_pattern) ESCAPE E'\\'
          )
        )
    ) THEN true
    ELSE false
  END;
$$;

GRANT EXECUTE ON FUNCTION private.machine_key_allowed TO authenticator;

UPDATE rbac.role_rules rr
SET resources = array_remove(rr.resources, 'machine_tokens')
FROM rbac.roles r
WHERE rr.role_id = r.id
  AND r.name IN ('team-member', 'project-write')
  AND 'machine_tokens' = ANY (rr.resources);
