-- Machine privileged metadata helper for corvus-agent.
-- Ponytail: no new table; reuses api.secret_meta. Security definer + row_security off
-- so machine tokens (authenticator role, no JWT) can set corvus.* keys without RLS.

CREATE OR REPLACE FUNCTION private.machine_set_meta(
  p_project uuid,
  p_hash text,
  p_key text,
  p_meta_key text,
  p_meta_value text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE
  v_secret_id uuid;
  v_val text := left(COALESCE(p_meta_value, ''), 2000);
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
    RETURN;
  END IF;
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN;
  END IF;
  IF p_meta_key IS NULL OR p_meta_key !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' THEN
    RETURN;
  END IF;
  -- Secret already upserted; handle folder hierarchy (key may contain slashes)
  SELECT id INTO v_secret_id
    FROM api.secrets
   WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
   LIMIT 1;
  IF v_secret_id IS NULL THEN
    RETURN;
  END IF;
  INSERT INTO api.secret_meta (secret_id, key, value, updated_at)
  VALUES (v_secret_id, p_meta_key, v_val, now())
  ON CONFLICT (secret_id, key) DO UPDATE
    SET value = EXCLUDED.value, updated_at = now();
END;
$$;

GRANT EXECUTE ON FUNCTION private.machine_set_meta(uuid, text, text, text, text) TO authenticator;
