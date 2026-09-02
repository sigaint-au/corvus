-- Machine list/meta must include secret_meta so CLI can filter by corvus.* keys.
-- Ponytail: add metadata jsonb column; no new table.

DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
RETURNS TABLE (
  id uuid, key text, value_enc text, note text, kind text,
  expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
  rotation_next_at timestamptz, rotated_at timestamptz,
  created_at timestamptz, updated_at timestamptz,
  crypto_provider text, metadata jsonb
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN;
  END IF;
  IF private.machine_role(p_project, p_hash) = 'service-read' THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
           s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
           s.created_at, s.updated_at, s.crypto_provider,
           COALESCE((SELECT jsonb_object_agg(m.key, m.value) FROM api.secret_meta m WHERE m.secret_id = s.id), '{}'::jsonb) AS metadata
    FROM api.secrets s
    WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
END;
$$;
GRANT EXECUTE ON FUNCTION private.machine_get_row(uuid, text, text) TO authenticator;

DROP FUNCTION IF EXISTS private.machine_list_meta(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_list_meta(p_project uuid, p_hash text, p_q text DEFAULT NULL)
RETURNS TABLE (
  id uuid, key text, note text, kind text,
  expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
  rotation_next_at timestamptz, rotated_at timestamptz,
  created_at timestamptz, updated_at timestamptz,
  metadata jsonb
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE q text := NULLIF(btrim(COALESCE(p_q, '')), '');
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.note, s.kind, s.expires_at,
           s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
           s.created_at, s.updated_at,
           COALESCE((SELECT jsonb_object_agg(m.key, m.value) FROM api.secret_meta m WHERE m.secret_id = s.id), '{}'::jsonb) AS metadata
    FROM api.secrets s
    WHERE s.project_id = p_project
      AND s.deleted_at IS NULL
      AND private.machine_key_allowed(p_project, p_hash, s.key)
      AND (
        q IS NULL
        OR s.key ILIKE ('%' || q || '%')
        OR s.note ILIKE ('%' || q || '%')
        OR EXISTS (
          SELECT 1 FROM api.secret_meta m
          WHERE m.secret_id = s.id
            AND (m.key ILIKE ('%' || q || '%') OR m.value ILIKE ('%' || q || '%'))
        )
      )
    ORDER BY s.key;
END;
$$;
GRANT EXECUTE ON FUNCTION private.machine_list_meta(uuid, text, text) TO authenticator;
