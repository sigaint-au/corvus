-- Parse /-separated key in machine_upsert_enc to create folder hierarchy
-- and store secrets with folder_id, matching web UI behavior.

CREATE OR REPLACE FUNCTION private.machine_upsert_enc(
  p_project uuid,
  p_hash text,
  p_key text,
  p_value_enc text,
  p_note text,
  p_kind text DEFAULT 'plain',
  p_expires_at timestamptz DEFAULT NULL,
  p_set_expires boolean DEFAULT false,
  p_crypto_provider text DEFAULT 'master'
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
DECLARE
  sid uuid;
  k text := COALESCE(NULLIF(btrim(p_kind), ''), 'plain');
  parts text[];
  folder_segments text[];
  folder_id uuid;
BEGIN
  IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
    RETURN NULL;
  END IF;
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN NULL;
  END IF;
  IF p_key IS NULL OR btrim(p_key) = '' OR p_value_enc IS NULL THEN
    RETURN NULL;
  END IF;
  IF k NOT IN ('plain', 'database', 'certificate', 'ssh', 'kv') THEN
    k := 'plain';
  END IF;

  -- Parse key into folder segments + leaf name
  parts := string_to_array(p_key, '/');
  IF array_length(parts, 1) > 1 THEN
    folder_segments := parts[1:array_length(parts, 1) - 1];
    FOR i IN 1 .. array_length(folder_segments, 1) LOOP
      folder_id := private.materialize_folder_path(
        p_project,
        CASE WHEN i = 1 THEN NULL ELSE folder_id END,
        folder_segments[i],
        (SELECT array_to_string(folder_segments[1:i], '/'))
      );
    END LOOP;
    INSERT INTO api.secrets (project_id, folder_id, key, value_enc, note, kind, expires_at, crypto_provider)
    VALUES (
      p_project, folder_id, p_key, p_value_enc, COALESCE(p_note, ''), k,
      CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END,
      CASE WHEN p_crypto_provider IN ('master', 'project') THEN p_crypto_provider ELSE 'master' END
    )
    ON CONFLICT (project_id, folder_id, key) WHERE folder_id IS NOT NULL AND deleted_at IS NULL DO UPDATE
      SET value_enc = EXCLUDED.value_enc,
          note = EXCLUDED.note,
          kind = EXCLUDED.kind,
          crypto_provider = EXCLUDED.crypto_provider,
          expires_at = CASE
            WHEN p_set_expires THEN p_expires_at
            ELSE api.secrets.expires_at
          END
    RETURNING id INTO sid;
  ELSE
    INSERT INTO api.secrets (project_id, key, value_enc, note, kind, expires_at, crypto_provider)
    VALUES (
      p_project, p_key, p_value_enc, COALESCE(p_note, ''), k,
      CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END,
      CASE WHEN p_crypto_provider IN ('master', 'project') THEN p_crypto_provider ELSE 'master' END
    )
    ON CONFLICT (project_id, key) WHERE folder_id IS NULL AND deleted_at IS NULL DO UPDATE
      SET value_enc = EXCLUDED.value_enc,
          note = EXCLUDED.note,
          kind = EXCLUDED.kind,
          crypto_provider = EXCLUDED.crypto_provider,
          expires_at = CASE
            WHEN p_set_expires THEN p_expires_at
            ELSE api.secrets.expires_at
          END
    RETURNING id INTO sid;
  END IF;
  RETURN sid;
END;
$$;

GRANT EXECUTE ON FUNCTION private.machine_upsert_enc TO authenticator;