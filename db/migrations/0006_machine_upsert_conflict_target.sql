-- Fix ON CONFLICT target in machine_upsert_enc to match the root-level unique
-- index introduced by 0003_secret_folders.sql.
--
-- Migration 0003 split secrets_project_key_live into two partial unique indexes:
--   (project_id, key) WHERE folder_id IS NULL AND deleted_at IS NULL     [root secrets]
--   (project_id, folder_id, key) WHERE folder_id IS NOT NULL AND deleted_at IS NULL  [folder secrets]
--
-- machine_upsert_enc always creates root-level secrets (no folder_id), so its
-- ON CONFLICT clause must now include the folder_id IS NULL predicate.
--
-- 0001_init.sql left two overloads: the 8-arg form (no p_crypto_provider) and
-- the 9-arg form. GRANT without an argument list is then ambiguous and aborts
-- this migration. Drop the stale 8-arg function first.

DROP FUNCTION IF EXISTS private.machine_upsert_enc(uuid, text, text, text, text, text, timestamptz, boolean);

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
  RETURN sid;
END;
$$;

GRANT EXECUTE ON FUNCTION private.machine_upsert_enc(uuid, text, text, text, text, text, timestamptz, boolean, text) TO authenticator;