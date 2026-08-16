-- 0003_machine_role_enforcement.sql
--
-- Enforce machine-token role on the read/reveal path.
--
-- Previously, private.machine_get_row and private.machine_list_enc returned
-- value_enc for ANY valid token regardless of role. A service-read token
-- (intended for metadata-only ESO sync) could retrieve ciphertext, which
-- the app then decrypted and returned as plaintext.
--
-- This migration adds a role gate: service-read tokens receive no rows
-- from machine_get_row / machine_list_enc (same behaviour as "not found").
-- service-reveal and service-write retain full access.

-- ── machine_get_row: refuse service-read ──────────────────────────────
--
-- Input:  p_project (uuid), p_hash (text), p_key (text)
-- Output: TABLE(id, key, value_enc, note, kind, expires_at, created_at, updated_at, crypto_provider)
--         — empty when token is service-read, invalid, or key not allowed
-- Example: SELECT * FROM private.machine_get_row('<uuid>', '<hash>', 'API_KEY');
--
-- The baseline squashed 0001 already shipped a machine_get_row returning the
-- rotation_* columns; this migration replaces it with a narrower signature
-- that adds the service-read gate. CREATE OR REPLACE rejects return-type
-- changes, so drop the old signature first (same pattern as 0001's own
-- crypto_provider change).

DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);

CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
RETURNS TABLE (
  id uuid,
  key text,
  value_enc text,
  note text,
  kind text,
  expires_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz,
  crypto_provider text
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
    SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at, s.created_at, s.updated_at, s.crypto_provider
    FROM api.secrets s
    WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
END;
$$;

-- ── machine_list_enc: refuse service-read ──────────────────────────────
--
-- Input:  p_project (uuid), p_hash (text)
-- Output: TABLE(key, value_enc, crypto_provider) — empty for service-read
-- Example: SELECT * FROM private.machine_list_enc('<uuid>', '<hash>');

CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
RETURNS TABLE (key text, value_enc text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.auth_machine(p_project, p_hash) THEN
    RETURN;
  END IF;
  IF private.machine_role(p_project, p_hash) = 'service-read' THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.key, s.value_enc, s.crypto_provider FROM api.secrets s
    WHERE s.project_id = p_project AND s.deleted_at IS NULL
      AND private.machine_key_allowed(p_project, p_hash, s.key);
END;
$$;

-- Re-grant execute (CREATE OR REPLACE preserves grants, but be explicit).
GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_list_enc TO authenticator;
