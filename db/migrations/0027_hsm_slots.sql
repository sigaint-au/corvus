-- Multi-HSM slots: named PKCS#11 URL configurations for BYOK.
--
-- A project's crypto key may link to a named slot (hsm_slot_id) instead of
-- relying on the global env-var HSM config. The app resolves the slot's
-- PKCS#11 URL and opens a session against that module/token.

CREATE TABLE private.hsm_slots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  pkcs11_url text NOT NULL,
  description text NOT NULL DEFAULT '',
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON private.hsm_slots FROM authenticator, authenticated, anon;

ALTER TABLE private.project_crypto_keys
  ADD COLUMN IF NOT EXISTS hsm_slot_id uuid
    REFERENCES private.hsm_slots(id) ON DELETE SET NULL;

-- List all slots (defaults first, then by name). Any authenticated user may
-- read slot names/URLs; the answers never include a PIN (redacted at render).
CREATE OR REPLACE FUNCTION api.list_hsm_slots()
RETURNS TABLE (
  id uuid, name text, pkcs11_url text, description text,
  is_default boolean, created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT s.id, s.name, s.pkcs11_url, s.description, s.is_default, s.created_at
  FROM private.hsm_slots s
  ORDER BY s.is_default DESC, s.name;
$$;

GRANT EXECUTE ON FUNCTION api.list_hsm_slots() TO authenticator, authenticated, anon;

-- Resolve a slot's PKCS#11 URL (used by the crypto layer to unwrap DEKs).
CREATE OR REPLACE FUNCTION api.hsm_slot_url(p_slot_id uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT s.pkcs11_url FROM private.hsm_slots s WHERE s.id = p_slot_id;
$$;

GRANT EXECUTE ON FUNCTION api.hsm_slot_url(uuid) TO authenticator, authenticated, anon;

-- Create or update a slot (global admins only). Setting is_default=true clears
-- the flag on every other slot first. Returns the slot id.
CREATE OR REPLACE FUNCTION api.hsm_slot_upsert(
  p_id uuid,
  p_name text,
  p_url text,
  p_description text DEFAULT '',
  p_is_default boolean DEFAULT false
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
DECLARE v_id uuid;
BEGIN
  IF NOT api.is_global_admin() THEN
    RAISE EXCEPTION 'global admin required';
  END IF;
  IF p_id IS NULL THEN
    IF p_is_default THEN
      UPDATE private.hsm_slots SET is_default = false WHERE is_default;
    END IF;
    INSERT INTO private.hsm_slots (name, pkcs11_url, description, is_default)
    VALUES (btrim(p_name), p_url, COALESCE(p_description, ''), COALESCE(p_is_default, false))
    RETURNING id INTO v_id;
  ELSE
    IF p_is_default THEN
      UPDATE private.hsm_slots SET is_default = false WHERE is_default AND id <> p_id;
    END IF;
    UPDATE private.hsm_slots
    SET name = btrim(p_name),
        pkcs11_url = p_url,
        description = COALESCE(p_description, ''),
        is_default = COALESCE(p_is_default, false),
        updated_at = now()
    WHERE id = p_id
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION api.hsm_slot_upsert(uuid, text, text, text, boolean)
  TO authenticator, authenticated, anon;

-- Delete a slot (global admin only); blocks when projects still reference it.
CREATE OR REPLACE FUNCTION api.hsm_slot_delete(p_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
BEGIN
  IF NOT api.is_global_admin() THEN
    RAISE EXCEPTION 'global admin required';
  END IF;
  IF EXISTS (
    SELECT 1 FROM private.project_crypto_keys k WHERE k.hsm_slot_id = p_id
  ) THEN
    RAISE EXCEPTION 'slot is in use by one or more projects';
  END IF;
  DELETE FROM private.hsm_slots WHERE id = p_id;
END;
$$;

GRANT EXECUTE ON FUNCTION api.hsm_slot_delete(uuid) TO authenticator, authenticated, anon;