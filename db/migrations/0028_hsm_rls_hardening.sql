CREATE OR REPLACE FUNCTION api.list_hsm_slots()
RETURNS TABLE (
  id uuid, name text, pkcs11_url text, description text,
  is_default boolean, created_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
  SELECT s.id, s.name,
         CASE WHEN api.is_global_admin() THEN s.pkcs11_url ELSE NULL END,
         s.description, s.is_default, s.created_at
  FROM private.hsm_slots s
  ORDER BY s.is_default DESC, s.name;
$$;

REVOKE EXECUTE ON FUNCTION api.list_hsm_slots() FROM anon;
GRANT EXECUTE ON FUNCTION api.list_hsm_slots() TO authenticated;

REVOKE EXECUTE ON FUNCTION api.hsm_slot_url(uuid)
  FROM anon, authenticated, authenticator;
REVOKE EXECUTE ON FUNCTION api.hsm_slot_upsert(uuid, text, text, text, boolean) FROM anon;
REVOKE EXECUTE ON FUNCTION api.hsm_slot_delete(uuid) FROM anon;

CREATE OR REPLACE FUNCTION api.hsm_slot_upsert(
  p_id uuid,
  p_name text,
  p_url text,
  p_description text DEFAULT '',
  p_is_default boolean DEFAULT false
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog
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
    IF EXISTS (
      SELECT 1 FROM private.project_crypto_keys
      WHERE hsm_slot_id = p_id
    ) AND EXISTS (
      SELECT 1 FROM private.hsm_slots
      WHERE id = p_id AND pkcs11_url IS DISTINCT FROM p_url
    ) THEN
      RAISE EXCEPTION 'cannot change the URL of a slot used by project keys; create a new slot and migrate the projects';
    END IF;
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

CREATE OR REPLACE FUNCTION api.rbac_subjects(p_user uuid DEFAULT NULL)
RETURNS TABLE(subject_kind text, subject_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
  WITH u AS (
    SELECT CASE
      WHEN p_user IS NULL
        OR p_user IS NOT DISTINCT FROM api.current_user_id()
        OR api.is_global_admin()
      THEN COALESCE(p_user, api.current_user_id())
      ELSE NULL::uuid
    END AS id
  )
  SELECT 'User'::text, u.id FROM u WHERE u.id IS NOT NULL
  UNION ALL
  SELECT 'Group'::text, gm.group_id
  FROM u
  JOIN api.group_members gm ON gm.user_id = u.id;
$$;

CREATE OR REPLACE FUNCTION api.can(
  p_verb text,
  p_resource text,
  p_scope_kind text DEFAULT 'cluster',
  p_scope_id uuid DEFAULT NULL,
  p_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
DECLARE uid uuid := COALESCE(p_subject, api.current_user_id());
DECLARE v_verb text := lower(btrim(COALESCE(p_verb, '')));
DECLARE v_res text := lower(btrim(COALESCE(p_resource, '')));
DECLARE ok boolean;
BEGIN
  IF p_subject IS NOT NULL
     AND p_subject IS DISTINCT FROM api.current_user_id()
     AND NOT api.is_global_admin() THEN
    RETURN false;
  END IF;
  IF uid IS NULL OR v_verb = '' OR v_res = '' THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1 FROM private.users WHERE id = uid AND is_global_admin
  ) THEN
    RETURN true;
  END IF;
  IF v_res = 'secrets' AND p_scope_kind = 'secret' AND p_scope_id IS NOT NULL THEN
    IF EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = p_scope_id AND s.deleted_at IS NOT NULL
    ) THEN
      RETURN false;
    END IF;
  END IF;
  SELECT EXISTS (
    SELECT 1
    FROM api.rbac_subjects(uid) sub
    JOIN rbac.bindings b
      ON b.subject_kind = sub.subject_kind
     AND b.subject_id = sub.subject_id
    JOIN api.rbac_scope_chain(p_scope_kind, p_scope_id) sc
      ON sc.scope_kind = b.scope_kind
     AND (
       (sc.scope_kind = 'cluster' AND b.scope_id IS NULL)
       OR (b.scope_id IS NOT DISTINCT FROM sc.scope_id)
     )
    JOIN rbac.role_rules rr ON rr.role_id = b.role_id
    WHERE api.rbac_rule_matches(rr.resources, rr.verbs, v_res, v_verb)
  ) INTO ok;
  RETURN COALESCE(ok, false);
END;
$$;

REVOKE EXECUTE ON FUNCTION api.rbac_subjects(uuid) FROM anon;
