-- RLS / privilege hardening (additive; 0001 remains the fresh-install squash).
-- Idempotent CREATE OR REPLACE / DROP POLICY IF EXISTS throughout.

-- ── 1. private DEFINER functions are not PUBLIC ──────────────────────────
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA private TO authenticator;

GRANT EXECUTE ON FUNCTION private.lookup_user TO authenticated;
GRANT EXECUTE ON FUNCTION private.team_group_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.group_member_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.secret_meta_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.touch_secret_access TO authenticated;
GRANT EXECUTE ON FUNCTION private.audit_org TO authenticated;
GRANT EXECUTE ON FUNCTION private.audit_secret TO authenticated;
GRANT EXECUTE ON FUNCTION private.lookup_invite TO authenticated;
GRANT EXECUTE ON FUNCTION private.secret_access_request_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.pending_access_requests_for_admin TO authenticated;
GRANT EXECUTE ON FUNCTION private.team_member_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.project_member_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.project_group_role_rows TO authenticated;
GRANT EXECUTE ON FUNCTION private.shared_with_me_secret_rows TO authenticated;

-- ── 2. Reveal is the reveal verb, not update ─────────────────────────────
CREATE OR REPLACE FUNCTION api.rbac_secret_binding_allows(
  p_sid uuid,
  p_need text,
  p_subject uuid DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
  SELECT EXISTS (
    SELECT 1
    FROM api.rbac_subjects(COALESCE(p_subject, api.current_user_id())) sub
    JOIN rbac.bindings b
      ON b.subject_kind = sub.subject_kind
     AND b.subject_id = sub.subject_id
    JOIN rbac.role_rules rr ON rr.role_id = b.role_id
    WHERE b.scope_kind = 'secret'
      AND b.scope_id = p_sid
      AND (
        CASE lower(COALESCE(p_need, ''))
          WHEN 'write' THEN
            api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'create')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
          WHEN 'reveal' THEN
            api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
          ELSE
            api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'get')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'list')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'reveal')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'update')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, 'secrets', 'admin')
            OR api.rbac_rule_matches(rr.resources, rr.verbs, '*', '*')
        END
      )
  );
$$;

CREATE OR REPLACE FUNCTION api.can_access_secret_row(
  sid uuid,
  pid uuid,
  mode text,
  need text DEFAULT 'read',
  deleted_at timestamptz DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL OR pid IS NULL THEN false
    WHEN deleted_at IS NOT NULL THEN false
    WHEN need IS NULL OR need NOT IN ('read', 'reveal', 'write') THEN false
    WHEN api.can_admin_project(pid) THEN true
    WHEN COALESCE(mode, 'inherit') = 'restricted' THEN
      api.rbac_secret_binding_allows(sid, need)
    WHEN need = 'write' THEN (
      api.can('update', 'secrets', 'secret', sid)
      OR api.can('create', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
    WHEN need = 'reveal' THEN (
      api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
    ELSE (
      api.can('get', 'secrets', 'secret', sid)
      OR api.can('list', 'secrets', 'secret', sid)
      OR api.can('reveal', 'secrets', 'secret', sid)
      OR api.can('update', 'secrets', 'secret', sid)
      OR api.can('admin', 'secrets', 'secret', sid)
      OR api.can('*', '*', 'secret', sid)
    )
  END;
$$;

-- ── 3. Only a team-owner (or first owner / admin DSN) can assign owner ───
CREATE OR REPLACE FUNCTION rbac.validate_binding_scope()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, rbac, private, pg_catalog
SET row_security = off AS $$
DECLARE role_name text;
DECLARE invoker text := session_user;
BEGIN
  IF NEW.scope_kind NOT IN ('cluster', 'team', 'project', 'secret') THEN
    RAISE EXCEPTION 'invalid binding scope';
  END IF;
  IF (NEW.scope_kind = 'cluster') IS DISTINCT FROM (NEW.scope_id IS NULL) THEN
    RAISE EXCEPTION 'cluster bindings require a null scope_id';
  END IF;
  IF NEW.scope_kind <> 'cluster' AND NEW.scope_id IS NULL THEN
    RAISE EXCEPTION 'non-cluster bindings require a scope_id';
  END IF;

  SELECT name INTO role_name FROM rbac.roles WHERE id = NEW.role_id;
  IF role_name IS NULL THEN
    RAISE EXCEPTION 'binding role does not exist';
  END IF;
  IF (
    (role_name LIKE 'team-%' AND NEW.scope_kind <> 'team') OR
    (role_name LIKE 'project-%' AND NEW.scope_kind <> 'project') OR
    (role_name LIKE 'secret-%' AND NEW.scope_kind <> 'secret') OR
    (role_name LIKE 'service-%' AND NEW.scope_kind NOT IN ('project', 'secret')) OR
    (role_name IN ('global-admin', 'audit-viewer') AND NEW.scope_kind <> 'cluster') OR
    (role_name NOT LIKE 'team-%' AND role_name NOT LIKE 'project-%'
     AND role_name NOT LIKE 'secret-%' AND role_name NOT LIKE 'service-%'
     AND role_name NOT IN ('global-admin', 'audit-viewer')
     AND NEW.scope_kind = 'cluster')
  ) THEN
    RAISE EXCEPTION 'role % cannot be assigned at scope %', role_name, NEW.scope_kind;
  END IF;

  IF role_name = 'team-owner' AND NEW.scope_kind = 'team' THEN
    IF invoker IN ('authenticator', 'authenticated', 'anon') THEN
      IF NOT api.is_global_admin()
         AND api.team_role(NEW.scope_id) IS DISTINCT FROM 'team-owner'
         AND EXISTS (
           SELECT 1 FROM rbac.bindings b
           JOIN rbac.roles r ON r.id = b.role_id
           WHERE b.scope_kind = 'team'
             AND b.scope_id = NEW.scope_id
             AND r.name = 'team-owner'
             AND (TG_OP = 'INSERT' OR b.id IS DISTINCT FROM NEW.id)
         ) THEN
        RAISE EXCEPTION 'only a team owner can assign team-owner';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS validate_binding_scope ON rbac.bindings;
CREATE TRIGGER validate_binding_scope
BEFORE INSERT OR UPDATE ON rbac.bindings
FOR EACH ROW EXECUTE FUNCTION rbac.validate_binding_scope();

-- ── 4. Directory maps cannot grant team-owner unless caller is owner ─────
CREATE OR REPLACE FUNCTION api.guard_team_dir_map()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NEW.role = 'team-owner'
     AND session_user IN ('authenticator', 'authenticated', 'anon')
     AND NOT api.is_global_admin()
     AND api.team_role(NEW.team_id) IS DISTINCT FROM 'team-owner' THEN
    RAISE EXCEPTION 'only a team owner can map team-owner';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_team_ldap_map ON api.team_ldap_maps;
CREATE TRIGGER guard_team_ldap_map
BEFORE INSERT OR UPDATE ON api.team_ldap_maps
FOR EACH ROW EXECUTE FUNCTION api.guard_team_dir_map();

DROP TRIGGER IF EXISTS guard_team_oidc_map ON api.team_oidc_maps;
CREATE TRIGGER guard_team_oidc_map
BEFORE INSERT OR UPDATE ON api.team_oidc_maps
FOR EACH ROW EXECUTE FUNCTION api.guard_team_dir_map();

-- ── 5. Machine tokens: project-admin only ────────────────────────────────
DROP POLICY IF EXISTS mt_insert ON api.machine_tokens;
CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
  WITH CHECK (api.can_admin_project(project_id));

DROP POLICY IF EXISTS mt_delete ON api.machine_tokens;
CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
  USING (api.can_admin_project(project_id));

DROP POLICY IF EXISTS mts_insert ON api.machine_token_scope;
CREATE POLICY mts_insert ON api.machine_token_scope FOR INSERT TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_admin_project(t.project_id)
    )
  );

DROP POLICY IF EXISTS mts_delete ON api.machine_token_scope;
CREATE POLICY mts_delete ON api.machine_token_scope FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM api.machine_tokens t
      WHERE t.id = token_id AND api.can_admin_project(t.project_id)
    )
  );

-- ── 6. Pin secret identity / approval / access_mode ──────────────────────
CREATE OR REPLACE FUNCTION api.guard_secret_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id THEN
    RAISE EXCEPTION 'secret identity fields cannot be changed';
  END IF;
  IF NEW.access_mode IS DISTINCT FROM OLD.access_mode
     OR NEW.requires_approval IS DISTINCT FROM OLD.requires_approval THEN
    IF NOT api.can_admin_project(OLD.project_id) THEN
      RAISE EXCEPTION 'only a project admin can change access_mode or requires_approval';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_secret_update ON api.secrets;
CREATE TRIGGER guard_secret_update
BEFORE UPDATE ON api.secrets
FOR EACH ROW EXECUTE FUNCTION api.guard_secret_update();

-- ── 7. Pin project.team_id ───────────────────────────────────────────────
CREATE OR REPLACE FUNCTION api.guard_project_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id THEN
    RAISE EXCEPTION 'project id cannot be changed';
  END IF;
  IF NEW.team_id IS DISTINCT FROM OLD.team_id THEN
    IF session_user IN ('authenticator', 'authenticated', 'anon')
       AND NOT (
         api.team_role(OLD.team_id) IN ('team-owner', 'team-admin')
         AND api.team_role(NEW.team_id) IN ('team-owner', 'team-admin')
       ) THEN
      RAISE EXCEPTION 'project team_id cannot be changed';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_project_update ON api.projects;
CREATE TRIGGER guard_project_update
BEFORE UPDATE ON api.projects
FOR EACH ROW EXECUTE FUNCTION api.guard_project_update();

-- ── 8. Machine get: reject service-read ──────────────────────────────────
CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, api
SET row_security = off AS $$
BEGIN
  IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
    RETURN NULL;
  END IF;
  IF private.machine_role(p_project, p_hash) = 'service-read' THEN
    RETURN NULL;
  END IF;
  RETURN (
    SELECT value_enc FROM api.secrets
    WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
  );
END;
$$;

CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
RETURNS TABLE (
  id uuid, key text, value_enc text, note text, kind text,
  expires_at timestamptz, rotation_interval_days integer, rotation_owner text,
  rotation_next_at timestamptz, rotated_at timestamptz,
  created_at timestamptz, updated_at timestamptz,
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
    SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at,
           s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
           s.created_at, s.updated_at, s.crypto_provider
    FROM api.secrets s
    WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
END;
$$;
GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;
GRANT EXECUTE ON FUNCTION private.machine_get_enc TO authenticator;

-- ── 9. Ciphertext is not a table column for authenticated ────────────────
REVOKE SELECT (value_enc) ON api.secrets FROM authenticated;
REVOKE SELECT (value_enc) ON api.secret_versions FROM authenticated;

CREATE OR REPLACE FUNCTION private.secret_enc(p_id uuid)
RETURNS TABLE (value_enc text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF p_id IS NULL OR NOT api.can_reveal_secret(p_id) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.value_enc, s.crypto_provider
    FROM api.secrets s
    WHERE s.id = p_id AND s.deleted_at IS NULL;
END;
$$;

CREATE OR REPLACE FUNCTION private.secret_version_enc(p_version uuid, p_secret uuid)
RETURNS TABLE (value_enc text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF p_version IS NULL OR p_secret IS NULL OR NOT api.can_reveal_secret(p_secret) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT v.value_enc, v.crypto_provider
    FROM api.secret_versions v
    WHERE v.id = p_version AND v.secret_id = p_secret;
END;
$$;

CREATE OR REPLACE FUNCTION private.project_reveal_enc_rows(p_project uuid)
RETURNS TABLE (id uuid, key text, value_enc text, note text, crypto_provider text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF p_project IS NULL OR NOT api.can_read_project(p_project) THEN
    RETURN;
  END IF;
  RETURN QUERY
    SELECT s.id, s.key, s.value_enc, s.note, s.crypto_provider
    FROM api.secrets s
    WHERE s.project_id = p_project
      AND s.deleted_at IS NULL
      AND api.can_reveal_secret(s.id)
    ORDER BY s.key;
END;
$$;

GRANT EXECUTE ON FUNCTION private.secret_enc TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.secret_version_enc TO authenticator, authenticated;
GRANT EXECUTE ON FUNCTION private.project_reveal_enc_rows TO authenticator, authenticated;

-- ── 10. Unauthenticated DEFINER oracles ──────────────────────────────────
REVOKE EXECUTE ON FUNCTION api.rbac_scope_chain(text, uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION api.rbac_rule_matches(text[], text[], text, text) FROM anon;
REVOKE EXECUTE ON FUNCTION api.my_access_rows() FROM anon;
REVOKE EXECUTE ON FUNCTION api.project_key_provider(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION api.project_key_providers(uuid[]) FROM anon;
REVOKE EXECUTE ON FUNCTION api.rbac_secret_binding_allows(uuid, text, uuid) FROM anon;
