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
-- Email verification for locally-registered accounts.
-- Adds verification columns to private.users and stamps directory-provisioned
-- users as verified: LDAP/OIDC sign-in already proves control of the mailbox.
-- Locally-registered accounts start unverified when SMTP is configured; the
-- app emails a single-use link (hashed at rest, 3-day window).

ALTER TABLE private.users
  ADD COLUMN IF NOT EXISTS email_verified_at timestamptz,
  ADD COLUMN IF NOT EXISTS email_verify_token_hash text,
  ADD COLUMN IF NOT EXISTS email_verify_sent_at timestamptz;

CREATE INDEX IF NOT EXISTS users_email_verify_token_idx
  ON private.users (email_verify_token_hash)
  WHERE email_verify_token_hash IS NOT NULL;

-- Directory provisioning proves the address: keep it verified.
CREATE OR REPLACE FUNCTION private.upsert_ldap_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source,
                               email_verified_at)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'ldap', now())
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = 'ldap',
        email_verified_at = COALESCE(email_verified_at, now())
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;

CREATE OR REPLACE FUNCTION private.upsert_oidc_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source,
                               email_verified_at)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'oidc', now())
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = CASE
          WHEN auth_source = 'local' AND password_hash IS NOT NULL THEN auth_source
          ELSE 'oidc'
        END,
        email_verified_at = COALESCE(email_verified_at, now())
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;
-- Email verification follow-up:
-- 1. Existing accounts already proved control of the mailbox by using the
--    system; stamp them verified so the login gate does not lock them out.
-- 2. Return email_verified_at from private.verify_user so login does not
--    SELECT private.users as authenticator (no table privilege).

UPDATE private.users
   SET email_verified_at = COALESCE(email_verified_at, created_at, now())
 WHERE email_verified_at IS NULL;

DROP FUNCTION IF EXISTS private.verify_user(text, text);

CREATE OR REPLACE FUNCTION private.verify_user(p_email text, p_password text)
RETURNS TABLE (
  id uuid,
  email text,
  name text,
  is_global_admin boolean,
  email_verified_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email, u.name, u.is_global_admin, u.email_verified_at
    FROM private.users u
   WHERE u.email = lower(p_email)
     AND u.password_hash IS NOT NULL
     AND u.disabled_at IS NULL
     AND u.password_hash = crypt(p_password, u.password_hash);
END;
$$;

GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator;
-- Clusters bootstrapped from an older 0001 (PBKDF2 hashed in the app, stored
-- as-is) need the bcrypt-in-SQL helpers that later landed in the baseline.
-- Additive so existing volumes can take the new app without replaying 0001.
-- DROP the 1-arg verify_user leftover; 0004 already created the 2-arg form.

DROP FUNCTION IF EXISTS private.verify_user(text);

CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
  VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), false, 'local')
  RETURNING id INTO uid;
  RETURN uid;
END;
$$;

CREATE OR REPLACE FUNCTION private.change_password(
  p_user uuid, p_old text, p_new text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  IF p_new IS NULL OR length(p_new) < 8 THEN
    RAISE EXCEPTION 'password must be at least 8 characters';
  END IF;
  UPDATE private.users
  SET password_hash = crypt(p_new, gen_salt('bf'))
  WHERE id = p_user
    AND auth_source = 'local'
    AND password_hash IS NOT NULL
    AND password_hash = crypt(p_old, password_hash);
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION private.set_local_password(p_user uuid, p_new text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  IF p_new IS NULL OR length(p_new) < 8 THEN
    RAISE EXCEPTION 'password must be at least 8 characters';
  END IF;
  UPDATE private.users
  SET password_hash = crypt(p_new, gen_salt('bf'))
  WHERE id = p_user
    AND auth_source = 'local'
    AND password_hash IS NOT NULL;
  RETURN FOUND;
END;
$$;

GRANT EXECUTE ON FUNCTION private.register_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.change_password TO authenticator;
GRANT EXECUTE ON FUNCTION private.set_local_password TO authenticator;
-- Rewrite leftover product names seeded by older defaults. Do not edit 0001:
-- its checksum is already recorded on existing databases.

UPDATE private.server_settings
   SET value = 'Corvus'
 WHERE key = 'smtp_from_name'
   AND value IN ('Sigaint Secret Server', 'Sigaint');

UPDATE private.server_settings
   SET value = 'Corvus'
 WHERE key = 'brand_name'
   AND value IN ('Sigaint', 'Sigaint Secret Server');

UPDATE private.server_settings
   SET value = 'Keep your secrets.'
 WHERE key = 'brand_tagline'
   AND value IN ('Secret Server', 'Secret Server v0.1.0', '');

INSERT INTO private.server_settings (key, value)
VALUES ('brand_tagline', 'Keep your secrets.')
ON CONFLICT (key) DO NOTHING;
-- Per-user login-alert email preference, plus a server force-override.
-- smtp_login_alerts remains the master switch; smtp_login_alerts_force
-- ignores the user preference when both SMTP and login alerts are on.

ALTER TABLE private.users
  ADD COLUMN IF NOT EXISTS login_alerts boolean NOT NULL DEFAULT true;

INSERT INTO private.server_settings (key, value)
VALUES ('smtp_login_alerts_force', 'false')
ON CONFLICT (key) DO NOTHING;
-- Team-members and viewers can list secrets they cannot reveal. An approved
-- time-limited access request must be enough to show the value; previously
-- can_reveal_secret required reveal ACL first, so grants never helped.

CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
    WHEN NOT api.can_access_secret(sid, 'get') THEN false
    WHEN api.is_global_admin() THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid AND api.can_admin_project(s.project_id)
    ) THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secret_access_requests r
      WHERE r.secret_id = sid
        AND r.user_id = api.current_user_id()
        AND r.status = 'approved'
        AND r.approved_until IS NOT NULL
        AND r.approved_until > now()
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
    WHEN NOT COALESCE(api.secret_requires_approval(sid), false) THEN true
    ELSE false
  END;
$$;
-- Team owners can allow (default) or forbid members requesting a reveal
-- of secrets they can see but cannot open. Existing approved grants still work.

ALTER TABLE api.teams
  ADD COLUMN IF NOT EXISTS allow_reveal_requests boolean NOT NULL DEFAULT true;

CREATE OR REPLACE FUNCTION api.team_allows_reveal_requests(pid uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT COALESCE(t.allow_reveal_requests, true)
  FROM api.projects p
  JOIN api.teams t ON t.id = p.team_id
  WHERE p.id = pid;
$$;

GRANT EXECUTE ON FUNCTION api.team_allows_reveal_requests TO authenticated, anon;
-- 0008 passed an invalid need to can_access_secret (only read/reveal/write
-- are accepted), so the visibility check was always false and nobody could
-- decrypt — including global admins and team-owners. Admins short-circuit
-- first; everyone else must be able to see the secret (read) before a grant
-- or reveal ACL can apply.

CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
    WHEN api.is_global_admin() THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid
        AND s.deleted_at IS NULL
        AND api.can_admin_project(s.project_id)
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'read') THEN false
    WHEN EXISTS (
      SELECT 1 FROM api.secret_access_requests r
      WHERE r.secret_id = sid
        AND r.user_id = api.current_user_id()
        AND r.status = 'approved'
        AND r.approved_until IS NOT NULL
        AND r.approved_until > now()
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
    WHEN NOT COALESCE(api.secret_requires_approval(sid), false) THEN true
    ELSE false
  END;
$$;

GRANT EXECUTE ON FUNCTION api.can_reveal_secret TO authenticated, anon;
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
-- 0010 let global admins reveal soft-deleted secrets: the is_global_admin()
-- branch ran before any deleted_at check (project admins were already
-- guarded). Deleted secrets stay unrevealable for everyone; restore flow
-- requires write access, not plaintext.

CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = api, private
SET row_security = off AS $$
  SELECT CASE
    WHEN sid IS NULL THEN false
    WHEN NOT EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid AND s.deleted_at IS NULL
    ) THEN false
    WHEN api.is_global_admin() THEN true
    WHEN EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = sid
        AND s.deleted_at IS NULL
        AND api.can_admin_project(s.project_id)
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'read') THEN false
    WHEN EXISTS (
      SELECT 1 FROM api.secret_access_requests r
      WHERE r.secret_id = sid
        AND r.user_id = api.current_user_id()
        AND r.status = 'approved'
        AND r.approved_until IS NOT NULL
        AND r.approved_until > now()
    ) THEN true
    WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
    WHEN NOT COALESCE(api.secret_requires_approval(sid), false) THEN true
    ELSE false
  END;
$$;

GRANT EXECUTE ON FUNCTION api.can_reveal_secret TO authenticated, anon;
-- ── Webhooks core schema
--    Tables for webhook definitions and the background delivery queue.

CREATE TABLE api.webhooks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    url text NOT NULL,
    secret_token text NOT NULL,
    events text[] NOT NULL DEFAULT '{}',
    scope_kind text NOT NULL CHECK (scope_kind IN ('cluster', 'team', 'project')),
    scope_id uuid, -- NULL for cluster
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- RLS: global admin or scope manager can see/edit
ALTER TABLE api.webhooks ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhooks_select ON api.webhooks FOR SELECT TO authenticated
  USING (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id));

CREATE POLICY webhooks_write ON api.webhooks FOR ALL TO authenticated
  USING (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id));

-- Delivery queue (internal)
CREATE TABLE private.webhook_delivery_queue (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id uuid NOT NULL REFERENCES api.webhooks(id) ON DELETE CASCADE,
    payload jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz
);

CREATE INDEX webhook_queue_retry_idx ON private.webhook_delivery_queue (next_retry_at, locked_until);

-- ── Logic: enqueue webhooks on audit
--    Check which webhooks match the current audit event's scope and event type.

CREATE OR REPLACE FUNCTION private.enqueue_webhooks(
    p_scope_kind text,
    p_scope_id uuid,
    p_event text,
    p_payload jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
DECLARE
    v_webhook_id uuid;
BEGIN
    FOR v_webhook_id IN
        SELECT id FROM api.webhooks
        WHERE active = true
          AND p_event = ANY(events)
          AND (
            (scope_kind = 'cluster')
            OR (scope_kind = 'team' AND scope_id = (
                CASE 
                    WHEN p_scope_kind = 'team' THEN p_scope_id
                    WHEN p_scope_kind = 'project' THEN (SELECT team_id FROM api.projects WHERE id = p_scope_id)
                END
            ))
            OR (scope_kind = 'project' AND p_scope_kind = 'project' AND scope_id = p_scope_id)
          )
    LOOP
        INSERT INTO private.webhook_delivery_queue (webhook_id, payload)
        VALUES (v_webhook_id, p_payload);
    END LOOP;
END;
$$;

-- Trigger enqueuing on secret audit
CREATE OR REPLACE FUNCTION private.tr_webhook_secret_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
BEGIN
    PERFORM private.enqueue_webhooks(
        'project',
        NEW.project_id,
        'secret.' || NEW.action,
        jsonb_build_object(
            'event', 'secret.' || NEW.action,
            'project_id', NEW.project_id,
            'secret_id', NEW.secret_id,
            'secret_key', NEW.secret_key,
            'actor_email', NEW.actor_email,
            'timestamp', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_webhook_secret_audit
AFTER INSERT ON api.secret_audit
FOR EACH ROW EXECUTE FUNCTION private.tr_webhook_secret_audit();

-- Trigger enqueuing on org audit
CREATE OR REPLACE FUNCTION private.tr_webhook_org_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
BEGIN
    PERFORM private.enqueue_webhooks(
        CASE WHEN NEW.project_id IS NOT NULL THEN 'project' ELSE 'team' END,
        COALESCE(NEW.project_id, NEW.team_id),
        'org.' || NEW.action,
        jsonb_build_object(
            'event', 'org.' || NEW.action,
            'team_id', NEW.team_id,
            'project_id', NEW.project_id,
            'action', NEW.action,
            'detail', NEW.detail,
            'actor_email', NEW.actor_email,
            'timestamp', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_webhook_org_audit
AFTER INSERT ON api.org_audit
FOR EACH ROW EXECUTE FUNCTION private.tr_webhook_org_audit();
-- ── Webhooks UX support
--    SSL-verification toggle on endpoints + a delivery log so operators can
--    debug receivers ("Recent deliveries" list). The queue stays in private;
--    the log is api.* so RLS can expose it to scope managers.

ALTER TABLE api.webhooks
  ADD COLUMN IF NOT EXISTS ssl_verify boolean NOT NULL DEFAULT true;

CREATE TABLE IF NOT EXISTS api.webhook_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id uuid NOT NULL REFERENCES api.webhooks(id) ON DELETE CASCADE,
  event text NOT NULL,
  ok boolean NOT NULL,
  status_code integer,
  error text NOT NULL DEFAULT '',
  duration_ms integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_recent_idx
  ON api.webhook_deliveries (webhook_id, created_at DESC);

ALTER TABLE api.webhook_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_deliveries_select ON api.webhook_deliveries FOR SELECT TO authenticated
  USING (
    api.is_global_admin()
    OR EXISTS (
      SELECT 1 FROM api.webhooks w
      WHERE w.id = webhook_id
        AND api.can_manage_rbac(w.scope_kind, w.scope_id)
    )
  );

GRANT SELECT ON api.webhook_deliveries TO authenticated;
-- api.webhooks was created by 0013 after 0001's blanket
-- "GRANT ... ON ALL TABLES IN SCHEMA api" ran, so authenticated had no table
-- privileges and every as_user() read failed with "permission denied".

GRANT SELECT, INSERT, UPDATE, DELETE ON api.webhooks TO authenticated;
-- Rewrite a leftover legacy brand name that 0006 missed.
-- 0006 handled 'Sigaint' / 'Sigaint Secret Server'; plain 'Secret Server'
-- slipped through and keeps rendering on every themed page (incl. errors).
-- 'Corvus' matches config.DEFAULT_SETTINGS["brand_name"].

UPDATE private.server_settings
   SET value = 'Corvus'
 WHERE key = 'brand_name'
   AND value = 'Secret Server';-- 0017: Team- and project-level metadata with precedence (team > project > secret).
-- Keys defined higher in the hierarchy cannot be overridden lower down.

CREATE TABLE IF NOT EXISTS api.team_meta (
    team_id    uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    value      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, key)
);

CREATE TABLE IF NOT EXISTS api.project_meta (
    project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    value      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, key)
);

-- Guard: reject writes of a key that already exists higher in the hierarchy.
CREATE OR REPLACE FUNCTION private.guard_meta_precedence() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private
AS $fn$
DECLARE
    v_team_id    uuid;
    v_project_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'team_meta' THEN
        RETURN NEW;
    ELSIF TG_TABLE_NAME = 'project_meta' THEN
        SELECT team_id INTO v_team_id FROM api.projects WHERE id = NEW.project_id;
        IF EXISTS (SELECT 1 FROM api.team_meta WHERE team_id = v_team_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at team level and cannot be overridden', NEW.key;
        END IF;
        RETURN NEW;
    ELSE  -- secret_meta
        SELECT project_id INTO v_project_id FROM api.secrets WHERE id = NEW.secret_id;
        SELECT team_id    INTO v_team_id    FROM api.projects WHERE id = v_project_id;
        IF EXISTS (SELECT 1 FROM api.team_meta WHERE team_id = v_team_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at team level and cannot be overridden', NEW.key;
        END IF;
        IF EXISTS (SELECT 1 FROM api.project_meta WHERE project_id = v_project_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at project level and cannot be overridden', NEW.key;
        END IF;
        RETURN NEW;
    END IF;
END;
$fn$;

DROP TRIGGER IF EXISTS team_meta_guard ON api.team_meta;
CREATE TRIGGER team_meta_guard BEFORE INSERT OR UPDATE ON api.team_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

DROP TRIGGER IF EXISTS project_meta_guard ON api.project_meta;
CREATE TRIGGER project_meta_guard BEFORE INSERT OR UPDATE ON api.project_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

DROP TRIGGER IF EXISTS secret_meta_guard ON api.secret_meta;
CREATE TRIGGER secret_meta_guard BEFORE INSERT OR UPDATE ON api.secret_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

-- RLS: read for anyone with visibility, write for admins only.
ALTER TABLE api.team_meta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS team_meta_select ON api.team_meta;
CREATE POLICY team_meta_select ON api.team_meta FOR SELECT TO authenticated
    USING (api.team_role(team_id) IS NOT NULL);
DROP POLICY IF EXISTS team_meta_admin ON api.team_meta;
CREATE POLICY team_meta_admin ON api.team_meta FOR ALL TO authenticated
    USING (api.team_role(team_id) IN ('team-owner', 'team-admin'))
    WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));

ALTER TABLE api.project_meta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_meta_select ON api.project_meta;
CREATE POLICY project_meta_select ON api.project_meta FOR SELECT TO authenticated
    USING (api.can_read_project(project_id));
DROP POLICY IF EXISTS project_meta_admin ON api.project_meta;
CREATE POLICY project_meta_admin ON api.project_meta FOR ALL TO authenticated
    USING (api.can_admin_project(project_id))
    WITH CHECK (api.can_admin_project(project_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_meta, api.project_meta TO authenticated;
GRANT EXECUTE ON FUNCTION private.guard_meta_precedence() TO authenticator, authenticated;

-- Merged read view for secrets: inherited metadata flows down.
-- Precedence on key collision: team > project > secret. Adds a source column.
-- CREATE OR REPLACE cannot change OUT/TABLE columns; drop the 0001 signature first.
DROP FUNCTION IF EXISTS private.secret_meta_rows(uuid);
CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)
RETURNS TABLE(key text, value text, updated_at timestamptz, source text)
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = api, private
AS $fn$
WITH scope AS (
    SELECT s.project_id AS project_id, p.team_id AS team_id
    FROM api.secrets s
    JOIN api.projects p ON p.id = s.project_id
    WHERE s.id = p_secret
),
own AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.secret_meta m
    WHERE m.secret_id = p_secret
),
pm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.project_meta m
    JOIN scope ON scope.project_id = m.project_id
),
tm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.team_meta m
    JOIN scope ON scope.team_id = m.team_id
),
merged AS (
    SELECT key, value, updated_at, 'team' AS source FROM tm
    UNION ALL
    SELECT key, value, updated_at, 'project' AS source FROM pm
    UNION ALL
    SELECT key, value, updated_at, 'secret' AS source FROM own
)
SELECT DISTINCT ON (key) key, value, updated_at, source
FROM merged
WHERE api.can_access_secret(p_secret, 'read')
ORDER BY key, source = 'secret', source = 'project'
$fn$;

GRANT EXECUTE ON FUNCTION private.secret_meta_rows TO authenticator, authenticated;
-- Add dedicated 'auditor' role for Defense-grade audit separation.
-- This role has 'get' and 'list' verbs on 'audit' resource at cluster/team scope.

DO $$
DECLARE
    rid uuid;
BEGIN
    -- auditor (cluster scope)
    INSERT INTO rbac.roles (name, description, built_in)
    VALUES ('auditor', 'Read-only access to audit logs across the organization', true)
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
    RETURNING id INTO rid;

    DELETE FROM rbac.role_rules WHERE role_id = rid;
    INSERT INTO rbac.role_rules (role_id, resources, verbs)
    VALUES (rid, ARRAY['audit'], ARRAY['get', 'list']);
END $$;
