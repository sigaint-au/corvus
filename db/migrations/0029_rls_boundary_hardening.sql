-- RLS and privilege-boundary hardening.
--
-- 0028 revoked selected functions from named roles, but PostgreSQL grants
-- EXECUTE on newly-created functions to PUBLIC by default. Remove that
-- implicit surface before applying the narrower grants below.

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rbac FROM PUBLIC;

-- The only rbac-schema function intentionally callable by the application
-- connection is the startup role seeder.
GRANT EXECUTE ON FUNCTION rbac.ensure_builtin_roles() TO authenticator;

REVOKE EXECUTE ON FUNCTION api.hsm_slot_url(uuid)
  FROM PUBLIC, anon, authenticated, authenticator;
REVOKE EXECUTE ON FUNCTION api.list_hsm_slots()
  FROM PUBLIC, anon;

-- Do not expose token verifiers through the PostgREST table. The application
-- already selects the metadata columns explicitly; token_hash remains usable
-- by privileged server-side code.
REVOKE SELECT ON api.machine_tokens FROM authenticated;
GRANT SELECT (
  id, project_id, name, token_prefix, role, expires_at, created_at, last_used_at
) ON api.machine_tokens TO authenticated;

-- All API tables must apply RLS even when queried by their table owner. The
-- database superuser still bypasses RLS by design; user-scoped application
-- paths must use db.as_user rather than db.connect_admin.
ALTER TABLE api.team_ldap_maps FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_oidc_maps FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_invites FORCE ROW LEVEL SECURITY;
ALTER TABLE api.team_join_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_pins FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_recent FORCE ROW LEVEL SECURITY;
ALTER TABLE api.org_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE api.secret_audit FORCE ROW LEVEL SECURITY;

-- Access requests must always point at a secret in the same project, and the
-- request identity/target cannot be rewritten after creation.
CREATE OR REPLACE FUNCTION api.guard_secret_access_request()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM api.secrets s
    WHERE s.id = NEW.secret_id
      AND s.project_id = NEW.project_id
  ) THEN
    RAISE EXCEPTION 'secret does not belong to request project';
  END IF;

  IF TG_OP = 'INSERT'
     AND (NEW.status <> 'pending'
          OR NEW.resolved_at IS NOT NULL
          OR NEW.resolved_by IS NOT NULL
          OR NEW.approved_until IS NOT NULL) THEN
    RAISE EXCEPTION 'new access requests must be pending and unresolved';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'access request identity fields cannot be changed';
    END IF;
    IF OLD.status <> 'pending' AND NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'resolved access requests cannot change status';
    END IF;
    IF NEW.status = 'pending'
       AND (NEW.resolved_at IS NOT NULL
            OR NEW.resolved_by IS NOT NULL
            OR NEW.approved_until IS NOT NULL) THEN
      RAISE EXCEPTION 'pending access requests cannot have resolution fields';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_secret_access_request
  ON api.secret_access_requests;
CREATE TRIGGER guard_secret_access_request
BEFORE INSERT OR UPDATE ON api.secret_access_requests
FOR EACH ROW EXECUTE FUNCTION api.guard_secret_access_request();

DROP POLICY IF EXISTS secret_access_requests_insert
  ON api.secret_access_requests;
CREATE POLICY secret_access_requests_insert ON api.secret_access_requests
FOR INSERT TO authenticated
WITH CHECK (
  user_id = api.current_user_id()
  AND api.can_read_project(project_id)
  AND EXISTS (
    SELECT 1 FROM api.secrets s
    WHERE s.id = secret_id
      AND s.project_id = project_id
      AND s.deleted_at IS NULL
  )
);

DROP POLICY IF EXISTS secret_access_requests_update
  ON api.secret_access_requests;
CREATE POLICY secret_access_requests_update ON api.secret_access_requests
FOR UPDATE TO authenticated
USING (api.can_admin_project(project_id))
WITH CHECK (api.can_admin_project(project_id));

-- Enforce the role/scope contract at the database boundary. The UI performs
-- the same validation, but PostgREST writes must not be able to bypass it.
CREATE OR REPLACE FUNCTION rbac.validate_binding_scope()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rbac, pg_catalog
SET row_security = off AS $$
DECLARE role_name text;
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
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS validate_binding_scope ON rbac.bindings;
CREATE TRIGGER validate_binding_scope
BEFORE INSERT OR UPDATE ON rbac.bindings
FOR EACH ROW EXECUTE FUNCTION rbac.validate_binding_scope();
