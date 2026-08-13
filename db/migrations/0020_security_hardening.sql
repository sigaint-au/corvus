-- 0020_security_hardening
-- FORCE RLS, hardened search_path, policy hardening

DROP POLICY IF EXISTS projects_update ON api.projects;

CREATE POLICY projects_update ON api.projects FOR UPDATE TO authenticated
          USING (api.can_admin_project(id));

REVOKE INSERT, UPDATE, DELETE ON api.secret_versions FROM authenticated;

REVOKE ALL ON api.user_directory FROM anon;

ALTER TABLE api.teams FORCE ROW LEVEL SECURITY;

ALTER TABLE api.projects FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secrets FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secret_versions FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secret_meta FORCE ROW LEVEL SECURITY;

ALTER TABLE api.secret_access_requests FORCE ROW LEVEL SECURITY;

ALTER TABLE api.machine_tokens FORCE ROW LEVEL SECURITY;

ALTER TABLE api.groups FORCE ROW LEVEL SECURITY;

ALTER TABLE api.group_members FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION private.lookup_user(p_email text)
        RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, private
        SET row_security = off AS $$
          SELECT id FROM private.users WHERE email = lower(p_email) LIMIT 1;
        $$;

REVOKE EXECUTE ON FUNCTION private.lookup_user FROM PUBLIC;
