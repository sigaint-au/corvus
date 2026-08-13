-- 0013_team_settings_invites_orgaudit
-- team settings, invites, join requests, org audit

ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS default_token_days int;

DO $$ BEGIN
          ALTER TABLE api.teams DROP CONSTRAINT IF EXISTS teams_default_token_days_check;
        EXCEPTION WHEN undefined_object THEN NULL;
        END $$;

ALTER TABLE api.teams
          ADD CONSTRAINT teams_default_token_days_check
          CHECK (
            default_token_days IS NULL
            OR (default_token_days > 0 AND default_token_days <= 3650)
          );

ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_enabled boolean;

ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_text text NOT NULL DEFAULT '';

ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_color text NOT NULL DEFAULT '';

ALTER TABLE api.teams
          ADD COLUMN IF NOT EXISTS classification_fg text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS api.team_invites (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          token_hash text NOT NULL UNIQUE,
          role text NOT NULL DEFAULT 'team-member'
            CHECK (role IN ('team-admin', 'team-member', 'team-viewer')),
          expires_at timestamptz NOT NULL,
          created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          revoked_at timestamptz
        );

CREATE INDEX IF NOT EXISTS team_invites_team_idx
          ON api.team_invites (team_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS api.team_join_requests (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
          invite_id uuid REFERENCES api.team_invites(id) ON DELETE SET NULL,
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          role text NOT NULL DEFAULT 'team-member'
            CHECK (role IN ('team-admin', 'team-member', 'team-viewer')),
          status text NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'approved', 'rejected')),
          created_at timestamptz NOT NULL DEFAULT now(),
          resolved_at timestamptz,
          resolved_by uuid REFERENCES private.users(id) ON DELETE SET NULL
        );

CREATE UNIQUE INDEX IF NOT EXISTS team_join_requests_pending_uidx
          ON api.team_join_requests (team_id, user_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS api.org_audit (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          team_id uuid REFERENCES api.teams(id) ON DELETE CASCADE,
          project_id uuid REFERENCES api.projects(id) ON DELETE CASCADE,
          action text NOT NULL,
          detail text NOT NULL DEFAULT '',
          user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
          actor_email text NOT NULL DEFAULT '',
          created_at timestamptz NOT NULL DEFAULT now()
        );

CREATE INDEX IF NOT EXISTS org_audit_team_created_idx
          ON api.org_audit (team_id, created_at DESC);

CREATE INDEX IF NOT EXISTS org_audit_project_created_idx
          ON api.org_audit (project_id, created_at DESC);

ALTER TABLE api.team_invites ENABLE ROW LEVEL SECURITY;

ALTER TABLE api.team_join_requests ENABLE ROW LEVEL SECURITY;

ALTER TABLE api.org_audit ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS team_invites_select ON api.team_invites;

CREATE POLICY team_invites_select ON api.team_invites FOR SELECT TO authenticated
          USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

DROP POLICY IF EXISTS team_invites_insert ON api.team_invites;

CREATE POLICY team_invites_insert ON api.team_invites FOR INSERT TO authenticated
          WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));

DROP POLICY IF EXISTS team_invites_update ON api.team_invites;

CREATE POLICY team_invites_update ON api.team_invites FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

DROP POLICY IF EXISTS team_invites_delete ON api.team_invites;

CREATE POLICY team_invites_delete ON api.team_invites FOR DELETE TO authenticated
          USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

DROP POLICY IF EXISTS team_join_requests_select ON api.team_join_requests;

CREATE POLICY team_join_requests_select ON api.team_join_requests FOR SELECT TO authenticated
          USING (
            api.team_role(team_id) IN ('team-owner', 'team-admin')
            OR user_id = api.current_user_id()
          );

DROP POLICY IF EXISTS team_join_requests_insert ON api.team_join_requests;

CREATE POLICY team_join_requests_insert ON api.team_join_requests FOR INSERT TO authenticated
          WITH CHECK (user_id = api.current_user_id());

DROP POLICY IF EXISTS team_join_requests_update ON api.team_join_requests;

CREATE POLICY team_join_requests_update ON api.team_join_requests FOR UPDATE TO authenticated
          USING (api.team_role(team_id) IN ('team-owner', 'team-admin'));

DROP POLICY IF EXISTS org_audit_select ON api.org_audit;

CREATE POLICY org_audit_select ON api.org_audit FOR SELECT TO authenticated
          USING (
            (team_id IS NOT NULL AND api.is_team_member(team_id))
            OR (project_id IS NOT NULL AND api.can_read_project(project_id))
          );

REVOKE INSERT ON api.org_audit FROM authenticated;

GRANT SELECT ON api.org_audit TO authenticated;

GRANT ALL ON api.org_audit TO authenticator;

GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_invites TO authenticated;

GRANT SELECT, INSERT, UPDATE ON api.team_join_requests TO authenticated;

GRANT ALL ON api.team_invites TO authenticator;

GRANT ALL ON api.team_join_requests TO authenticator;

CREATE OR REPLACE FUNCTION private.audit_org(
          p_team uuid,
          p_project uuid,
          p_action text,
          p_detail text DEFAULT '',
          p_actor_email text DEFAULT NULL
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private AS $$
        DECLARE
          uid uuid;
          email text;
        BEGIN
          IF p_action IS NULL OR btrim(p_action) = '' THEN
            RAISE EXCEPTION 'invalid org audit action';
          END IF;
          BEGIN
            uid := NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
          EXCEPTION WHEN others THEN
            uid := NULL;
          END;
          email := COALESCE(
            (SELECT u.email FROM private.users u WHERE u.id = uid),
            NULLIF(p_actor_email, ''),
            ''
          );
          INSERT INTO api.org_audit (team_id, project_id, action, detail, user_id, actor_email)
          VALUES (p_team, p_project, p_action, COALESCE(p_detail, ''), uid, email);
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.audit_org TO authenticator, authenticated;

CREATE OR REPLACE FUNCTION private.lookup_invite(p_hash text)
        RETURNS TABLE (
          invite_id uuid, team_id uuid, team_name text, role text, expires_at timestamptz
        )
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT i.id, i.team_id, t.name, i.role, i.expires_at
          FROM api.team_invites i
          JOIN api.teams t ON t.id = i.team_id
          WHERE i.token_hash = p_hash
            AND i.revoked_at IS NULL
            AND i.expires_at > now()
          LIMIT 1;
        $$;

GRANT EXECUTE ON FUNCTION private.lookup_invite TO authenticator, authenticated;
