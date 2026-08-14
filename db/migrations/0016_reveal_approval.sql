-- 0016_reveal_approval
-- reveal approval columns, secret meta, access requests

ALTER TABLE api.projects
          ADD COLUMN IF NOT EXISTS require_reveal_approval boolean NOT NULL DEFAULT false;

ALTER TABLE api.projects
          ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';

ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS requires_approval boolean;

ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS last_accessed_at timestamptz;

ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS last_accessed_by uuid
            REFERENCES private.users(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS api.secret_meta (
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          key text NOT NULL
            CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
          value text NOT NULL DEFAULT '',
          updated_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (secret_id, key)
        );

CREATE INDEX IF NOT EXISTS secret_meta_key_idx ON api.secret_meta (key);

CREATE INDEX IF NOT EXISTS secret_meta_value_idx ON api.secret_meta (value);

ALTER TABLE api.secret_meta ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secret_meta_select ON api.secret_meta;

CREATE POLICY secret_meta_select ON api.secret_meta FOR SELECT TO authenticated
          USING (api.can_access_secret(secret_id, 'read'));

DROP POLICY IF EXISTS secret_meta_insert ON api.secret_meta;

CREATE POLICY secret_meta_insert ON api.secret_meta FOR INSERT TO authenticated
          WITH CHECK (api.can_access_secret(secret_id, 'write'));

DROP POLICY IF EXISTS secret_meta_update ON api.secret_meta;

CREATE POLICY secret_meta_update ON api.secret_meta FOR UPDATE TO authenticated
          USING (api.can_access_secret(secret_id, 'write'));

DROP POLICY IF EXISTS secret_meta_delete ON api.secret_meta;

CREATE POLICY secret_meta_delete ON api.secret_meta FOR DELETE TO authenticated
          USING (api.can_access_secret(secret_id, 'write'));

GRANT SELECT, INSERT, UPDATE, DELETE ON api.secret_meta TO authenticated;

GRANT ALL ON api.secret_meta TO authenticator;

CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)
        RETURNS TABLE (key text, value text, updated_at timestamptz)
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
        BEGIN
          RETURN QUERY
          SELECT m.key, m.value, m.updated_at
          FROM api.secret_meta m
          WHERE m.secret_id = p_secret
            AND api.can_access_secret(p_secret, 'read')
          ORDER BY m.key;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.touch_secret_access(p_secret uuid)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
        BEGIN
          IF p_secret IS NULL OR api.current_user_id() IS NULL THEN
            RETURN;
          END IF;
          IF NOT api.can_access_secret(p_secret, 'reveal') THEN
            RETURN;
          END IF;
          UPDATE api.secrets
             SET last_accessed_at = now(),
                 last_accessed_by = api.current_user_id()
           WHERE id = p_secret AND deleted_at IS NULL;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.secret_meta_rows TO authenticator, authenticated;

GRANT EXECUTE ON FUNCTION private.touch_secret_access TO authenticator, authenticated;

CREATE TABLE IF NOT EXISTS api.secret_access_requests (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          status text NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'approved', 'denied')),
          reason text NOT NULL DEFAULT '',
          created_at timestamptz NOT NULL DEFAULT now(),
          resolved_at timestamptz,
          resolved_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
          approved_until timestamptz
        );

CREATE UNIQUE INDEX IF NOT EXISTS secret_access_requests_pending_uidx
          ON api.secret_access_requests (secret_id, user_id)
          WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS secret_access_requests_project_status_idx
          ON api.secret_access_requests (project_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS secret_access_requests_grant_idx
          ON api.secret_access_requests (secret_id, user_id, approved_until)
          WHERE status = 'approved';

ALTER TABLE api.secret_access_requests ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secret_access_requests_select ON api.secret_access_requests;

CREATE POLICY secret_access_requests_select ON api.secret_access_requests
          FOR SELECT TO authenticated
          USING (
            api.can_admin_project(project_id)
            OR user_id = api.current_user_id()
          );

DROP POLICY IF EXISTS secret_access_requests_insert ON api.secret_access_requests;

CREATE POLICY secret_access_requests_insert ON api.secret_access_requests
          FOR INSERT TO authenticated
          WITH CHECK (
            user_id = api.current_user_id()
            AND api.can_read_project(project_id)
          );

DROP POLICY IF EXISTS secret_access_requests_update ON api.secret_access_requests;

CREATE POLICY secret_access_requests_update ON api.secret_access_requests
          FOR UPDATE TO authenticated
          USING (api.can_admin_project(project_id));

GRANT SELECT, INSERT, UPDATE ON api.secret_access_requests TO authenticated;

GRANT ALL ON api.secret_access_requests TO authenticator;

-- Effective policy: secret.requires_approval overrides project default;
        -- NULL inherits project.require_reveal_approval (default false).
        CREATE OR REPLACE FUNCTION api.secret_requires_approval(sid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT CASE
            WHEN s.requires_approval IS TRUE THEN true
            WHEN s.requires_approval IS FALSE THEN false
            ELSE COALESCE(p.require_reveal_approval, false)
          END
          FROM api.secrets s
          JOIN api.projects p ON p.id = s.project_id
          WHERE s.id = sid AND s.deleted_at IS NULL;
        $$;

GRANT EXECUTE ON FUNCTION api.secret_requires_approval TO authenticated, anon;

CREATE OR REPLACE FUNCTION api.can_reveal_secret(sid uuid) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
          SELECT CASE
            WHEN sid IS NULL THEN false
            WHEN NOT api.can_access_secret(sid, 'reveal') THEN false
            WHEN api.is_global_admin() THEN true
            WHEN EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = sid AND api.can_admin_project(s.project_id)
            ) THEN true
            WHEN NOT COALESCE(api.secret_requires_approval(sid), false) THEN true
            WHEN EXISTS (
              SELECT 1 FROM api.secret_access_requests r
              WHERE r.secret_id = sid
                AND r.user_id = api.current_user_id()
                AND r.status = 'approved'
                AND r.approved_until IS NOT NULL
                AND r.approved_until > now()
            ) THEN true
            ELSE false
          END;
        $$;

GRANT EXECUTE ON FUNCTION api.can_reveal_secret TO authenticated, anon;

CREATE OR REPLACE FUNCTION private.secret_access_request_rows(p_project uuid)
        RETURNS TABLE (
          id uuid,
          secret_id uuid,
          secret_key text,
          user_id uuid,
          email text,
          name text,
          status text,
          reason text,
          created_at timestamptz,
          resolved_at timestamptz,
          approved_until timestamptz,
          resolver_email text
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
        BEGIN
          RETURN QUERY
          SELECT r.id, r.secret_id, COALESCE(s.key, ''), r.user_id,
                 u.email, u.name, r.status, r.reason, r.created_at,
                 r.resolved_at, r.approved_until,
                 COALESCE(ru.email, '')
          FROM api.secret_access_requests r
          JOIN private.users u ON u.id = r.user_id
          LEFT JOIN api.secrets s ON s.id = r.secret_id
          LEFT JOIN private.users ru ON ru.id = r.resolved_by
          WHERE r.project_id = p_project
            AND (
              api.can_admin_project(p_project)
              OR r.user_id = api.current_user_id()
            )
          ORDER BY
            CASE r.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
            r.created_at DESC
          LIMIT 200;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.secret_access_request_rows TO authenticator, authenticated;

CREATE OR REPLACE FUNCTION private.pending_access_requests_for_admin()
        RETURNS TABLE (
          id uuid,
          project_id uuid,
          project_name text,
          secret_id uuid,
          secret_key text,
          user_id uuid,
          email text,
          name text,
          reason text,
          created_at timestamptz
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = api, private
        SET row_security = off AS $$
        BEGIN
          RETURN QUERY
          SELECT r.id, r.project_id, p.name, r.secret_id, COALESCE(s.key, ''),
                 r.user_id, u.email, u.name, r.reason, r.created_at
          FROM api.secret_access_requests r
          JOIN api.projects p ON p.id = r.project_id
          JOIN private.users u ON u.id = r.user_id
          LEFT JOIN api.secrets s ON s.id = r.secret_id
          WHERE r.status = 'pending'
            AND api.can_admin_project(r.project_id)
          ORDER BY r.created_at ASC
          LIMIT 100;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.pending_access_requests_for_admin TO authenticator, authenticated;
