-- 0009_secret_audit
-- secret audit table + audit_secret function

CREATE TABLE IF NOT EXISTS api.secret_audit (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
          secret_id uuid,
          secret_key text NOT NULL DEFAULT '',
          user_id uuid REFERENCES private.users(id) ON DELETE SET NULL,
          actor_email text NOT NULL DEFAULT '',
          action text NOT NULL DEFAULT 'created',
          created_at timestamptz NOT NULL DEFAULT now()
        );

DO $$ BEGIN
          ALTER TABLE api.secret_audit DROP CONSTRAINT IF EXISTS secret_audit_action_check;
          ALTER TABLE api.secret_audit
            ADD CONSTRAINT secret_audit_action_check
            CHECK (action IN (
              'created', 'updated', 'revealed', 'deleted', 'restored', 'purged',
              'machine_upsert', 'exported',
              'access_requested', 'access_approved', 'access_denied'
            ));
        EXCEPTION WHEN others THEN NULL;
        END $$;

CREATE INDEX IF NOT EXISTS secret_audit_project_created_idx
          ON api.secret_audit (project_id, created_at DESC);

ALTER TABLE api.secret_audit ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secret_audit_select ON api.secret_audit;

CREATE POLICY secret_audit_select ON api.secret_audit FOR SELECT TO authenticated
          USING (api.can_read_project(project_id));

DROP POLICY IF EXISTS secret_audit_insert ON api.secret_audit;

REVOKE INSERT ON api.secret_audit FROM authenticated;

GRANT SELECT ON api.secret_audit TO authenticated;

GRANT ALL ON api.secret_audit TO authenticator;

CREATE OR REPLACE FUNCTION private.audit_secret(
          p_project uuid,
          p_secret_id uuid,
          p_secret_key text,
          p_action text,
          p_user_id uuid DEFAULT NULL,
          p_actor_email text DEFAULT NULL
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private AS $$
        DECLARE
          uid uuid;
          email text;
        BEGIN
          IF p_action NOT IN (
            'created', 'updated', 'revealed', 'deleted', 'restored', 'purged',
            'machine_upsert', 'exported',
            'access_requested', 'access_approved', 'access_denied'
          ) THEN
            RAISE EXCEPTION 'invalid audit action: %', p_action;
          END IF;
          -- Never trust caller-supplied p_user_id; always derive from JWT
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
          INSERT INTO api.secret_audit
            (project_id, secret_id, secret_key, user_id, actor_email, action)
          VALUES (p_project, p_secret_id, COALESCE(p_secret_key, ''), uid, email, p_action);
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.audit_secret TO authenticator, authenticated;
