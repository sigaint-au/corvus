-- 0014_favorites_recent
-- secret pins + recent

CREATE TABLE IF NOT EXISTS api.secret_pins (
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          created_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (user_id, secret_id)
        );

CREATE TABLE IF NOT EXISTS api.secret_recent (
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          accessed_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (user_id, secret_id)
        );

CREATE INDEX IF NOT EXISTS secret_recent_user_accessed_idx
          ON api.secret_recent (user_id, accessed_at DESC);

ALTER TABLE api.secret_pins ENABLE ROW LEVEL SECURITY;

ALTER TABLE api.secret_recent ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secret_pins_select ON api.secret_pins;

CREATE POLICY secret_pins_select ON api.secret_pins FOR SELECT TO authenticated
          USING (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          );

DROP POLICY IF EXISTS secret_pins_insert ON api.secret_pins;

CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
          WITH CHECK (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          );

DROP POLICY IF EXISTS secret_pins_delete ON api.secret_pins;

CREATE POLICY secret_pins_delete ON api.secret_pins FOR DELETE TO authenticated
          USING (user_id = api.current_user_id());

DROP POLICY IF EXISTS secret_recent_select ON api.secret_recent;

CREATE POLICY secret_recent_select ON api.secret_recent FOR SELECT TO authenticated
          USING (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          );

DROP POLICY IF EXISTS secret_recent_insert ON api.secret_recent;

CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
          WITH CHECK (
            user_id = api.current_user_id()
            AND EXISTS (
              SELECT 1 FROM api.secrets s
              WHERE s.id = secret_id AND s.deleted_at IS NULL
                AND api.can_read_project(s.project_id)
            )
          );

DROP POLICY IF EXISTS secret_recent_update ON api.secret_recent;

CREATE POLICY secret_recent_update ON api.secret_recent FOR UPDATE TO authenticated
          USING (user_id = api.current_user_id());

DROP POLICY IF EXISTS secret_recent_delete ON api.secret_recent;

CREATE POLICY secret_recent_delete ON api.secret_recent FOR DELETE TO authenticated
          USING (user_id = api.current_user_id());

GRANT SELECT, INSERT, DELETE ON api.secret_pins TO authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON api.secret_recent TO authenticated;

GRANT ALL ON api.secret_pins TO authenticator;

GRANT ALL ON api.secret_recent TO authenticator;
