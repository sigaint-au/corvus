-- 0023_shared_recent_pins
-- Pins and recently-accessed rows must allow secret-scope grantees, not only
-- project members. Viewing a shared secret used to fail RLS on secret_recent
-- INSERT and abort the rest of the view transaction.

DROP POLICY IF EXISTS secret_pins_select ON api.secret_pins;
CREATE POLICY secret_pins_select ON api.secret_pins FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS secret_pins_insert ON api.secret_pins;
CREATE POLICY secret_pins_insert ON api.secret_pins FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS secret_recent_select ON api.secret_recent;
CREATE POLICY secret_recent_select ON api.secret_recent FOR SELECT TO authenticated
  USING (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );

DROP POLICY IF EXISTS secret_recent_insert ON api.secret_recent;
CREATE POLICY secret_recent_insert ON api.secret_recent FOR INSERT TO authenticated
  WITH CHECK (
    user_id = api.current_user_id()
    AND EXISTS (
      SELECT 1 FROM api.secrets s
      WHERE s.id = secret_id AND s.deleted_at IS NULL
        AND api.can_access_secret_row(
          s.id, s.project_id, s.access_mode, 'read', NULL
        )
    )
  );
