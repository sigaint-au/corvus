-- 0012_secret_versioning
-- secret expires_at, secret_versions archive

ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS expires_at timestamptz;

CREATE TABLE IF NOT EXISTS api.secret_versions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          secret_id uuid NOT NULL REFERENCES api.secrets(id) ON DELETE CASCADE,
          value_enc text NOT NULL,
          note text NOT NULL DEFAULT '',
          created_at timestamptz NOT NULL DEFAULT now()
        );

CREATE INDEX IF NOT EXISTS secret_versions_secret_created_idx
          ON api.secret_versions (secret_id, created_at DESC);

CREATE OR REPLACE FUNCTION api.archive_secret_version()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, api, private
        SET row_security = off AS $$
        BEGIN
          IF OLD.value_enc IS DISTINCT FROM NEW.value_enc THEN
            INSERT INTO api.secret_versions (secret_id, value_enc, note)
            VALUES (OLD.id, OLD.value_enc, OLD.note);
          END IF;
          RETURN NEW;
        END;
        $$;

DROP TRIGGER IF EXISTS secrets_archive_version ON api.secrets;

CREATE TRIGGER secrets_archive_version
          BEFORE UPDATE ON api.secrets
          FOR EACH ROW EXECUTE FUNCTION api.archive_secret_version();

ALTER TABLE api.secret_versions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secret_versions_insert ON api.secret_versions;

REVOKE INSERT ON api.secret_versions FROM authenticated;

GRANT SELECT ON api.secret_versions TO authenticated;

GRANT ALL ON api.secret_versions TO authenticator;
