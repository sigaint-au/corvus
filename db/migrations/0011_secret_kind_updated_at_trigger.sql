-- 0011_secret_kind_updated_at_trigger
-- secret kind column, updated_at trigger

CREATE OR REPLACE FUNCTION api.touch_updated_at()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          NEW.updated_at := now();
          RETURN NEW;
        END;
        $$;

DROP TRIGGER IF EXISTS secrets_touch_updated_at ON api.secrets;

CREATE TRIGGER secrets_touch_updated_at
          BEFORE UPDATE ON api.secrets
          FOR EACH ROW EXECUTE FUNCTION api.touch_updated_at();

ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'plain';

DO $$ BEGIN
          ALTER TABLE api.secrets DROP CONSTRAINT IF EXISTS secrets_kind_check;
          ALTER TABLE api.secrets
            ADD CONSTRAINT secrets_kind_check
            CHECK (kind IN ('plain', 'database', 'certificate', 'ssh', 'kv'));
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
