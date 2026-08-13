-- 0017_access_mode_cleanup
-- drop secret_acl, project default_access_mode

DROP FUNCTION IF EXISTS private.secret_acl_rows(uuid);

DROP TABLE IF EXISTS api.secret_acl CASCADE;

ALTER TABLE api.projects
          ADD COLUMN IF NOT EXISTS default_access_mode text NOT NULL DEFAULT 'inherit';

ALTER TABLE api.projects DROP COLUMN IF EXISTS default_acl_mode;

DO $$ BEGIN
          ALTER TABLE api.projects DROP CONSTRAINT IF EXISTS projects_default_access_mode_check;
        EXCEPTION WHEN others THEN NULL;
        END $$;

UPDATE api.projects SET default_access_mode = 'restricted'
         WHERE default_access_mode = 'custom';

UPDATE api.projects SET default_access_mode = 'inherit'
         WHERE default_access_mode NOT IN ('inherit', 'restricted');

DO $$ BEGIN
          ALTER TABLE api.projects
            ADD CONSTRAINT projects_default_access_mode_check
            CHECK (default_access_mode IN ('inherit', 'restricted'));
        EXCEPTION WHEN others THEN NULL;
        END $$;
