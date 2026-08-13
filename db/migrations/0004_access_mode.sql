-- api.secrets.access_mode data migration: scrub legacy values, enforce tight CHECK.
--
-- Legacy access modes (``custom`` and min-role modes like ``write``/``admin``)
-- were collapsed to ``inherit`` / ``restricted``. This is a *data* migration
-- (not just DDL): it must run exactly once, in order, before the tight CHECK
-- is re-added, so existing rows survive the constraint.

-- Add the column on older volumes that predate it (no-op on current baseline).
ALTER TABLE api.secrets
  ADD COLUMN IF NOT EXISTS access_mode text NOT NULL DEFAULT 'inherit';

-- Drop any existing access_mode CHECK (from earlier builds) before scrubbing.
DO $$
DECLARE c record;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'api.secrets'::regclass
      AND pg_get_constraintdef(oid) ILIKE '%access_mode%'
  LOOP
    EXECUTE format('ALTER TABLE api.secrets DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$
;

-- custom was exclusive (secret-scope only) → restricted;
-- writers/admins/owners were min-role modes → inherit.
UPDATE api.secrets SET access_mode = 'restricted'
 WHERE access_mode = 'custom';

UPDATE api.secrets SET access_mode = 'inherit'
 WHERE access_mode NOT IN ('inherit', 'restricted');

-- Drop the renamed/legacy column if present from older builds.
ALTER TABLE api.secrets DROP COLUMN IF EXISTS acl_mode;

DO $$ BEGIN
  ALTER TABLE api.secrets
    ADD CONSTRAINT secrets_access_mode_check
    CHECK (access_mode IN ('inherit', 'restricted'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
