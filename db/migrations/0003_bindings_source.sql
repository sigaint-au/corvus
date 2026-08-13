-- rbac.bindings.source column + source CHECK constraint.
--
-- bindings gained a ``source`` column (manual/ldap/oidc) so directory sync and
-- manual grants can coexist without clobbering each other. The CHECK is
-- re-bound idempotently so older volumes that already added the column without
-- the constraint get it.

ALTER TABLE rbac.bindings
  ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual';

DO $$ BEGIN
  ALTER TABLE rbac.bindings
    ADD CONSTRAINT bindings_source_check
    CHECK (source IN ('manual', 'ldap', 'oidc'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
