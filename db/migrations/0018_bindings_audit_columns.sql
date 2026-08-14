-- 0018_bindings_audit_columns
-- rbac.bindings updated_at/updated_by + unique index

ALTER TABLE rbac.bindings
          ADD COLUMN IF NOT EXISTS updated_at timestamptz;

ALTER TABLE rbac.bindings
          ADD COLUMN IF NOT EXISTS updated_by uuid;

CREATE UNIQUE INDEX IF NOT EXISTS bindings_unique_idx
          ON rbac.bindings(role_id, subject_kind, subject_id, scope_kind,
                           COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- _perm_rank removed: rbac.sql provides RBAC-based authorization;
