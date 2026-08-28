-- Add dedicated 'auditor' role for Defense-grade audit separation.
-- This role has 'get' and 'list' verbs on 'audit' resource at cluster/team scope.

DO $$
DECLARE
    rid uuid;
BEGIN
    -- auditor (cluster scope)
    INSERT INTO rbac.roles (name, description, built_in)
    VALUES ('auditor', 'Read-only access to audit logs across the organization', true)
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, built_in = true
    RETURNING id INTO rid;

    DELETE FROM rbac.role_rules WHERE role_id = rid;
    INSERT INTO rbac.role_rules (role_id, resources, verbs)
    VALUES (rid, ARRAY['audit'], ARRAY['get', 'list']);
END $$;
