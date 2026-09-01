-- SECURITY DEFINER wrapper for folder path materialization.
--
-- Folder upsert is a side effect of secret creation, not a user-facing action.
-- The RLS policy on api.folders (folders_insert checks can_write_project) is
-- redundant with secrets_insert (same check) but triggers first in the code
-- path, causing an InsufficientPrivilege error for users who hold project write
-- through ancestor scope bindings. Running the INSERT here bypasses RLS so that
-- the single authorizing check on api.secrets controls write access.

CREATE OR REPLACE FUNCTION private.materialize_folder_path(
    p_project_id uuid,
    p_parent_id uuid,
    p_name text,
    p_path text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog
SET row_security = off AS $$
DECLARE v_id uuid;
BEGIN
    INSERT INTO api.folders (project_id, parent_id, name, path)
    VALUES (p_project_id, p_parent_id, p_name, p_path)
    ON CONFLICT (project_id, path) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION private.materialize_folder_path TO authenticator, authenticated;