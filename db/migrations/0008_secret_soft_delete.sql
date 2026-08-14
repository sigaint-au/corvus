-- 0008_secret_soft_delete
-- secret soft-delete, unique live index, machine read helpers

ALTER TABLE api.secrets
          ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

DO $$ BEGIN
          ALTER TABLE api.secrets DROP CONSTRAINT IF EXISTS secrets_project_id_key_key;
        EXCEPTION WHEN undefined_object THEN NULL;
        END $$;

CREATE UNIQUE INDEX IF NOT EXISTS secrets_project_key_live
          ON api.secrets (project_id, key) WHERE deleted_at IS NULL;

CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
        RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN NULL;
          END IF;
          RETURN (
            SELECT value_enc FROM api.secrets
            WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
          );
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
        RETURNS TABLE (
          id uuid,
          key text,
          value_enc text,
          note text,
          kind text,
          expires_at timestamptz,
          created_at timestamptz,
          updated_at timestamptz
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at, s.created_at, s.updated_at
            FROM api.secrets s
            WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.machine_get_row TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
        RETURNS TABLE (key text, value_enc text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.key, s.value_enc FROM api.secrets s
            WHERE s.project_id = p_project AND s.deleted_at IS NULL;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_list_meta(
          p_project uuid, p_hash text, p_q text DEFAULT NULL
        )
        RETURNS TABLE (
          id uuid,
          key text,
          note text,
          kind text,
          expires_at timestamptz,
          created_at timestamptz,
          updated_at timestamptz
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = api AS $$
        DECLARE q text := NULLIF(btrim(COALESCE(p_q, '')), '');
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.note, s.kind, s.expires_at, s.created_at, s.updated_at
            FROM api.secrets s
            WHERE s.project_id = p_project
              AND s.deleted_at IS NULL
              AND (
                q IS NULL
                OR s.key ILIKE ('%' || q || '%')
                OR s.note ILIKE ('%' || q || '%')
              )
            ORDER BY s.key;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.machine_list_meta TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_delete(
          p_project uuid, p_hash text, p_key text
        )
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = api AS $$
        DECLARE sid uuid;
        BEGIN
          IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
            RETURN NULL;
          END IF;
          IF p_key IS NULL OR btrim(p_key) = '' THEN
            RETURN NULL;
          END IF;
          UPDATE api.secrets
          SET deleted_at = now()
          WHERE project_id = p_project
            AND key = p_key
            AND deleted_at IS NULL
          RETURNING id INTO sid;
          RETURN sid;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.machine_delete TO authenticator;
