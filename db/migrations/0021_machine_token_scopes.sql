-- 0021_machine_token_scopes
-- machine token key scopes + scope-aware machine helpers

CREATE TABLE IF NOT EXISTS api.machine_token_scope (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          token_id uuid NOT NULL REFERENCES api.machine_tokens(id) ON DELETE CASCADE,
          secret_key text,
          key_pattern text,
          created_at timestamptz NOT NULL DEFAULT now(),
          CHECK (
            (
              secret_key IS NOT NULL AND btrim(secret_key) <> '' AND key_pattern IS NULL
            ) OR (
              key_pattern IS NOT NULL AND btrim(key_pattern) <> '' AND secret_key IS NULL
            )
          )
        );

CREATE UNIQUE INDEX IF NOT EXISTS machine_token_scope_exact_uidx
          ON api.machine_token_scope (token_id, secret_key) WHERE secret_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS machine_token_scope_pattern_uidx
          ON api.machine_token_scope (token_id, key_pattern) WHERE key_pattern IS NOT NULL;

CREATE INDEX IF NOT EXISTS machine_token_scope_token_idx
          ON api.machine_token_scope (token_id);

ALTER TABLE api.machine_token_scope ENABLE ROW LEVEL SECURITY;

ALTER TABLE api.machine_token_scope FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mts_select ON api.machine_token_scope;

CREATE POLICY mts_select ON api.machine_token_scope FOR SELECT TO authenticated
          USING (
            EXISTS (
              SELECT 1 FROM api.machine_tokens t
              WHERE t.id = token_id AND api.can_read_project(t.project_id)
            )
          );

DROP POLICY IF EXISTS mts_insert ON api.machine_token_scope;

CREATE POLICY mts_insert ON api.machine_token_scope FOR INSERT TO authenticated
          WITH CHECK (
            EXISTS (
              SELECT 1 FROM api.machine_tokens t
              WHERE t.id = token_id AND api.can_write_project(t.project_id)
            )
          );

DROP POLICY IF EXISTS mts_delete ON api.machine_token_scope;

CREATE POLICY mts_delete ON api.machine_token_scope FOR DELETE TO authenticated
          USING (
            EXISTS (
              SELECT 1 FROM api.machine_tokens t
              WHERE t.id = token_id AND api.can_write_project(t.project_id)
            )
          );

GRANT SELECT, INSERT, DELETE ON api.machine_token_scope TO authenticated;

GRANT ALL ON api.machine_token_scope TO authenticator;

-- Shell-style glob (* ?) → SQL LIKE pattern (escape % and _).
        --
        -- Input:  p_glob (text: shell-style glob, e.g. 'API_*')
        -- Output: text — SQL LIKE pattern, e.g. 'API\_%'
        -- Example: SELECT private.glob_to_like('API_*');
        CREATE OR REPLACE FUNCTION private.glob_to_like(p_glob text)
        RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT
        SET search_path = pg_catalog AS $$
        DECLARE s text;
        BEGIN
          s := replace(p_glob, E'\\', E'\\\\');
          s := replace(s, '%', E'\\%');
          s := replace(s, '_', E'\\_');
          s := replace(s, '*', '%');
          s := replace(s, '?', '_');
          RETURN s;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_key_allowed(
          p_project uuid, p_hash text, p_key text
        ) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
          SELECT CASE
            WHEN p_key IS NULL OR btrim(p_key) = '' THEN false
            WHEN NOT private.auth_machine(p_project, p_hash) THEN false
            WHEN NOT EXISTS (
              SELECT 1
              FROM api.machine_token_scope sc
              JOIN api.machine_tokens t ON t.id = sc.token_id
              WHERE t.project_id = p_project
                AND t.token_hash = p_hash
                AND (t.expires_at IS NULL OR t.expires_at > now())
            ) THEN true
            WHEN EXISTS (
              SELECT 1
              FROM api.machine_token_scope sc
              JOIN api.machine_tokens t ON t.id = sc.token_id
              WHERE t.project_id = p_project
                AND t.token_hash = p_hash
                AND (t.expires_at IS NULL OR t.expires_at > now())
                AND (
                  (sc.secret_key IS NOT NULL AND sc.secret_key = p_key)
                  OR (
                    sc.key_pattern IS NOT NULL
                    AND p_key LIKE private.glob_to_like(sc.key_pattern) ESCAPE E'\\'
                  )
                )
            ) THEN true
            ELSE false
          END;
        $$;

GRANT EXECUTE ON FUNCTION private.glob_to_like TO authenticator;

GRANT EXECUTE ON FUNCTION private.machine_key_allowed TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_get_enc(p_project uuid, p_hash text, p_key text)
        RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
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
          id uuid, key text, value_enc text, note text, kind text,
          expires_at timestamptz, created_at timestamptz, updated_at timestamptz
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at, s.created_at, s.updated_at
            FROM api.secrets s
            WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
        RETURNS TABLE (key text, value_enc text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.key, s.value_enc FROM api.secrets s
            WHERE s.project_id = p_project AND s.deleted_at IS NULL
              AND private.machine_key_allowed(p_project, p_hash, s.key);
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_list_meta(
          p_project uuid, p_hash text, p_q text DEFAULT NULL
        )
        RETURNS TABLE (
          id uuid, key text, note text, kind text,
          expires_at timestamptz, created_at timestamptz, updated_at timestamptz
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
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
              AND private.machine_key_allowed(p_project, p_hash, s.key)
              AND (
                q IS NULL
                OR s.key ILIKE ('%' || q || '%')
                OR s.note ILIKE ('%' || q || '%')
                OR EXISTS (
                  SELECT 1 FROM api.secret_meta m
                  WHERE m.secret_id = s.id
                    AND (m.key ILIKE ('%' || q || '%') OR m.value ILIKE ('%' || q || '%'))
                )
              )
            ORDER BY s.key;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_delete(
          p_project uuid, p_hash text, p_key text
        )
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        DECLARE sid uuid;
        BEGIN
          IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
            RETURN NULL;
          END IF;
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN NULL;
          END IF;
          IF p_key IS NULL OR btrim(p_key) = '' THEN
            RETURN NULL;
          END IF;
          UPDATE api.secrets
          SET deleted_at = now
          WHERE project_id = p_project AND key = p_key AND deleted_at IS NULL
          RETURNING id INTO sid;
          RETURN sid;
        END;
        $$;

CREATE OR REPLACE FUNCTION private.machine_upsert_enc(
          p_project uuid,
          p_hash text,
          p_key text,
          p_value_enc text,
          p_note text,
          p_kind text DEFAULT 'plain',
          p_expires_at timestamptz DEFAULT NULL,
          p_set_expires boolean DEFAULT false
        )
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        DECLARE
          sid uuid;
          k text := COALESCE(NULLIF(btrim(p_kind), ''), 'plain');
        BEGIN
          IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
            RETURN NULL;
          END IF;
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN NULL;
          END IF;
          IF p_key IS NULL OR btrim(p_key) = '' OR p_value_enc IS NULL THEN
            RETURN NULL;
          END IF;
          IF k NOT IN ('plain', 'database', 'certificate', 'ssh', 'kv') THEN
            k := 'plain';
          END IF;
          INSERT INTO api.secrets (project_id, key, value_enc, note, kind, expires_at)
          VALUES (
            p_project, p_key, p_value_enc, COALESCE(p_note, ''), k,
            CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END
          )
          ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
            SET value_enc = EXCLUDED.value_enc,
                note = EXCLUDED.note,
                kind = EXCLUDED.kind,
                expires_at = CASE
                  WHEN p_set_expires THEN p_expires_at
                  ELSE api.secrets.expires_at
                END
          RETURNING id INTO sid;
          RETURN sid;
        END;
        $$;
