-- 0010_login_lockout_machine_tokens
-- login failures, machine token columns/roles, auth_machine

CREATE TABLE IF NOT EXISTS private.login_failures (
          id bigserial PRIMARY KEY,
          email text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        );

CREATE INDEX IF NOT EXISTS login_failures_email_created_idx
          ON private.login_failures (email, created_at);

ALTER TABLE api.machine_tokens
          ADD COLUMN IF NOT EXISTS expires_at timestamptz;

ALTER TABLE api.machine_tokens
          ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'service-reveal';

ALTER TABLE api.machine_tokens
          ADD COLUMN IF NOT EXISTS last_used_at timestamptz;

DO $$ BEGIN
          ALTER TABLE api.machine_tokens
            ADD CONSTRAINT machine_tokens_token_prefix_key UNIQUE (token_prefix);
        EXCEPTION WHEN duplicate_table OR duplicate_object OR unique_violation THEN NULL;
        END $$;

DO $$ BEGIN
          ALTER TABLE api.machine_tokens DROP CONSTRAINT IF EXISTS machine_tokens_role_check;
          ALTER TABLE api.machine_tokens
            ADD CONSTRAINT machine_tokens_role_check
            CHECK (role IN ('service-read', 'service-reveal', 'service-write'));
        EXCEPTION WHEN others THEN NULL;
        END $$;

-- Migrate machine token roles to RBAC service role names
        UPDATE api.machine_tokens SET role = 'service-read' WHERE role IN ('read', 'read-only');

UPDATE api.machine_tokens SET role = 'service-reveal' WHERE role = 'reveal';

UPDATE api.machine_tokens SET role = 'service-write' WHERE role = 'write';

CREATE OR REPLACE FUNCTION private.auth_machine(p_project uuid, p_hash text)
        RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = api AS $$
          DECLARE
            ok boolean;
          BEGIN
            SELECT EXISTS (
              SELECT 1 FROM api.machine_tokens
              WHERE project_id = p_project AND token_hash = p_hash
                AND (expires_at IS NULL OR expires_at > now())
            ) INTO ok;
            IF ok THEN
              UPDATE api.machine_tokens
              SET last_used_at = now()
              WHERE project_id = p_project AND token_hash = p_hash;
            END IF;
            RETURN ok;
          END;
        $$;

GRANT EXECUTE ON FUNCTION private.auth_machine TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_role(p_project uuid, p_hash text)
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
          SELECT role FROM api.machine_tokens
          WHERE project_id = p_project AND token_hash = p_hash
            AND (expires_at IS NULL OR expires_at > now())
          LIMIT 1;
        $$;

GRANT EXECUTE ON FUNCTION private.machine_role TO authenticator;

CREATE OR REPLACE FUNCTION private.machine_token_label(p_project uuid, p_hash text)
        RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = api AS $$
          SELECT COALESCE(NULLIF(btrim(name), ''), 'token') || ':' || token_prefix
          FROM api.machine_tokens
          WHERE project_id = p_project AND token_hash = p_hash
            AND (expires_at IS NULL OR expires_at > now())
          LIMIT 1;
        $$;

GRANT EXECUTE ON FUNCTION private.machine_token_label TO authenticator;

DROP FUNCTION IF EXISTS private.machine_upsert_enc(uuid, text, text, text, text);

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
        RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = api AS $$
        DECLARE
          sid uuid;
          k text := COALESCE(NULLIF(btrim(p_kind), ''), 'plain');
        BEGIN
          IF private.machine_role(p_project, p_hash) IS DISTINCT FROM 'service-write' THEN
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
            p_project,
            p_key,
            p_value_enc,
            COALESCE(p_note, ''),
            k,
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

GRANT EXECUTE ON FUNCTION private.machine_upsert_enc TO authenticator;

DROP POLICY IF EXISTS mt_select ON api.machine_tokens;

CREATE POLICY mt_select ON api.machine_tokens FOR SELECT TO authenticated
          USING (api.can_read_project(project_id));

DROP POLICY IF EXISTS mt_insert ON api.machine_tokens;

CREATE POLICY mt_insert ON api.machine_tokens FOR INSERT TO authenticated
          WITH CHECK (api.can_write_project(project_id));

DROP POLICY IF EXISTS mt_delete ON api.machine_tokens;

CREATE POLICY mt_delete ON api.machine_tokens FOR DELETE TO authenticated
          USING (api.can_write_project(project_id));
