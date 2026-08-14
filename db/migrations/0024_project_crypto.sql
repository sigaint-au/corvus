-- Per-project Bring-Your-Own-Key (BYOK) support.
--
-- Each project may have a dedicated data-encryption key (DEK). The DEK is a
-- random Fernet key, stored wrapped ("enveloped") by the app MASTER_KEY in
-- private.project_crypto_keys — the raw DEK is never stored. Secret values
-- encrypted with a project DEK are marked ``crypto_provider='project'``;
-- values still encrypted with the app master key (legacy / non-BYOK) are
-- marked ``crypto_provider='master'``. Secret version snapshots carry the same
-- marker so history stays decryptable.
--
-- Added only: new tables and columns. Existing baseline DDL is untouched
-- (the runner never re-applies 0001/0002).

CREATE TABLE IF NOT EXISTS private.project_crypto_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  -- DEK wrapped by MASTER_KEY (Fernet); never store the raw key.
  key_enc text NOT NULL,
  -- Key material origin: 'local' (generated & stored server-side) now;
  -- 'kms' later.
  key_provider text NOT NULL DEFAULT 'local',
  -- Future: external key reference (e.g. KMS ARN / URI) when key_provider=kms.
  kms_key_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id)
);

REVOKE ALL ON private.project_crypto_keys FROM authenticator, authenticated, anon;

-- Which key encrypted this secret's value_enc: 'master' (app key) or 'project'
-- (this project's DEK). Defaults to 'master' for existing rows.
ALTER TABLE api.secrets
  ADD COLUMN IF NOT EXISTS crypto_provider text NOT NULL DEFAULT 'master';

ALTER TABLE api.secret_versions
  ADD COLUMN IF NOT EXISTS crypto_provider text NOT NULL DEFAULT 'master';

-- Copy the provider into archived versions so history can be decrypted.
CREATE OR REPLACE FUNCTION api.archive_secret_version()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, api, private
SET row_security = off AS $$
BEGIN
  IF OLD.value_enc IS DISTINCT FROM NEW.value_enc THEN
    INSERT INTO api.secret_versions (secret_id, value_enc, note, crypto_provider)
    VALUES (OLD.id, OLD.value_enc, OLD.note, OLD.crypto_provider);
  END IF;
  RETURN NEW;
END;
$$;

-- Machine read helper returns the provider so the app can pick the right key.
-- Return type changed (added crypto_provider) → drop old signature first.
DROP FUNCTION IF EXISTS private.machine_get_row(uuid, text, text);
CREATE OR REPLACE FUNCTION private.machine_get_row(p_project uuid, p_hash text, p_key text)
        RETURNS TABLE (
          id uuid, key text, value_enc text, note text, kind text,
          expires_at timestamptz, created_at timestamptz, updated_at timestamptz,
          crypto_provider text
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.machine_key_allowed(p_project, p_hash, p_key) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.id, s.key, s.value_enc, s.note, s.kind, s.expires_at, s.created_at, s.updated_at,
                   s.crypto_provider
            FROM api.secrets s
            WHERE s.project_id = p_project AND s.key = p_key AND s.deleted_at IS NULL;
        END;
        $$;

-- Machine bulk value listing also reports per-row provider (return type changed
-- → drop the old 3-column form first).
DROP FUNCTION IF EXISTS private.machine_list_enc(uuid, text);
CREATE OR REPLACE FUNCTION private.machine_list_enc(p_project uuid, p_hash text)
        RETURNS TABLE (key text, value_enc text, crypto_provider text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, api
        SET row_security = off AS $$
        BEGIN
          IF NOT private.auth_machine(p_project, p_hash) THEN
            RETURN;
          END IF;
          RETURN QUERY
            SELECT s.key, s.value_enc, s.crypto_provider FROM api.secrets s
            WHERE s.project_id = p_project AND s.deleted_at IS NULL
              AND private.machine_key_allowed(p_project, p_hash, s.key);
        END;
        $$;

-- Machine upsert stores the provider the app encrypted with.
DROP FUNCTION IF EXISTS private.machine_upsert_enc(uuid, text, text, text, text, text, timestamptz, boolean);
CREATE OR REPLACE FUNCTION private.machine_upsert_enc(
          p_project uuid,
          p_hash text,
          p_key text,
          p_value_enc text,
          p_note text,
          p_kind text DEFAULT 'plain',
          p_expires_at timestamptz DEFAULT NULL,
          p_set_expires boolean DEFAULT false,
          p_crypto_provider text DEFAULT 'master'
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
          INSERT INTO api.secrets (project_id, key, value_enc, note, kind, expires_at, crypto_provider)
          VALUES (
            p_project, p_key, p_value_enc, COALESCE(p_note, ''), k,
            CASE WHEN p_set_expires THEN p_expires_at ELSE NULL END,
            CASE WHEN p_crypto_provider IN ('master', 'project') THEN p_crypto_provider ELSE 'master' END
          )
          ON CONFLICT (project_id, key) WHERE deleted_at IS NULL DO UPDATE
            SET value_enc = EXCLUDED.value_enc,
                note = EXCLUDED.note,
                kind = EXCLUDED.kind,
                crypto_provider = EXCLUDED.crypto_provider,
                expires_at = CASE
                  WHEN p_set_expires THEN p_expires_at
                  ELSE api.secrets.expires_at
                END
          RETURNING id INTO sid;
          RETURN sid;
        END;
        $$;