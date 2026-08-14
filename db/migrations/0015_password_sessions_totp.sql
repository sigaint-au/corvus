-- 0015_password_sessions_totp
-- password change, sessions, password reset, TOTP

-- Change password (local accounts only; requires current password).
        --
        -- Input:  p_user (uuid: user id),
        --         p_old  (text: current plaintext password),
        --         p_new  (text: new plaintext password, min 8 chars)
        -- Output: boolean — true if changed, false if old password wrong
        -- Example: SELECT private.change_password('<user-uuid>', 'oldpass', 'newpass123');
        CREATE OR REPLACE FUNCTION private.change_password(
          p_user uuid, p_old text, p_new text
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        BEGIN
          IF p_new IS NULL OR length(p_new) < 8 THEN
            RAISE EXCEPTION 'password must be at least 8 characters';
          END IF;
          UPDATE private.users
          SET password_hash = crypt(p_new, gen_salt('bf'))
          WHERE id = p_user
            AND auth_source = 'local'
            AND password_hash IS NOT NULL
            AND password_hash = crypt(p_old, password_hash);
          RETURN FOUND;
        END;
        $$;

-- Set password after verified reset (local accounts only).
        --
        -- Input:  p_user (uuid: user id),
        --         p_new  (text: new plaintext password, min 8 chars)
        -- Output: boolean — true if set, false if user not found / not local
        -- Example: SELECT private.set_local_password('<user-uuid>', 'newpass123');
        CREATE OR REPLACE FUNCTION private.set_local_password(p_user uuid, p_new text)
        RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
        BEGIN
          IF p_new IS NULL OR length(p_new) < 8 THEN
            RAISE EXCEPTION 'password must be at least 8 characters';
          END IF;
          UPDATE private.users
          SET password_hash = crypt(p_new, gen_salt('bf'))
          WHERE id = p_user
            AND auth_source = 'local'
            AND password_hash IS NOT NULL;
          RETURN FOUND;
        END;
        $$;

GRANT EXECUTE ON FUNCTION private.change_password TO authenticator;

GRANT EXECUTE ON FUNCTION private.set_local_password TO authenticator;

CREATE TABLE IF NOT EXISTS private.user_sessions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          created_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL,
          revoked_at timestamptz,
          user_agent text NOT NULL DEFAULT '',
          ip text NOT NULL DEFAULT ''
        );

CREATE INDEX IF NOT EXISTS user_sessions_user_active_idx
          ON private.user_sessions (user_id, last_seen_at DESC)
          WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS private.password_reset_tokens (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          token_hash text NOT NULL UNIQUE,
          expires_at timestamptz NOT NULL,
          used_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now()
        );

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
          ON private.password_reset_tokens (user_id)
          WHERE used_at IS NULL;

ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS totp_secret_enc text;

ALTER TABLE private.users
          ADD COLUMN IF NOT EXISTS totp_enabled_at timestamptz;

CREATE TABLE IF NOT EXISTS private.totp_recovery_codes (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
          code_hash text NOT NULL,
          used_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now()
        );

CREATE INDEX IF NOT EXISTS totp_recovery_codes_user_idx
          ON private.totp_recovery_codes (user_id)
          WHERE used_at IS NULL;
