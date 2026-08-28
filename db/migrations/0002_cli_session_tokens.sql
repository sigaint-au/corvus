-- CLI session tokens (user-scoped, short-lived, single-purpose login handoff).
--
-- Minted by the "Copy login command" flow so a user can paste a ready-made
-- `corvus login --url <base> --token sso_…` command into a shell without
-- exposing a long-lived PAT. Opaque token, SHA-256 hashed at rest, multi-use
-- within a fixed TTL (cli_session_ttl_seconds, default 3600 = 1h).
--
-- Unlike personal_access_tokens, expires_at is NOT NULL: every CLI session
-- token carries an expiry enforced by the resolver. last_used_at is bumped on
-- each successful use (multi-use is intentional within the TTL).

CREATE TABLE IF NOT EXISTS private.cli_session_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES private.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cli_session_tokens_user_idx
  ON private.cli_session_tokens (user_id, created_at DESC);
