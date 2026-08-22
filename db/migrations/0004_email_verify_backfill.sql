-- Email verification follow-up:
-- 1. Existing accounts already proved control of the mailbox by using the
--    system; stamp them verified so the login gate does not lock them out.
-- 2. Return email_verified_at from private.verify_user so login does not
--    SELECT private.users as authenticator (no table privilege).

UPDATE private.users
   SET email_verified_at = COALESCE(email_verified_at, created_at, now())
 WHERE email_verified_at IS NULL;

DROP FUNCTION IF EXISTS private.verify_user(text, text);

CREATE OR REPLACE FUNCTION private.verify_user(p_email text, p_password text)
RETURNS TABLE (
  id uuid,
  email text,
  name text,
  is_global_admin boolean,
  email_verified_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email, u.name, u.is_global_admin, u.email_verified_at
    FROM private.users u
   WHERE u.email = lower(p_email)
     AND u.password_hash IS NOT NULL
     AND u.disabled_at IS NULL
     AND u.password_hash = crypt(p_password, u.password_hash);
END;
$$;

GRANT EXECUTE ON FUNCTION private.verify_user TO authenticator;
