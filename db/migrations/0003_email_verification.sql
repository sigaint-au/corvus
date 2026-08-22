-- Email verification for locally-registered accounts.
-- Adds verification columns to private.users and stamps directory-provisioned
-- users as verified: LDAP/OIDC sign-in already proves control of the mailbox.
-- Locally-registered accounts start unverified when SMTP is configured; the
-- app emails a single-use link (hashed at rest, 3-day window).

ALTER TABLE private.users
  ADD COLUMN IF NOT EXISTS email_verified_at timestamptz,
  ADD COLUMN IF NOT EXISTS email_verify_token_hash text,
  ADD COLUMN IF NOT EXISTS email_verify_sent_at timestamptz;

CREATE INDEX IF NOT EXISTS users_email_verify_token_idx
  ON private.users (email_verify_token_hash)
  WHERE email_verify_token_hash IS NOT NULL;

-- Directory provisioning proves the address: keep it verified.
CREATE OR REPLACE FUNCTION private.upsert_ldap_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source,
                               email_verified_at)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'ldap', now())
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = 'ldap',
        email_verified_at = COALESCE(email_verified_at, now())
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;

CREATE OR REPLACE FUNCTION private.upsert_oidc_user(p_email text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  SELECT id INTO uid FROM private.users WHERE email = lower(p_email);
  IF uid IS NULL THEN
    INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source,
                               email_verified_at)
    VALUES (lower(p_email), NULL, COALESCE(p_name, ''), false, 'oidc', now())
    RETURNING id INTO uid;
  ELSE
    UPDATE private.users
    SET name = CASE WHEN COALESCE(p_name, '') <> '' THEN p_name ELSE name END,
        auth_source = CASE
          WHEN auth_source = 'local' AND password_hash IS NOT NULL THEN auth_source
          ELSE 'oidc'
        END,
        email_verified_at = COALESCE(email_verified_at, now())
    WHERE id = uid;
  END IF;
  RETURN uid;
END;
$$;
