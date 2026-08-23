-- Clusters bootstrapped from an older 0001 (PBKDF2 hashed in the app, stored
-- as-is) need the bcrypt-in-SQL helpers that later landed in the baseline.
-- Additive so existing volumes can take the new app without replaying 0001.
-- DROP the 1-arg verify_user leftover; 0004 already created the 2-arg form.

DROP FUNCTION IF EXISTS private.verify_user(text);

CREATE OR REPLACE FUNCTION private.register_user(p_email text, p_password text, p_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = private, public AS $$
DECLARE uid uuid;
BEGIN
  INSERT INTO private.users (email, password_hash, name, is_global_admin, auth_source)
  VALUES (lower(p_email), crypt(p_password, gen_salt('bf')), COALESCE(p_name, ''), false, 'local')
  RETURNING id INTO uid;
  RETURN uid;
END;
$$;

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

GRANT EXECUTE ON FUNCTION private.register_user TO authenticator;
GRANT EXECUTE ON FUNCTION private.change_password TO authenticator;
GRANT EXECUTE ON FUNCTION private.set_local_password TO authenticator;
