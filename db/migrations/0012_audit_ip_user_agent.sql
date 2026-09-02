-- Audit IP address + user agent (forensics: who acted from where).
-- Ponytail: plain text columns with defaults, no index; follows
-- private.user_sessions (user_agent, ip) convention. Writers pass
-- Flask request metadata; machine/CLI API rows go through the same
-- log_secret/log_org helpers so they are captured too.

ALTER TABLE api.secret_audit
  ADD COLUMN IF NOT EXISTS ip_address text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS user_agent text NOT NULL DEFAULT '';

ALTER TABLE api.org_audit
  ADD COLUMN IF NOT EXISTS ip_address text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS user_agent text NOT NULL DEFAULT '';

CREATE OR REPLACE FUNCTION private.audit_secret(
  p_project uuid,
  p_secret_id uuid,
  p_secret_key text,
  p_action text,
  p_user_id uuid DEFAULT NULL,
  p_actor_email text DEFAULT NULL,
  p_ip_address text DEFAULT '',
  p_user_agent text DEFAULT ''
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private, pg_catalog AS $$
DECLARE
  uid uuid;
  email text;
BEGIN
  IF p_action NOT IN (
    'created', 'updated', 'revealed', 'deleted', 'restored', 'purged',
    'machine_upsert', 'exported',
    'access_requested', 'access_approved', 'access_denied'
  ) THEN
    RAISE EXCEPTION 'invalid audit action: %', p_action;
  END IF;
  -- Never trust caller-supplied p_user_id
  BEGIN
    uid := NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
  EXCEPTION WHEN others THEN
    uid := NULL;
  END;
  email := COALESCE(
    (SELECT u.email FROM private.users u WHERE u.id = uid),
    NULLIF(p_actor_email, ''),
    ''
  );
  INSERT INTO api.secret_audit (project_id, secret_id, secret_key, user_id, actor_email, action, ip_address, user_agent)
  VALUES (p_project, p_secret_id, COALESCE(p_secret_key, ''), uid, email, p_action, COALESCE(p_ip_address, ''), COALESCE(p_user_agent, ''));
END;
$$;

CREATE OR REPLACE FUNCTION private.audit_org(
  p_team uuid,
  p_project uuid,
  p_action text,
  p_detail text DEFAULT '',
  p_actor_email text DEFAULT NULL,
  p_ip_address text DEFAULT '',
  p_user_agent text DEFAULT ''
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = api, private, pg_catalog AS $$
DECLARE
  uid uuid;
  email text;
BEGIN
  IF p_action IS NULL OR btrim(p_action) = '' THEN
    RAISE EXCEPTION 'invalid org audit action';
  END IF;
  BEGIN
    uid := NULLIF(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid;
  EXCEPTION WHEN others THEN
    uid := NULL;
  END;
  email := COALESCE(
    (SELECT u.email FROM private.users u WHERE u.id = uid),
    NULLIF(p_actor_email, ''),
    ''
  );
  INSERT INTO api.org_audit (team_id, project_id, action, detail, user_id, actor_email, ip_address, user_agent)
  VALUES (p_team, p_project, p_action, COALESCE(p_detail, ''), uid, email, COALESCE(p_ip_address, ''), COALESCE(p_user_agent, ''));
END;
$$;
