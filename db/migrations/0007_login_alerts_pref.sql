-- Per-user login-alert email preference, plus a server force-override.
-- smtp_login_alerts remains the master switch; smtp_login_alerts_force
-- ignores the user preference when both SMTP and login alerts are on.

ALTER TABLE private.users
  ADD COLUMN IF NOT EXISTS login_alerts boolean NOT NULL DEFAULT true;

INSERT INTO private.server_settings (key, value)
VALUES ('smtp_login_alerts_force', 'false')
ON CONFLICT (key) DO NOTHING;
