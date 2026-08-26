-- api.webhooks was created by 0013 after 0001's blanket
-- "GRANT ... ON ALL TABLES IN SCHEMA api" ran, so authenticated had no table
-- privileges and every as_user() read failed with "permission denied".

GRANT SELECT, INSERT, UPDATE, DELETE ON api.webhooks TO authenticated;
