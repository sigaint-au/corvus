-- 0011 added api.machine_tokens.description after 0001's column-level
-- SELECT grant (token_hash withheld from PostgREST / authenticated).
-- New columns do not inherit that GRANT, so SELECT description raises
-- permission denied for table machine_tokens and the tokens tab 500s.

GRANT SELECT (description) ON api.machine_tokens TO authenticated;
