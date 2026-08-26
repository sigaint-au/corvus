-- ── Webhooks UX support
--    SSL-verification toggle on endpoints + a delivery log so operators can
--    debug receivers ("Recent deliveries" list). The queue stays in private;
--    the log is api.* so RLS can expose it to scope managers.

ALTER TABLE api.webhooks
  ADD COLUMN IF NOT EXISTS ssl_verify boolean NOT NULL DEFAULT true;

CREATE TABLE IF NOT EXISTS api.webhook_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id uuid NOT NULL REFERENCES api.webhooks(id) ON DELETE CASCADE,
  event text NOT NULL,
  ok boolean NOT NULL,
  status_code integer,
  error text NOT NULL DEFAULT '',
  duration_ms integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_recent_idx
  ON api.webhook_deliveries (webhook_id, created_at DESC);

ALTER TABLE api.webhook_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_deliveries_select ON api.webhook_deliveries FOR SELECT TO authenticated
  USING (
    api.is_global_admin()
    OR EXISTS (
      SELECT 1 FROM api.webhooks w
      WHERE w.id = webhook_id
        AND api.can_manage_rbac(w.scope_kind, w.scope_id)
    )
  );

GRANT SELECT ON api.webhook_deliveries TO authenticated;
