-- ── Webhooks core schema
--    Tables for webhook definitions and the background delivery queue.

CREATE TABLE api.webhooks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    url text NOT NULL,
    secret_token text NOT NULL,
    events text[] NOT NULL DEFAULT '{}',
    scope_kind text NOT NULL CHECK (scope_kind IN ('cluster', 'team', 'project')),
    scope_id uuid, -- NULL for cluster
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- RLS: global admin or scope manager can see/edit
ALTER TABLE api.webhooks ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhooks_select ON api.webhooks FOR SELECT TO authenticated
  USING (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id));

CREATE POLICY webhooks_write ON api.webhooks FOR ALL TO authenticated
  USING (api.is_global_admin() OR api.can_manage_rbac(scope_kind, scope_id));

-- Delivery queue (internal)
CREATE TABLE private.webhook_delivery_queue (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id uuid NOT NULL REFERENCES api.webhooks(id) ON DELETE CASCADE,
    payload jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    next_retry_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz
);

CREATE INDEX webhook_queue_retry_idx ON private.webhook_delivery_queue (next_retry_at) 
  WHERE locked_until IS NULL OR locked_until < now();

-- ── Logic: enqueue webhooks on audit
--    Check which webhooks match the current audit event's scope and event type.

CREATE OR REPLACE FUNCTION private.enqueue_webhooks(
    p_scope_kind text,
    p_scope_id uuid,
    p_event text,
    p_payload jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
DECLARE
    v_webhook_id uuid;
BEGIN
    FOR v_webhook_id IN
        SELECT id FROM api.webhooks
        WHERE active = true
          AND p_event = ANY(events)
          AND (
            (scope_kind = 'cluster')
            OR (scope_kind = 'team' AND scope_id = (
                CASE 
                    WHEN p_scope_kind = 'team' THEN p_scope_id
                    WHEN p_scope_kind = 'project' THEN (SELECT team_id FROM api.projects WHERE id = p_scope_id)
                END
            ))
            OR (scope_kind = 'project' AND p_scope_kind = 'project' AND scope_id = p_scope_id)
          )
    LOOP
        INSERT INTO private.webhook_delivery_queue (webhook_id, payload)
        VALUES (v_webhook_id, p_payload);
    END LOOP;
END;
$$;

-- Trigger enqueuing on secret audit
CREATE OR REPLACE FUNCTION private.tr_webhook_secret_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
BEGIN
    PERFORM private.enqueue_webhooks(
        'project',
        NEW.project_id,
        'secret.' || NEW.action,
        jsonb_build_object(
            'event', 'secret.' || NEW.action,
            'project_id', NEW.project_id,
            'secret_id', NEW.secret_id,
            'secret_key', NEW.secret_key,
            'actor_email', NEW.actor_email,
            'timestamp', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_webhook_secret_audit
AFTER INSERT ON api.secret_audit
FOR EACH ROW EXECUTE FUNCTION private.tr_webhook_secret_audit();

-- Trigger enqueuing on org audit
CREATE OR REPLACE FUNCTION private.tr_webhook_org_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = api, private, pg_catalog AS $$
BEGIN
    PERFORM private.enqueue_webhooks(
        CASE WHEN NEW.project_id IS NOT NULL THEN 'project' ELSE 'team' END,
        COALESCE(NEW.project_id, NEW.team_id),
        'org.' || NEW.action,
        jsonb_build_object(
            'event', 'org.' || NEW.action,
            'team_id', NEW.team_id,
            'project_id', NEW.project_id,
            'action', NEW.action,
            'detail', NEW.detail,
            'actor_email', NEW.actor_email,
            'timestamp', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_webhook_org_audit
AFTER INSERT ON api.org_audit
FOR EACH ROW EXECUTE FUNCTION private.tr_webhook_org_audit();
