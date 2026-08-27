# Webhooks

Corvus can push audit events (secret reveal, update, member changes, and more)
to your own HTTP endpoints. Each webhook is scoped to a project, a team, or the
whole cluster, and only fires for the event types you select.

Webhooks are a **push** integration: Corvus is the client, your endpoint is the
server. This is the reverse of the [External Secrets Operator](external-secrets.md)
flow, where Corvus is the server.

| Direction | Who calls | Purpose |
|-----------|-----------|---------|
| **Webhooks** | Corvus → your endpoint | Alerting, SIEM, automation on events |
| **ESO pull** | External Secrets Operator → Corvus | Sync secrets into Kubernetes |
| **ESO push** | External Secrets Operator → Corvus | Rotate secrets from the cluster |

---

## 1. Prerequisites

- A **background worker** must be running, or no webhook is delivered. See
  [deploy.md](deploy.md#webhook-background-worker) (`flask --app app work-webhooks`).
- The endpoint must be reachable from the worker and answer within **10 seconds**.
- You need permission to manage the scope you target: a **global admin** for
  cluster webhooks, a team or project admin for team/project webhooks.

---

## 2. Scopes

Every webhook belongs to one scope. The scope decides which events reach it:

| Scope | Receives | Who manages |
|-------|----------|-------------|
| **Cluster** | Every event type on every team and project | Global admins (Server settings → Webhooks) |
| **Team** | All `org.*` events for that team **plus** every `secret.*` event for projects in that team | Team admins (Team → Webhooks) |
| **Project** | Every `secret.*` event for that project and `org.*` events whose `project_id` is that project | Project admins (Project → Webhooks) |

A webhook fires only when **all** of these hold:

- the webhook is `active`,
- the event is in the webhook's event list,
- the event's scope matches the webhook's scope (above).

---

## 3. Events

Events are grouped in the UI, but each is a single string you subscribe to.
The full list:

| Group | Events |
|-------|--------|
| **Secret events** | `secret.created`, `secret.updated`, `secret.revealed`, `secret.deleted`, `secret.restored`, `secret.purged`, `secret.machine_upsert`, `secret.exported`, `secret.access_requested`, `secret.access_approved`, `secret.access_denied` |
| **Team events** | `org.member_add`, `org.member_remove`, `org.member_role`, `org.invite_create`, `org.invite_revoke`, `org.join_request`, `org.join_approve`, `org.join_reject`, `org.team_settings` |
| **Project events** | `org.project_member_add`, `org.project_member_remove`, `org.project_member_role`, `org.project_key_created`, `org.hsm_kek_rotated` |

Notes:

- `secret.revealed` fires when a value is revealed in the UI or via the API,
  including ESO pulls.
- `secret.machine_upsert` fires when a machine token or ESO push creates or
  updates a secret.
- `secret.purged` is the only event that can arrive for a secret that no longer
  exists (the row is already gone).
- `org.project_key_created` and `org.hsm_kek_rotated` are project-scope events
  about the project's encryption key, not a secret.

---

## 4. Payload

The body is a JSON object. The shape differs slightly between secret and org
events, but both carry `event`, `actor_email`, and `timestamp` so a receiver can
handle them uniformly.

### Secret events

```json
{
  "event": "secret.revealed",
  "project_id": "3f8e2c1a-5d4b-4c3a-9f2e-1a2b3c4d5e6f",
  "secret_id": "9c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
  "secret_key": "API_KEY",
  "actor_email": "alice@example.com",
  "timestamp": "2026-08-27T10:15:30.123456+00:00"
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `event` | string | The event name, e.g. `secret.created` |
| `project_id` | string (UUID) | Project the secret belongs to |
| `secret_id` | string (UUID) | The secret's id (`null` after `secret.purged`) |
| `secret_key` | string | The secret's key, e.g. `API_KEY` |
| `actor_email` | string | Email of the user (or `machine`) who triggered the event |
| `timestamp` | string (ISO 8601) | When the audit row was written |

### Org events

```json
{
  "event": "org.member_add",
  "team_id": "2a1b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "project_id": null,
  "action": "member_add",
  "detail": "",
  "actor_email": "alice@example.com",
  "timestamp": "2026-08-27T10:15:30.123456+00:00"
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `event` | string | The event name, e.g. `org.member_add` |
| `team_id` | string (UUID) | Team the event belongs to |
| `project_id` | string (UUID) or `null` | Project, when the event is project-scoped |
| `action` | string | The action without the `org.` prefix |
| `detail` | string | Free-form detail string from the audit row (often empty) |
| `actor_email` | string | Email of the user who triggered the event |
| `timestamp` | string (ISO 8601) | When the audit row was written |

The payload never contains secret values. `secret_key` is the key name only —
the value stays encrypted in the database.

---

## 5. HTTP request

Each delivery is a single `POST`:

| | |
|---|---|
| **Method** | `POST` |
| **Content-Type** | `application/json` |
| **Body** | The payload (section 4), JSON-encoded |
| **User-Agent** | `Corvus-Webhooks/1.0` |
| **X-Corvus-Signature** | HMAC-SHA256 hex digest of the raw body, keyed with the webhook's signing secret |

Example:

```
POST /hooks/corvus HTTP/1.1
Host: example.internal
Content-Type: application/json
User-Agent: Corvus-Webhooks/1.0
X-Corvus-Signature: 5f4dcc3b5aa765d61d8327deb882cf99b95930f3d9b0f3a1...

{"event": "secret.revealed", "project_id": "3f8e...", "secret_id": "9c1d...", "secret_key": "API_KEY", "actor_email": "alice@example.com", "timestamp": "2026-08-27T10:15:30.123456+00:00"}
```

The signature is computed over the **exact raw request body**, not a
re-serialized copy. Compute it on the bytes you received.

---

## 6. Verify the signature

Always verify `X-Corvus-Signature` on the receiver side. The signing secret is
generated for you when you create a webhook (or you can supply your own) and is
**shown once** — store it in your endpoint's configuration or secret manager.

Python (stdlib only):

```python
import hashlib, hmac

def verify(payload: bytes, signature: str, secret_token: str) -> bool:
    expected = hmac.new(
        secret_token.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Use a constant-time comparison (`hmac.compare_digest` above). A naive `==`
comparison leaks timing information.

---

## 7. Response expectations and retries

| Outcome | Result |
|---------|--------|
| `2xx` | Delivery is a success; the queue row is deleted. |
| Any other status, network error, or timeout (> 10 s) | Delivery is retried with exponential backoff. |
| 10 failed attempts | The delivery is dropped and logged. |

Backoff schedule: **30s, 1m, 2m, 4m, 8m, …** (30 × 2^n seconds). Respond `2xx`
as soon as you have accepted the event; do the slow work (indexing, fan-out)
after responding, so you stay inside the 10-second window.

The worker uses `SELECT … FOR UPDATE SKIP LOCKED`, so you can run multiple
worker replicas and each event is delivered exactly once per attempt — no
double delivery from concurrent workers.

---

## 8. Delivery log

Every attempt is recorded on the webhook's page under **Recent deliveries**:
event, HTTP status, error, and duration in milliseconds. The last **50**
attempts per webhook are kept; older rows are pruned automatically. Use this
page to confirm a webhook is healthy and to debug failures.

---

## 9. How you might use it

### Alerting on sensitive events

Subscribe a project to `secret.revealed` and post to a Slack/Teams webhook or
PagerDuty. A reveal of a production credential outside normal hours becomes a
notification instead of a silent event.

### SIEM / audit aggregation

Point a cluster webhook at your SIEM's HTTP collector. Corvus's own audit log is
in-app; a webhook streams the same events into your central log store for
correlation with the rest of your infrastructure.

### Drift and compliance checks

Subscribe to `org.member_add`, `org.member_remove`, and `org.member_role` to
detect access changes as they happen. `org.project_key_created` /
`org.hsm_kek_rotated` tell you when a project's encryption key changes.

### Incident response

`secret.access_requested` / `secret.access_approved` / `secret.access_denied`
let you watch the reveal-approval workflow. `secret.exported` flags bulk
exports (`secret.exported` fires on project export and bulk download).

### Rotating secrets from outside

`secret.machine_upsert` fires when ESO pushes a new value. A downstream system
(e.g. a deployment pipeline) can listen and reload configs that reference the
rotated secret.

---

## 10. Security notes

- **Use HTTPS** for the payload URL. Corvus verifies the endpoint's TLS
  certificate by default; uncheck *Verify SSL certificate* only for internal
  endpoints with a private CA.
- **Verify the signature** on every request (section 6). The signing secret is
  the only thing that proves a delivery came from Corvus.
- **Rotate the signing secret** by editing the webhook and changing it — the
  field is blank on edit, so a new value replaces the old one.
- The payload is **metadata only**: no secret values, no tokens, no encrypted
  blobs. Treat it as sensitive but not as a credential channel.
- A webhook that fails 10 times is dropped silently (logged). Monitor the
  delivery log or the endpoint's own liveness.

---

## Related docs

- [deploy.md](deploy.md#webhook-background-worker): running the worker
- [audit.md](audit.md): the audit log the events are derived from
- [external-secrets.md](external-secrets.md): the reverse direction (ESO → Corvus)
- [configuration.md](configuration.md): the `work-webhooks` command