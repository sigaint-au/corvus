# Auditing

Sigaint Secret Server records two audit streams and provides an admin review
UI, export, and retention purge.

---

## Audit streams

| Table | Scope | Contents |
|-------|-------|----------|
| `api.secret_audit` | Per secret / project | create, update, reveal, delete, restore, purge, machine_upsert, export, access_requested/approved/denied |
| `api.org_audit` | Per team / project | membership changes, group role changes, project settings, ownership transfer |

Audit rows are **append-only**: they are written only via SECURITY DEFINER
functions (`private.audit_secret`, `private.audit_org`) and cannot be inserted
or modified by clients. The actor is always derived from the JWT claims, never
from caller-supplied input.

---

## Viewing

### Project audit log

Open a project → **Audit log** tab. Filter by search text, actor, action, and
date range.

### Team activity

Open a team → **Activity** tab (team-level events).

### Global admin audit

Sidebar → **Administration → Auditing**. Tabs:

| Tab | Contents |
|-----|----------|
| **Access review** | Access-related events |
| **Role changes** | Membership / role changes |
| **Export & retention** | Export audit data and set retention |

---

## Retention & purge

Retention is configured in the UI (**Administration → Auditing → Export &
retention**, `audit_retention_days`). `0` = keep forever.

Rows are **not** deleted automatically. A purge job must run:

```bash
# Dry-run (counts only)
flask --app app purge-audit --dry-run

# Use server setting audit_retention_days
flask --app app purge-audit

# Override retention for this run
flask --app app purge-audit --days 90
```

Purge targets: `api.secret_audit`, `api.org_audit`, `private.login_failures`.

### Schedule a daily cron

Podman:

```cron
15 3 * * * podman exec secretserver_app_1 flask --app app purge-audit >> /var/log/secretserver-purge-audit.log 2>&1
```

Docker Compose:

```cron
15 3 * * * cd /path/to/secretserver && docker compose exec -T app flask --app app purge-audit >> /var/log/secretserver-purge-audit.log 2>&1
```

### OpenShift CronJob

Full manifest: [openshift-purge-audit-cronjob.yaml](../openshift-purge-audit-cronjob.yaml).

```bash
oc apply -f docs/openshift-purge-audit-cronjob.yaml
oc create job --from=cronjob/secretserver-purge-audit purge-audit-manual -n secretserver
oc logs job/purge-audit-manual -n secretserver
```

---

## Export

Global admins can export audit data from the **Auditing → Export & retention**
tab. Use this for compliance / external auditors.

---

## Related docs

- [deploy.md](deploy.md): purge cron setup
- [api.md](../dev/api.md): audit via API
