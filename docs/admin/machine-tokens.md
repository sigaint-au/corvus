# Machine Accounts & ESO

Machine tokens (`ss_…`) let automation (CI, OpenShift External Secrets
Operator) read and write secrets without a browser session.

---

## Roles

| Role | List / get | Create / update / delete |
|------|------------|---------------------------|
| `read-only` (default) | yes | **403** |
| `write` | yes | yes |

- Prefer **`read-only`** for ESO pull and read-only automation.
- Use **`write`** only if automation must create, rotate, or delete secrets.

Tokens are **project-scoped** (a token only ever sees one project). The raw
`ss_…` value is shown once at creation; only a SHA-256 hash is stored.

---

## Create a token (UI)

Project → **Integrations** (or **Machine accounts**):

```text
Name: openshift-prod
Role: read-only        (or write)
Expires (days): 90     (optional)
[Create machine account]
```

Copy the `ss_…` value immediately — it is shown once.

---

## Key allow-lists (limit what a token can read)

By default a token can read **every** secret in the project. To restrict it,
set a **key allow-list** on the token: exact secret keys and/or glob patterns.

| Pattern | Matches |
|----------|---------|
| `API_KEY` | exactly `API_KEY` |
| `prod/*` | `prod/db`, `prod/api-key`, … |
| `DB_*` | `DB_PASSWORD`, `DB_USER`, … |
| `?.api-key` | `a.api-key`, `b.api-key`, … |

Empty allow-list = **all** keys in the project. A scoped token gets
**404/empty** for keys outside its allow-list.

Create via the UI (**Key allow-list** on Machine accounts) or via the PAT API
body `scope: ["API_KEY", "prod/*"]`.

> **Security note:** machine tokens bypass per-secret human ACL modes and
> reveal-approval (they use SECURITY DEFINER helpers). Use a **key allow-list**
> or a **separate project** when automation must not see every secret in a
> shared project.

---

## ESO integration (OpenShift)

The machine API powers the External Secrets Operator webhook provider.

### 1. Create a read-only machine token

Project → **Integrations** → create a **read-only** token for the cluster.

### 2. Generate the manifests

On the **Integrations** tab, paste the token and set the base URL, namespace,
and resource name prefix. The UI generates the `Secret` + `SecretStore` YAML.

### 3. Apply in the cluster

```bash
oc apply -f generated-secretstore.yaml
```

Sample manifest: [openshift-eso.yaml](../openshift-eso.yaml).

The webhook URL is:

```text
{server_url}/eso/v1/projects/{project_id}/secrets/{key}
```

with `Authorization: Bearer {token}` and `jsonPath: $.value`.

---

## CLI / CI usage

```bash
export SS_URL=https://secrets.example.com
export SS_TOKEN=ss_…        # or pat_…
export SS_PROJECT=<project-uuid-or-name>
```

See [cli.md](../user/cli.md) and [authentication.md](authentication.md) for
full examples.

---

## Revocation

Delete a token in the UI (**Machine accounts** → **Revoke**). Revoked tokens
immediately fail `auth_machine`. Set an expiry on every token as a blast-radius
control; rotate tokens on a schedule.

---

## Related docs

- [authentication.md](authentication.md) — machine token auth flow and curl
- [cli.md](../user/cli.md) — CLI usage
- [api.md](../dev/api.md) — `/eso/v1` endpoint reference
- [openshift-eso.yaml](../openshift-eso.yaml) — sample ESO manifest
