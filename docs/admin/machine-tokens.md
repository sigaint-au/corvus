# Machine accounts and ESO

Machine tokens (`ss_…`) let automation (CI, External Secrets Operator)
read and write secrets without a browser session.

---

## Roles

| Role | Metadata | Reveal values | Write |
|------|----------|---------------|-------|
| `service-read` | yes | no | no |
| `service-reveal` | yes | yes | no |
| `service-write` | yes | yes | yes |

- Prefer **`service-reveal`** for ESO pull and automation that needs values.
- Use **`service-write`** only if automation must create, rotate, or delete.

Tokens are **project-scoped** (a token only ever sees one project). The raw
`ss_…` value is shown once at creation; only a SHA-256 hash is stored.

---

## Create a token (UI)

Project → **Integrations** (or **Machine accounts**):

```text
Name: eso-prod
Role: service-reveal    (or service-write)
Expires (days): 90      (optional)
[Create machine account]
```

Copy the `ss_…` value immediately; it shows only this once.

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

> **Security note:** machine tokens bypass per-secret human role bindings and
> reveal-approval (they use SECURITY DEFINER helpers). Use a **key allow-list**
> or a **separate project** when automation must not see every secret in a
> shared project.

---

## ESO integration

The machine API is the External Secrets Operator **webhook** backend.

- **Pull** (`ExternalSecret`, `GET`) needs **`service-reveal`**.
- **Push** (`PushSecret`, `PUT`) needs **`service-write`** and a **second**
  SecretStore (a store’s HTTP method is shared).

Full setup, troubleshooting, and copy-paste YAML:
[external-secrets.md](external-secrets.md).

Samples: [eso-pull.yaml](../eso-pull.yaml) (pull),
[eso-push.yaml](../eso-push.yaml) (push).

Project → **Integrations** generates the pull token Secret + SecretStore. Add
the `ExternalSecret` `spec.data` keys yourself.

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

- [authentication.md](authentication.md): machine token auth flow and curl
- [cli.md](../user/cli.md): CLI usage
- [api.md](../dev/api.md): `/eso/v1` endpoint reference
- [external-secrets.md](external-secrets.md): ESO pull and push setup
- [eso-pull.yaml](../eso-pull.yaml): pull manifests
- [eso-push.yaml](../eso-push.yaml): push manifests
