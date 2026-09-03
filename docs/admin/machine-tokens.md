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

- Default for a new token is **`service-read`**.
- Prefer **`service-reveal`** for ESO pull (pick it explicitly).
- Use **`service-write`** only if automation must create, rotate, or delete.

Only a **project admin** or **team-owner / team-admin** can create or revoke
tokens. Tokens are **project-scoped**. The raw `ss_…` value is shown once at
creation; only a SHA-256 hash is stored.

---

## Create a token (UI)

Project → **Integrations** (or **Machine accounts**):

```text
Name: eso-prod
Description: ESO pull for prod cluster   (optional, up to 500 chars)
Role: service-reveal    (default is service-read)
Expires (days): 90      (optional)
[Create machine account]
```

Copy the `ss_…` value immediately; it shows only this once. The description is
shown in the token list to tell tokens apart; it is never secret.

---

## Key allow-lists

A token only sees keys on its allow-list. No rows means **nothing**. Creating
a token with no list stores `*` (every **non-restricted** key).

| Pattern | Matches |
|----------|---------|
| `API_KEY` | exactly `API_KEY` |
| `prod/*` | `prod/db`, `prod/api-key`, … |
| `DB_*` | `DB_PASSWORD`, `DB_USER`, … |
| `*` | every inherit key in the project; **not** restricted secrets |
| `?.api-key` | `a.api-key`, `b.api-key`, … |

Secrets with `access_mode = restricted` need an **exact** key on the list.
Globs and `*` never open them. Keys outside the list return **404/empty**.

Create via the UI (Restrict keys) or the PAT API body
`scope: ["API_KEY", "prod/*"]`.

Put automation in its own project if the list would otherwise be most of
the vault.

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
