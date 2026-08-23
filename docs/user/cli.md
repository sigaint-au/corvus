# CLI guide

A kubectl-style CLI for Corvus (`/eso/v1`). Python 3 stdlib only,
RHEL 9+.

---

## Install

```bash
sudo install -m 0755 corvus /usr/bin/corvus
# or build an RPM:
make rpm && sudo dnf install -y dist/corvus-cli-*.noarch.rpm
```

---

## Credentials

Env **or** `~/.config/corvus/config` (`0600`). **Env wins.**

| Env | Meaning |
|-----|---------|
| `SS_URL` | Base URL (no trailing slash) |
| `SS_TOKEN` | `ss_…` machine token **or** `pat_…` PAT |
| `SS_PROJECT` | Project UUID (`ss_…`) or UUID/name (`pat_…`) |
| `PID` | Alias for `SS_PROJECT` |

| Token | Project |
|-------|---------|
| `ss_…` | UUID only |
| `pat_…` | UUID or unique **name** |

```bash
# Machine token
corvus login \
  --url https://secrets.example.com \
  --token ss_… \
  --project 31a70875-7d6a-40a7-a315-751f8a7ee38f

# PAT (name ok)
corvus login \
  --url https://secrets.example.com \
  --token pat_… \
  --project ios-app

# Env-only (CI / no config file)
export SS_URL=https://secrets.example.com
export SS_TOKEN=ss_…   # do not commit
export SS_PROJECT=<uuid>
```

`configure` is an alias for `login`.

---

## Project

```bash
corvus project              # show current
corvus project ios-app      # switch (PAT: name; machine: UUID)
```

---

## List secrets (metadata only)

```bash
corvus get secrets
corvus get secrets -l api      # filter key/note/metadata
corvus get secrets -o json
```

Values are **not** listed (metadata only).

---

## Get one secret

```bash
corvus get secret API_KEY              # table (default)
corvus get secret API_KEY -o value     # scripts: value only
corvus get secret API_KEY -o json
corvus get secret API_KEY -o name
```

If the project/secret **requires approval**, a PAT `get` returns 403 until an
admin approves. Machine tokens (`ss_…`) are not gated.

---

## Reveal approval workflow

```bash
# Request access (PAT)
corvus reveal secret API_KEY --reason "debugging prod auth #1234"

# Approver (project admin / team owner, PAT)
corvus get requests
corvus approve <request-id> --minutes 15
# corvus deny <request-id>

# Then fetch the value
corvus get secret API_KEY -o value
```

`approve --minutes` must be one of: `15`, `60`, `240`, `1440`.

---

## Create / update

```bash
# History-safe (preferred)
printf '%s' "$NEW" | corvus apply secret API_KEY --from-file=-
corvus apply secret API_KEY --from-env=NEW_API_KEY
corvus apply secret API_KEY --from-file=./api.key

# Metadata only
corvus apply secret API_KEY --note 'rotated in CI'
corvus apply secret API_KEY --kind plain --expires-days 90 --from-env=V

# Avoid in interactive shells (lands in history):
# corvus apply secret API_KEY --value 'literal'
```

Aliases: `create`, `set` → `apply`. Success output **omits** the secret value.

---

## Delete

```bash
corvus delete secret API_KEY
```

Soft-delete (restorable in the UI trash).

---

## Other resources

```bash
corvus get projects
corvus get teams
corvus get members --team Platform
corvus create team Platform
corvus create project demo --team Platform
corvus create member alice@example.com --team Platform --role team-member
corvus get tokens
corvus create token ci --role service-write
corvus get trash
corvus restore trash <secret-id>
corvus get users              # global admin + PAT
corvus get audit --source org # global admin + PAT
corvus transfer team NAME --email user@x
```

---

## Output formats (`-o`)

| Flag | Use |
|------|-----|
| `table` | Human tables (**default**) |
| `json` | Pretty JSON |
| `value` | Plaintext only → scripts / `$(…)` |
| `name` | Resource name only |
| `wide` | Same as `table` |

---

## Shell scripts (keep secrets out of history)

1. Store `SS_TOKEN` in env/CI secrets or a `0600` config file, never in git.
2. Read with `-o value`.
3. Write with `--from-file=-` or `--from-env=…` (not `--value`).
4. Prefer `set -euo pipefail`.

```bash
#!/usr/bin/env bash
set -euo pipefail
export SS_URL=https://secrets.example.com
export SS_TOKEN="${SS_TOKEN:?}"        # from CI secret
export SS_PROJECT=<project-uuid>

# Read a value into an env var without exposing it in the shell history
DB_URL=$(corvus get secret DATABASE_URL -o value)
```

---

## Help

```bash
corvus help
corvus <command> --help
```

---

## Related docs

- [guide.md](guide.md): web UI guide
- [../admin/machine-tokens.md](../admin/machine-tokens.md): machine accounts
- [../admin/external-secrets.md](../admin/external-secrets.md): External Secrets Operator
- [../admin/authentication.md](../admin/authentication.md): auth flows
