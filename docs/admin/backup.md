# Backup & Restore

Secret values are **Fernet-encrypted** with `MASTER_KEY` and stored in
Postgres. To restore a working instance you need **both** the database and the
encryption/signing keys.

---

## What to back up

| Item | Why |
|------|-----|
| Postgres database | All tables incl. `api.secrets.value_enc` (ciphertext) |
| `MASTER_KEY` | Required to decrypt secret values |
| `JWT_SECRET` | Validates JWTs (PostgREST) |
| `SECRET_KEY` | Validates session cookies + TOTP recovery HMAC |

Store the three keys in a secrets manager (or encrypted vault), separate from
the database backup.

---

## Database backup

### Logical dump (pg_dump)

```bash
# Dump the whole database
pg_dump -h <db-host> -U <admin-user> -d secretserver \
  -Fc -f secretserver.dump

# Or plain SQL
pg_dump -h <db-host> -U <admin-user> -d secretserver -f secretserver.sql
```

### In-container (Compose)

```bash
podman exec <db-container> pg_dump -U postgres secretserver -Fc > secretserver.dump
```

### Scheduled

```cron
0 2 * * * pg_dump -h db -U postgres -Fc secretserver > /backups/secretserver-$(date +\%F).dump
```

Keep a retention policy (e.g. 30 daily, 12 monthly) and test restores
periodically.

---

## Restore

```bash
# Create the database if needed
createdb -h <db-host> -U <admin-user> secretserver

# Restore custom-format dump
pg_restore -h <db-host> -U <admin-user> -d secretserver --clean --if-exists secretserver.dump

# Or restore plain SQL
psql -h <db-host> -U <admin-user> -d secretserver -f secretserver.sql
```

After restoring, set the same `MASTER_KEY`, `JWT_SECRET`, and `SECRET_KEY` in
the app environment so existing ciphertext and tokens remain valid.

> `0001_init.sql` / `0002_rls_authz_hardening.sql` are for a **first** database init and fresh installs only.
> This branch uses a fresh-install-only squashed baseline; recreate the database
> before applying it and do not use it as an upgrade script for an existing DB.
> This branch is **fresh-install-only squash** — existing databases must be
> recreated; do **not** re-run the baseline migrations over a restored database.

---

## Verify a restore

1. Start the app against the restored DB with the original keys.
2. Log in as an existing user.
3. Reveal a known secret — it must decrypt correctly.
4. Confirm audit logs and access requests are present.

---

## Related docs

- [configuration.md](configuration.md) — env vars / keys
- [deploy.md](deploy.md) — deployment
