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
pg_dump -h <db-host> -U <admin-user> -d secretstore \
  -Fc -f secretstore.dump

# Or plain SQL
pg_dump -h <db-host> -U <admin-user> -d secretstore -f secretstore.sql
```

### In-container (Compose)

```bash
podman exec <db-container> pg_dump -U postgres secretstore -Fc > secretstore.dump
```

### Scheduled

```cron
0 2 * * * pg_dump -h db -U postgres -Fc secretstore > /backups/secretstore-$(date +\%F).dump
```

Keep a retention policy (e.g. 30 daily, 12 monthly) and test restores
periodically.

---

## Restore

```bash
# Create the database if needed
createdb -h <db-host> -U <admin-user> secretstore

# Restore custom-format dump
pg_restore -h <db-host> -U <admin-user> -d secretstore --clean --if-exists secretstore.dump

# Or restore plain SQL
psql -h <db-host> -U <admin-user> -d secretstore -f secretstore.sql
```

After restoring, set the same `MASTER_KEY`, `JWT_SECRET`, and `SECRET_KEY` in
the app environment so existing ciphertext and tokens remain valid.

> `0001_init.sql` / `0002_rbac.sql` are only for a **first** database init.
> This branch uses a fresh-install-only squashed baseline; recreate the database
> before applying it and do not use it as an upgrade script for an existing DB.
> Existing databases are upgraded by `migrations.apply_pending()` at app
> startup — do **not** re-run the baseline migrations over a restored database.

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
