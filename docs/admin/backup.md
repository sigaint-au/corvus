# Backup and restore

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
pg_dump -h <db-host> -U <admin-user> -d corvus \
  -Fc -f corvus.dump

# Or plain SQL
pg_dump -h <db-host> -U <admin-user> -d corvus -f corvus.sql
```

### In-container (Compose)

```bash
podman exec <db-container> pg_dump -U postgres corvus -Fc > corvus.dump
```

### Scheduled

```cron
0 2 * * * pg_dump -h db -U postgres -Fc corvus > /backups/corvus-$(date +\%F).dump
```

Keep a retention policy (e.g. 30 daily, 12 monthly) and test restores
periodically.

---

## Restore

```bash
# Create the database if needed
createdb -h <db-host> -U <admin-user> corvus

# Restore custom-format dump
pg_restore -h <db-host> -U <admin-user> -d corvus --clean --if-exists corvus.dump

# Or restore plain SQL
psql -h <db-host> -U <admin-user> -d corvus -f corvus.sql
```

After restoring, set the same `MASTER_KEY`, `JWT_SECRET`, and `SECRET_KEY` in
the app environment so existing ciphertext and tokens remain valid.

> `0001_init.sql` is the fresh-install baseline (applied by
> `docker-entrypoint-initdb.d` on a first init only). Existing databases are
> upgraded in place by `app/core/migrations.py`, which applies pending
> `NNNN_*.sql` migrations at startup — never re-run baseline migrations over
> a restored database.

---

## Verify a restore

1. Start the app against the restored DB with the original keys.
2. Log in as an existing user.
3. Reveal a known secret; it must decrypt correctly.
4. Confirm audit logs and access requests are present.

---

## Related docs

- [configuration.md](configuration.md): env vars / keys
- [deploy.md](deploy.md): deployment
