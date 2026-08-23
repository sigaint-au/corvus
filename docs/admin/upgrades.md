# Upgrades

Existing databases upgrade in place. Do **not** recreate the volume.

## Procedure

1. Back up the database before upgrading (see [backup.md](backup.md)).
2. Pull the new image and restart the stack:

   ```bash
   # or: docker compose pull && docker compose up -d
   scripts/restart.sh
   ```

3. On startup, `app/core/migrations.py` compares `db/migrations/NNNN_*.sql`
   against `private.schema_migrations` and applies any pending files in order.
   The `DATABASE_ADMIN_URL` superuser DSN is required for this.
4. Verify readiness and migration state:

   ```bash
   curl -fsS http://localhost:8080/readyz
   scripts/logs.sh   # look for migration lines from core.migrations
   ```

## How migrations work

- Fresh volumes are bootstrapped by `docker-entrypoint-initdb.d` running the
  complete squashed baseline `db/migrations/0001_init.sql`.
- Existing volumes skip that init and receive later `NNNN_*.sql` migrations
  at app startup, recorded in `private.schema_migrations`.
- Migrations are additive and forward-only; never edit a released migration
  file — add a new one instead.

## Rollback

Migrations are not reversible. To downgrade, restore the pre-upgrade backup
(see [backup.md](backup.md)) and run the previous image version.
