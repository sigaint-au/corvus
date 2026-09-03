# Deprovisioning directory users

Corvus never deletes user rows. Offboarding runs through `flask sync-directory`,
which soft-disables (`disabled_at`) every LDAP/OIDC user missing from the
current directory roster.

## What disabling does

A disabled account is locked out everywhere, immediately:

| Surface | Enforcement |
|---------|-------------|
| Browser login (local, LDAP, OIDC, 2FA-pending) | `is_account_disabled` check + `disabled_at IS NULL` in `verify_user` |
| Personal access tokens | `resolve()` joins users with `disabled_at IS NULL` — existing PATs go inert |
| CLI session tokens | Same `disabled_at` check, **plus** rows are deleted by the job (no revoke flag exists) |
| Browser sessions | `revoked_at` set on all rows |
| Data access (incl. lingering role bindings) | `effective_access_rows` excludes disabled users, so RLS denies |

Directory re-login does **not** re-enable: neither `upsert_ldap_user` nor
`upsert_oidc_user` touches `disabled_at`.

Token handling is deliberately asymmetric, matching a manual admin disable:

- **PATs are kept.** They are user-managed credentials; re-enabling the account
  restores them. (Previously the job deleted them — unrecoverable.)
- **CLI session tokens are deleted.** They are ephemeral, always expire, and are
  re-issued on next CLI login.

## Roster sources

- `--source ldap` (default): live-fetch from the directory. Paged, so large
  directories are fully enumerated, and locked accounts count as departed:
  AD `userAccountControl` ACCOUNTDISABLE bit, `nsAccountLock`, and
  `pwdAccountLockedTime` are all treated as inactive.
- `--source oidc` (or `ldap,oidc`): requires `--active-email-file`, one address
  per line, `#` comments allowed. Malformed lines abort the run — a mangled
  file fails closed instead of half-matching.

## Safety guards

| Guard | Behavior | `--force` overrides? |
|-------|----------|----------------------|
| Empty roster | Refuse | Yes |
| Roster covers < 80% of known directory users (truncated/failed fetch) | Refuse | Yes |
| Would disable the last active global admin | Refuse | **No** |

If the last-admin guard blocks a legitimate teardown, promote a successor first,
or re-enable afterwards with SQL:
`UPDATE private.users SET disabled_at = NULL WHERE email = 'admin@example.com'`.

## Runbook

1. Dry-run first, every time:
   `flask --app app sync-directory --source ldap --dry-run`
2. Review `disabled=` and the `emails=[...]` list.
3. Run live: `flask --app app sync-directory --source ldap`
4. Verify in Administration → Audit (actor `sync-directory`, one
   `user_disabled` row per account) or in the container logs (one JSON line
   per account, shippable to a SIEM).

Result fields: `source`, `disabled`, `disabled_emails`, `revoked_sessions`,
`revoked_cli_tokens`. Note: `revoked_tokens` (deleted PATs) from older versions
is gone — PATs are preserved now.

## Scheduling

There is no in-app scheduler. Run at least daily — a leaver keeps access until
the job runs. Options:

- Kubernetes (default): `corvus-sync-directory` ships in `deploy/base/app`
  and runs daily at 02:30 UTC with `--source ldap` in every overlay.
  Suspend per site with
  `kubectl -n corvus patch cronjob corvus-sync-directory -p '{"spec":{"suspend":true}}'`.
- System cron on a host with the app environment:
  `30 2 * * * flask --app app sync-directory --source ldap`
- Standalone OpenShift example: `docs/openshift-sync-directory-cronjob.yaml`.
  OIDC/file rosters need the file mounted (e.g. a ConfigMap volume) and
  `--active-email-file /etc/corvus/active-emails.txt` added to the command.

## Re-enabling

Administration → Users → enable the account (writes `user_enabled` to the
audit log). The user gets a fresh session on next login; PATs resume; CLI
tokens must be re-issued.
