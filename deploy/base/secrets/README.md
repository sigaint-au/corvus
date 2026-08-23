# `secrets/` — bootstrap-time Kubernetes Secrets

This directory ships **template manifests only**. The base kustomization
does not include any live Secret objects — operators bootstrap real
Secrets out-of-band before applying the workloads.

## Required Secret names

| Secret name                              | Consumed by          | Required keys                                                  |
| ---------------------------------------- | -------------------- | -------------------------------------------------------------- |
| `corvus-app-secrets`               | app Deployment       | `DATABASE_URL`, `DATABASE_ADMIN_URL`, `JWT_SECRET`, `MASTER_KEY`, `SECRET_KEY` |
| `corvus-postgrest-secrets`         | postgrest Deployment | `PGRST_DB_URI`, `PGRST_JWT_SECRET`                             |
| `corvus-postgres-superuser`        | CNPG Cluster CR      | `username`, `password` (boots the cluster)                     |
| `corvus-postgres-authenticator`    | CNPG Cluster CR      | `username`, `password` (application DB role)                   |
| `corvus-redis-secrets`             | redis + sentinel     | `REDIS_PASSWORD`, `REDIS_SENTINEL_PASSWORD`                    |
| `corvus-postgres-backup` (opt)     | CNPG ScheduledBackup | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_BUCKET` |

All values are plain `Opaque` Secrets. The Deployment manifests in
`deploy/base/app/` and `deploy/base/postgrest/` reference these names
via `env[].valueFrom.secretKeyRef`; the Pods will not start until
each Secret exists with the required keys.

## Bootstrap procedure

The recommended path is the helper script at the repo root:

```bash
scripts/bootstrap-secrets.sh            # writes Secrets to the current namespace
scripts/bootstrap-secrets.sh corvus   # specify a namespace
```

The script generates random passwords (32-byte urlsafe-base64, suitable
for Fernet-style wrapping) for every Secret listed above and `kubectl
apply`s them. Re-running is safe — it uses `kubectl apply` semantics.

For non-disposable environments (production), generate values out-of-band
(Sealed Secrets, HashiCorp Vault, AWS Secrets Manager sync, CI/CD
credential broker) and `kubectl apply` each Secret individually. Do
NOT commit real Secret values.

## Key generation rules

- `JWT_SECRET` / `PGRST_JWT_SECRET`: must match between `corvus-app-secrets`
  and `corvus-postgrest-secrets`. PostgREST verifies HS256 tokens
  with this value; a mismatch means every API call 401s.
- `MASTER_KEY`: 32+ random bytes (Fernet requires SHA-256 → 32 bytes →
  urlsafe-base64 → 44 bytes). Rotating it requires running
  `flask rekey-project-keys --old-master-key "$OLD"` afterward, or
  every project BYOK-wrapped DEK is unreadable.
- `SECRET_KEY`: Flask session signing key. 32+ bytes is fine.
- DB passwords: 24+ chars, random alphanumeric.
- Redis password + sentinel password: 32+ chars each, distinct.

## Master-key recovery

If `MASTER_KEY` is lost, every secret value encrypted with that key is
unrecoverable. Back up the Secret manifest itself (or its values) to
an out-of-band location — Kubernetes does not replicate Secrets to
etcd backups unless you configure encryption-at-rest for the API
server.
