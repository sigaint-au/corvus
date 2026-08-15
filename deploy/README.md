# `deploy/` — Kubernetes HA deployment (Kustomize)

Kustomize composition for a **highly-available** production deployment of
Secret Server. Designed around Kubernetes best practices:

- **Pod Security Standards `restricted`** at the namespace level
  (no privileged, no host namespaces, drop ALL caps, runAsNonRoot,
  seccompProfile=RuntimeDefault).
- **Stateless web tier** (`secretserver-app` + `secretserver-postgrest`)
  with HPA, anti-affinity, PodDisruptionBudget, topology-spread
  constraints.
- **Stateful tier** run by **CloudNativePG** (HA Postgres with synchronous
  replication, automatic failover, fencing, WAL streaming backups to S3).
- **HA Redis** via Sentinel (3 sentinels + 3 redis replicas, AOF
  persistence, automatic master promotion) with a kustomize-native
  failover controller (replaces the Spotahome operator pattern).
- **No external secret store** — this application *is* the secrets
  store for other systems, so its own bootstrap credentials live as
  ordinary Kubernetes Secrets created by the operator (see
  "Secrets bootstrap" below). No External Secrets Operator, no Vault.
- **cert-manager**-issued TLS for the ingress, HSTS enabled.
- **Default-deny** NetworkPolicy in the namespace; per-component
  policies open only the minimum required paths.
- **PodMonitor** for Prometheus scraping of stateful metrics.
- **Overlays** for prod and staging (different hostnames, replica counts,
  storage classes).

---

## Layout

```
deploy/
├── README.md                         # this file
├── base/                             # base composition (kustomize "base")
│   ├── kustomization.yaml            # composes all base resources
│   ├── namespace.yaml                # secretserver namespace + PSS labels
│   ├── rbac/                         # PriorityClass + ServiceAccounts + RBAC
│   ├── app/                          # Flask/gunicorn Deployment + HPA + PDB
│   ├── postgrest/                    # PostgREST Deployment + HPA + PDB
│   ├── postgres/                     # CloudNativePG Cluster + backups + NetPol
│   ├── redis/                        # Redis + Sentinel + failover controller
│   ├── secrets/                      # bootstrap-time Secret templates + README
│   ├── ingress/                      # Ingress + Certificate + ClusterIssuer
│   └── networkpolicies/              # default-deny umbrella policy
└── overlays/
    ├── prod/                         # prod: 5 app / 3 pg / 3 redis, SSD, Let's Encrypt
    └── staging/                      # staging: smaller counts, self-signed cert
```

---

## Cluster prerequisites

Install once per cluster:

| Component                         | Used for                       | Install                                                       |
| --------------------------------- | ------------------------------ | ------------------------------------------------------------- |
| [CloudNativePG][cnpg]             | HA Postgres                    | `kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/releases/cnpg-1.24.yaml` |
| [cert-manager][cm]                | TLS for Ingress                | `kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.0/cert-manager.yaml` |
| [nginx Ingress Controller][ing]   | Edge TLS / rate-limit          | `helm install ingress-nginx ingress-nginx/ingress-nginx`      |
| [Prometheus Operator][po]         | PodMonitor CRDs                | `helm install prometheus prometheus-community/kube-prometheus`|

[cnpg]: https://cloudnative-pg.io/
[cm]: https://cert-manager.io/
[ing]: https://kubernetes.github.io/ingress-nginx/
[po]: https://prometheus-operator.dev/

---

## Secrets bootstrap

This application acts as the external secrets store for *other*
systems. Its own bootstrap credentials are not pulled from any
external store — operators create plain Kubernetes `Opaque` Secrets
in the namespace before applying the workloads.

### Required Secrets

| Secret name                          | Consumed by          | Required keys                                              |
| ------------------------------------ | -------------------- | ---------------------------------------------------------- |
| `secretserver-app-secrets`           | app Deployment       | `DATABASE_URL`, `DATABASE_ADMIN_URL`, `JWT_SECRET`, `MASTER_KEY`, `SECRET_KEY` |
| `secretserver-postgrest-secrets`     | postgrest Deployment | `PGRST_DB_URI`, `PGRST_JWT_SECRET` (must match app's `JWT_SECRET`) |
| `secretserver-postgres-superuser`    | CNPG Cluster CR      | `username`, `password` — bootstraps the cluster            |
| `secretserver-postgres-authenticator`| CNPG Cluster CR      | `username`, `password` — application DB role               |
| `secretserver-redis-secrets`         | redis + sentinel     | `REDIS_PASSWORD`, `REDIS_SENTINEL_PASSWORD`                |
| `secretserver-postgres-backup` (opt) | CNPG ScheduledBackup | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_BUCKET` |

`deploy/base/secrets/secrets.example.yaml` ships structural templates
with empty `stringData:` blocks. **Do not apply it directly** — it is
a reference only.

### Recommended bootstrap path

```bash
# Generates random passwords (32-byte urlsafe-base64 for Fernet keys,
# 32-char alphanumeric for DB / Redis) and applies the Secrets.
scripts/bootstrap-secrets.sh secretserver
# or for staging:
scripts/bootstrap-secrets.sh secretserver-staging
```

The script dumps the generated values to `/tmp/secretserver-bootstrap.env`
(chmod 600, auto-deleted in 60s). **Back up `MASTER_KEY`** — losing it
makes every encrypted secret unrecoverable.

### Production / non-disposable environments

For environments where ephemeral secrets aren't acceptable, generate
values out-of-band and `kubectl apply` each Secret individually:

- Sealed Secrets (`kubeseal` against the cluster's pubkey).
- HashiCorp Vault with `vault kv put` then a sealed-secret wrapper.
- AWS / GCP / Azure Secrets Manager sync via CI/CD credential broker.

The cluster does not require any operator component to manage these
Secrets — `kubectl apply` of an `Opaque` Secret is sufficient.

### Key rotation rules

- `JWT_SECRET` in `secretserver-app-secrets` and `PGRST_JWT_SECRET` in
  `secretserver-postgrest-secrets` **must be equal**. A mismatch makes
  every PostgREST call 401.
- `MASTER_KEY` rotation requires running the re-wrapping CLI tool (see
  runbook below).
- DB password changes require updating both
  `secretserver-postgres-authenticator` and `DATABASE_URL` in
  `secretserver-app-secrets`.

---

## Build / apply

### Build & diff locally

```bash
# Render prod overlay to stdout
kubectl kustomize deploy/overlays/prod

# Diff against what's currently in the cluster
kubectl diff -k deploy/overlays/prod

# Dry-run validation against the live API
kubectl apply -k deploy/overlays/prod --dry-run=server
```

### Apply in order

```bash
# 1. Bootstrap secrets FIRST (workloads will fail to start without them)
scripts/bootstrap-secrets.sh secretserver

# 2. Apply the overlay
kubectl apply -k deploy/overlays/prod

# 3. Wait for database readiness
kubectl -n secretserver wait --for=condition=Ready cluster/secretserver-postgres --timeout=300s

# 4. Wait for app deployment
kubectl -n secretserver rollout status deploy/secretserver-app --timeout=180s
```

### Scheduled operational jobs

The base app kustomization creates two UTC CronJobs using the same image and
bootstrap Secret as the web Deployment:

- `secretserver-purge-audit` — daily at 03:45 UTC; uses the configured
  `audit_retention_days` setting (`0` keeps audit rows forever).
- `secretserver-notify-due` — daily at 08:00 UTC; emails global admins about
  due secrets, token expiry, and pending access approvals through SMTP settings.

Both jobs use `concurrencyPolicy: Forbid`, retain three successful and failed
Jobs, and stop after 15 minutes. Inspect or run a job manually:

```bash
kubectl -n secretserver get cronjob secretserver-purge-audit secretserver-notify-due
kubectl -n secretserver create job --from=cronjob/secretserver-purge-audit purge-audit-manual
kubectl -n secretserver logs -f job/purge-audit-manual
```

The staging overlay inherits these schedules under its own namespace.

---

## Operations runbook

### Initial admin promotion (one-time)

```bash
# 1. Set the email in the overlay configmap or pass via CLI:
kubectl -n secretserver exec deploy/secretserver-app -- \
  flask --app app:app promote-admin --email=ops@example.com

# 2. Or set GLOBAL_ADMIN_EMAIL in deploy/base/app/configmap.yaml and rollout restart:
kubectl -n secretserver rollout restart deploy/secretserver-app
```

### Rotate MASTER_KEY

```bash
# 1. Replace the MASTER_KEY value in secretserver-app-secrets.
kubectl -n secretserver patch secret secretserver-app-secrets \
  --type=json \
  -p '[{"op":"replace","path":"/data/MASTER_KEY","value":"'"$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))' | base64 -w0)"'"}]'

# 2. Roll the Deployment so new pods pick up the new key.
kubectl -n secretserver rollout restart deploy/secretserver-app

# 3. After pods come back, re-wrap project DEKs:
kubectl -n secretserver exec deploy/secretserver-app -- \
  flask rekey-project-keys --old-master-key "$OLD_MASTER_KEY"
```

### Rotate DB password

```bash
# 1. Generate a new password and update both Secrets.
NEW_PW=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))')
kubectl -n secretserver patch secret secretserver-postgres-authenticator \
  --type=json -p "[{\"op\":\"replace\",\"path\":\"/data/password\",\"value\":\"$(echo -n "$NEW_PW" | base64 -w0)\"}]"
kubectl -n secretserver patch secret secretserver-app-secrets \
  --type=json -p "[{\"op\":\"replace\",\"path\":\"/data/DATABASE_URL\",\"value\":\"$(echo -n "postgresql://secretserver-app:$NEW_PW@secretserver-postgres-rw:5432/secretserver" | base64 -w0)\"}]"

# 2. Roll the deployments so new pods connect with the new password.
kubectl -n secretserver rollout restart deploy/secretserver-app deploy/secretserver-postgrest
```

### Postgres failover (manual)

```bash
kubectl -n secretserver cnpg promote secretserver-postgres \
  --target=secretserver-postgres-2
```

### Postgres restore (point-in-time)

```bash
kubectl -n secretserver cnpg status secretserver-postgres

kubectl -n secretserver cnpg recovery secretserver-postgres \
  --source=secretserver-postgres-daily-YYYYMMDDHHMMSS \
  --target-time="2025-01-15 03:00:00 UTC"
```

### Redis failover verification

```bash
kubectl -n secretserver exec deploy/redis-failover-controller -- \
  redis-cli -h redis-sentinel -p 26379 -a "$SENTINEL_PW" \
  SENTINEL get-master-addr-by-name secretserver-master

kubectl -n secretserver cordon <node-running-redis-0>
kubectl -n secretserver drain <node-running-redis-0> --ignore-errors
```

### Backup verification

```bash
kubectl -n secretserver get scheduledbackup secretserver-postgres-daily
kubectl -n secretserver get backup -l cnpg.io/cluster=secretserver-postgres
```

---

## Upgrade procedure

1. **App image**: edit `deploy/overlays/prod/kustomization.yaml` →
   `images[].newTag`. Apply: `kubectl apply -k deploy/overlays/prod`.
   Rollout is `RollingUpdate` with `maxUnavailable: 0` — zero downtime.
2. **Postgres image / version**: edit the `Cluster.spec.imageName` tag
   in the overlay patch. The operator handles online minor-version
   upgrades automatically.
3. **Redis**: pin a new `bitnami/redis` tag in the overlay's
   `images:` block. StatefulSet `RollingUpdate` with `maxSurge: 0,
   maxUnavailable: 1` restarts one pod at a time.
4. **Secret rotation**: `kubectl patch secret` (see runbook above) or
   re-run `scripts/bootstrap-secrets.sh` — then roll the consuming
   Deployment.

---

## Monitoring

PodMonitors scrape Prometheus metrics endpoints:

| Component       | Port | Path       | Notes                                      |
| --------------- | ---- | ---------- | ------------------------------------------ |
| Postgres (cnpg) | 9187 | /metrics   | Native CloudNativePG Prometheus metrics    |
| Redis           | 9121 | /metrics   | redis-exporter sidecar                     |

Health endpoints:
- App: `/healthz` (liveness, 200 OK) and `/readyz` (readiness, DB check) on port 8080.
- PostgREST: HTTP health check on port 3000.

Alerts to start with:

- Postgres replication lag > 30s for 5m
- Postgres primary not ready > 2m
- Redis master unreachable from any sentinel > 30s
- App readiness failing > 50% of replicas > 5m
- HPA at maxReplicas for 10m (capacity-planning signal)
- TLS cert expiry < 14 days

---

## Caveats and tradeoffs

- The kustomize `redis-failover-controller` is a lightweight,
  kustomize-native alternative to the Spotahome Redis Operator. It is a
  shell loop that polls Sentinel and patches the `redis-master` Service
  selector. For higher-confidence deployments, **replace it with the
  Spotahome operator** (drop `deploy/redis/failover-controller.yaml`
  from the kustomization, add the operator Helm release, and let it
  manage the StatefulSet).
- The base `Cluster` uses `synchronous: quorum` — writes block until
  one replica acknowledges. This is **the safe HA setting**; for
  latency-critical workloads, switch to `mode: preferred` in the prod
  overlay.
- The app's `REDIS_URL` points at `redis-master:6379/0`. The
  `redis-failover-controller` dynamically maintains the `redis-master`
  Service selector to track the active master pod elected by Sentinel.
- HSM is **not** deployed in the cluster — the deployment assumes an
  external PKCS#11 module (cloud HSM or hardware). See the HSM
  integration section in `docs/` for details.
- Secrets bootstrap is operator-managed, not kustomize-managed. The
  `scripts/bootstrap-secrets.sh` helper writes Secrets into the
  namespace on demand; production environments should use sealed-secrets
  or a CI/CD credential broker instead.
