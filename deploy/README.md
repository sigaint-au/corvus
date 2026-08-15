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
- **External Secrets Operator** for every secret
  (MASTER_KEY / JWT_SECRET / SECRET_KEY / DB passwords / Redis
  passwords / backup credentials). No plaintext secrets in the tree.
- **cert-manager**-issued TLS for the ingress, HSTS enabled.
- **Default-deny** NetworkPolicy in the namespace; per-component
  policies open only the minimum required paths.
- **PodMonitor** for Prometheus scraping of every component.
- **Overlays** for prod and staging (different hostnames, replica counts,
  storage classes, secrets backends).

---

## Layout
```
deploy/
├── README.md                         # this file
├── base/                             # base composition (kustomize "base")
│   ├── kustomization.yaml            # composes all base resources
│   ├── namespace.yaml                # secretserver namespace + PSS labels
│   ├── rbac/                         # PriorityClass + ServiceAccounts + RBAC
│   ├── app/                          # Flask/gunicorn Deployment
│   ├── postgrest/                    # PostgREST Deployment
│   ├── postgres/                     # CloudNativePG Cluster + backups + NetPol
│   ├── redis/                        # Redis + Sentinel + failover controller
│   ├── external-secrets/             # ClusterSecretStore + ExternalSecrets
│   ├── ingress/                      # Ingress + Certificate + ClusterIssuer
│   └── networkpolicies/              # default-deny umbrella policy
└── overlays/
    ├── prod/                         # prod: 5 app / 2-6 postgrest / 3 pg / 3 redis
    └── staging/                      # staging: smaller counts, self-signed cert
```

| Component                                | Used for                              | Install                                                       |
| ---------------------------------------- | ------------------------------------- | ------------------------------------------------------------- |
| [CloudNativePG][cnpg]                    | HA Postgres                           | `kubectl apply -f cnpg-1.24.yaml` (from cnpg.io)              |
| [cert-manager][cm]                       | TLS for Ingress                       | `kubectl apply -f cert-manager-v1.15.yaml`                    |
| [nginx Ingress Controller][ing]          | Edge TLS / rate-limit                 | `helm install ingress-nginx ingress-nginx/ingress-nginx`      |
| [External Secrets Operator][eso]         | Vault → K8s Secret sync               | `helm install eso external-secrets/external-secrets`          |
| [Prometheus Operator][po]                | PodMonitor CRDs                       | `helm install prometheus prometheus-community/kube-prometheus`|

[cnpg]: https://cloudnative-pg.io/
[cm]: https://cert-manager.io/
[ing]: https://kubernetes.github.io/ingress-nginx/
[eso]: https://external-secrets.io/
[po]: https://prometheus-operator.dev/

Vault prerequisites (in your Vault cluster):

```bash
# 1. Enable K8s auth
vault auth enable kubernetes

# 2. Write the policy
cat <<'EOF' | vault policy write secretserver-app -
path "secret/data/secretserver/*" {
  capabilities = ["read"]
}
path "secret/metadata/secretserver/*" {
  capabilities = ["list"]
}
EOF

# 3. Bind the policy to a K8s role tied to the external-secrets-reader SA
vault write auth/kubernetes/role/secretserver-prod \
  bound_service_account_names=external-secrets-reader \
  bound_service_account_namespaces=secretserver \
  policies=secretserver-app \
  ttl=24h
```

Render the base without an overlay first (sanity check):

```bash
kustomize build deploy/base | less
```

Vault KV-v2 layout (the `secret/data/...` paths):

```
secret/data/secretserver/
├── app/
│   ├── database_url         # postgresql://authenticator:<pw>@<service>:5432/secretserver
│   ├── database_admin_url   # postgresql://postgres:<pw>@<service>:5432/secretserver
│   ├── jwt_secret           # 32+ random bytes
│   ├── master_key           # 32+ random bytes (Fernet)
│   └── secret_key           # Flask session signing key
├── postgrest/
│   ├── db_uri               # postgresql://authenticator:<pw>@<service>:5432/secretserver
│   └── jwt_secret           # matches app/jwt_secret
├── postgres/
│   ├── superuser_username   # postgres
│   ├── superuser_password   # random, ≥24 chars
│   ├── app_username         # secretserver-app
│   └── app_password         # random
├── redis/
│   ├── password             # 32+ chars
│   └── sentinel_password    # 32+ chars
└── postgres-backup/
    ├── aws_access_key_id
    ├── aws_secret_access_key
    ├── aws_region           # us-east-1
    ├── aws_endpoint         # optional (S3-compatible stores)
    └── aws_bucket           # secretserver-prod-pg-backups
```

> **The Cluster CR references `secretserver-postgres-superuser` for the
> bootstrap password.** Seed that Secret (or write it via ESO) **before**
> applying the Cluster. The Cluster will refuse to reconcile without it.

---

## Build / apply

### Build & diff locally

```bash
# Render prod overlay to stdout, pipe through kubeval if installed
kustomize build deploy/overlays/prod | less

# Server-side dry-run against a cluster
kubectl kustomize deploy/overlays/prod | \
  kubectl apply --dry-run=server -f -
```

### Apply prod

```bash
kubectl apply -k deploy/overlays/prod
```

Watch the rollout:

```bash
kubectl -n secretserver get pods -w
kubectl -n secretserver get cluster secretserver-postgres -w
kubectl -n secretserver get hpa secretserver-app -w
```

### Apply staging

```bash
kubectl create namespace secretserver-staging || true
kubectl apply -k deploy/overlays/staging
```

---

## HA characteristics

| Component       | Replicas | HA mechanism                                         |
| --------------- | -------- | ----------------------------------------------------- |
| App (Flask)     | 3 → 10   | HPA on CPU/mem + PDB minAvailable=2 + topology-spread |
| PostgREST       | 2 → 6    | HPA on CPU/mem + PDB minAvailable=1 + topology-spread |
| Postgres        | 3        | CloudNativePG sync-replication quorum + fencing       |
| Redis           | 3        | Sentinel quorum=2, AOF everysec                       |
| Redis Sentinel  | 3        | StatefulSet, anti-affinity hostname, quorum=2         |
| Redis failover  | 1 (ctrl) | Watches sentinel, patches Service selector            |
| Ingress         | n/a      | nginx ingress controller (cluster-managed HA)         |

Survives:

- ✅ Single node loss across replicas (`topologySpreadConstraints` +
  `podAntiAffinity`).
- ✅ Single Postgres primary failure (fencing + sync quorum: replicas
  auto-promote in <30s).
- ✅ Single Redis master failure (sentinel quorum elects a new master
  in <5s; controller patches the master Service).
- ✅ Rolling app deployments with zero downtime
  (`maxUnavailable: 0`).
- ✅ Voluntary disruptions (drains, autoscaler scale-down) blocked by
  PDB until safe.

---

## HSM integration (production)

The base manifests assume an **external PKCS#11 HSM** (AWS CloudHSM,
Azure Dedicated HSM, Thales Luna, etc.). The application stores slot
URLs in `private.hsm_slots` and resolves them at runtime; the operator's
responsibility is to make the PKCS#11 module reachable.

Common patterns:

- **Network-attached HSM**: open the HSM port (e.g. 1798) from the
  cluster's egress IP block. Patch the `app/deployment.yaml` egress
  NetworkPolicy to permit this CIDR.
- **CSI driver + Secrets Store CSI** (recommended for cloud HSMs):
  mount a CSI volume into the app pod containing the PKCS#11 module
  `.so` and pin-source file. Add a `volumeMount` to the app pod via
  overlay patch.
- **SoftHSM2 in dev only**: copy `softhsm2/Dockerfile` from this repo
  and add a StatefulSet + shared volume. **Never run SoftHSM2 in
  production** — it does not provide real key protection.

---

## Operations runbook

### Promote an admin (one-time)

```bash
kubectl -n secretserver exec -it deploy/secretserver-app -- \
  flask --app app:app promote-admin --email=ops@example.com
```

Or set `GLOBAL_ADMIN_EMAIL` in `deploy/app/configmap.yaml` overlay and
restart the Deployment; the next request from that account is promoted.

### Rotate MASTER_KEY

```bash
# 1. Set the new key in Vault:
#    secret/data/secretserver/app/master_key = <new value>
#
# 2. Force a refresh and rollout:
kubectl -n secretserver annotate externalsecret secretserver-app-secrets \
  force-sync=$(date +%s) --overwrite
kubectl -n secretserver rollout restart deploy/secretserver-app
#
# 3. After pods come back, re-wrap project DEKs:
kubectl -n secretserver exec deploy/secretserver-app -- \
  flask rekey-project-keys --old-master-key "$OLD_MASTER_KEY"
```

### Postgres failover (manual)

```bash
# Switch to a designated replica (no data loss):
kubectl -n secretserver cnpg promote secretserver-postgres \
  --target=secretserver-postgres-2
```

### Postgres restore (point-in-time)

```bash
# List available recovery targets:
kubectl -n secretserver cnpg status secretserver-postgres

# Restore to a target time using the latest base backup + WAL replay:
kubectl -n secretserver cnpg recovery secretserver-postgres \
  --source=secretserver-postgres-daily-YYYYMMDDHHMMSS \
  --target-time="2025-01-15 03:00:00 UTC"
```

### Redis failover verification

```bash
# Inside the cluster, point at the sentinel service:
kubectl -n secretserver exec deploy/redis-failover-controller -- \
  redis-cli -h redis-sentinel -p 26379 -a "$SENTINEL_PW" \
  SENTINEL get-master-addr-by-name secretserver-master

# Cordon a redis pod and watch sentinel elect a new master:
kubectl -n secretserver cordon <node-running-redis-0>
kubectl -n secretserver drain <node-running-redis-0> --ignore-errors
```

### Backup verification

```bash
# Check the daily backup ran:
kubectl -n secretserver get scheduledbackup secretserver-postgres-daily
kubectl -n secretserver get backup -l cnpg.io/cluster=secretserver-postgres

# Inspect a backup artifact:
kubectl -n secretserver describe backup secretserver-postgres-daily-YYYYMMDDHHMMSS
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
4. **Secrets rotation**: push the new value to Vault, annotate the
   ExternalSecret with `force-sync`, restart the consuming Deployment.

---

## Monitoring

PodMonitors scrape:

| Component      | Port | Path       |
| -------------- | ---- | ---------- |
| App            | 8080 | /healthz   |
| PostgREST      | 3000 | /metrics   |
| Postgres (cnpg)| 9187 | /metrics   |
| Redis          | 9121 | /metrics   |

Recommended Grafana dashboards:

- CNPG provided dashboard for Postgres (lag, WAL, replication slots).
- Redis exporter dashboard (hit rate, evictions, memory).
- Generic Flask/gunicorn: add `nginx-ingress` + `kube-state-metrics`
  panels for HTTP latency, request rate, pod restarts.

Alerts to start with:

- Postgres replication lag > 30s for 5m
- Postgres primary not ready > 2m
- Redis master unreachable from any sentinel > 30s
- App readiness failing > 50% of replicas > 5m
- HPA at maxReplicas for 10m (capacity-planning signal)
- ESO `ClusterSecretStoreReady=False` for 5m
- TLS cert expiry < 14 days

---

## Caveats and tradeoffs

- The kustomize `redis-failover-controller` is a deliberate
  alternative to the Spotahome Redis Operator. It is a 30-line shell
  loop that polls sentinel and patches Services. For higher-confidence
  deployments, **replace it with the Spotahome operator** (drop
  `deploy/redis/failover-controller.yaml` from the kustomization, add
  the operator Helm release, and let it manage the StatefulSet).
- The base `Cluster` uses `synchronous: quorum` — writes block until
  one replica acknowledges. This is **the safe HA setting**; for
  latency-critical workloads, switch to `mode: preferred` in the prod
  overlay.
- The app's `REDIS_URL` points at sentinel (`redis-sentinel:26379`).
  The current `app/core/cache.py` uses `redis.from_url(REDIS_URL)`
  which **does not** perform sentinel-aware discovery. Two options:
  1. Patch `cache.py` to use `redis.sentinel.Sentinel` (preferred).
  2. Change the overlay's `REDIS_URL` to `redis://redis-master:6379/0`
     and rely on the failover controller to keep the Service selector
     current.
- HSM is **not** deployed in the cluster — the deployment assumes an
  external PKCS#11 module (cloud HSM or hardware). See the HSM
  integration section above.
