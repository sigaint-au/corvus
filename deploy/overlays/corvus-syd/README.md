# `corvus-syd` — example overlay

Worked example of deploying the **base** manifests onto a cluster that
already has operators (cert-manager, CloudNativePG) and does **not** want
the base's cluster-scoped objects (ClusterIssuer, PriorityClass, Namespace)
or full Redis Sentinel HA.

It is **not** a second source of truth for secrets. Image pull credentials
and `MASTER_KEY` stay as in-cluster Secrets you create yourself.

Use it by copying the directory and changing the rows in **What to change**.

```bash
cp -r deploy/overlays/corvus-syd deploy/overlays/my-cluster
```

## What this overlay assumes

- Namespace `corvus` already exists (Rancher/project-managed).
- [cert-manager](https://cert-manager.io/) ClusterIssuer `le-production` exists.
- [CloudNativePG](https://cloudnative-pg.io/) operator is installed (API 1.28-compatible Cluster spec).
- Ingress controller class `traefik`.
- Optional: Prometheus `PodMonitor` CRDs (base still emits them).
- Optional: a dockerconfig Secret named `quay-registry` if the app image is private.

It **drops** from base: ClusterIssuers, PriorityClass, the Namespace object,
default-deny NetworkPolicies, Redis Sentinel + failover controller, CNPG
ScheduledBackup.

It **keeps**: app + PostgREST Deployments, CNPG Cluster (2 instances),
one Redis replica with AOF, Ingress + Certificate, CronJobs, HPAs, PDBs.

## What to change

| File / field | Example value here | You set |
|--------------|--------------------|---------|
| `kustomization.yaml` → `namespace` | `corvus` | Target namespace |
| `kustomization.yaml` → `images[].newName` / `newTag` | `quay.io/sigaint/corvus` / `2026.8.23.1` | Registry and tag you built ([building.md](../../../docs/dev/building.md)) |
| `ingress-patch.yaml` | host `corvus.sigaint.au`, class `traefik`, issuer `le-production` | Your DNS name, IngressClass, cert-manager issuer |
| `certificate-patch.yaml` | same DNS + `le-production` | Must match Ingress TLS host |
| `global-admin-email.yaml` | `admin@sigaint.au` | Email that is promoted to global admin **once**, when that user exists and no admin exists yet. Empty string disables promotion. |
| `pull-secret-deploy.yaml` / `pull-secret-cronjob.yaml` | `imagePullSecrets: quay-registry` | Name of your pull Secret, or delete these patches if the image is public |
| `postgres-spec.yaml` | 2 instances, 10Gi, `ghcr.io/cloudnative-pg/postgresql:16` | Instance count, storage, Postgres image your operator supports |
| `app-replicas.yaml` / `postgrest-replicas.yaml` / `*-hpa.yaml` | 2 app / 1 PostgREST | Size of the web tier |
| `redis-replicas.yaml` | 1 | Keep 1 unless you restore Sentinel from base (then drop `delete-extras.yaml`) |

Do **not** put `MASTER_KEY`, DB passwords, or registry passwords in this
directory. Create those Secrets in the namespace first:

```bash
scripts/bootstrap-secrets.sh corvus
# or apply your own Opaque Secrets (see deploy/README.md)
```

If the app image is private:

```bash
kubectl -n corvus create secret docker-registry quay-registry \
  --docker-server=quay.io \
  --docker-username=… \
  --docker-password=…
```

## Deploy

```bash
# Render (no cluster required)
kubectl kustomize deploy/overlays/corvus-syd

# Diff against the live API
kubectl diff -k deploy/overlays/corvus-syd

kubectl apply -k deploy/overlays/corvus-syd
kubectl -n corvus wait --for=condition=Ready cluster/corvus-postgres --timeout=300s
kubectl -n corvus rollout status deploy/corvus-app --timeout=180s
```

App image upgrades: change `images[].newTag` in `kustomization.yaml` and
re-apply. The Deployment is `RollingUpdate` with `maxUnavailable: 0`.

## What the other patches mean

| File | Why it exists |
|------|----------------|
| `delete-cluster-scoped.yaml` | ClusterIssuer / PriorityClass / Namespace already exist or are not allowed. |
| `delete-netpol.yaml` | Base default-deny + component policies; this cluster skipped them. |
| `delete-extras.yaml` | No object-store backup credentials; no Sentinel (single Redis). |
| `postgres-spec.yaml` | Replaces the base Cluster spec with a 1.28-safe object (no fencing/podTemplate). |
| `drop-priority-class.yaml` | Base sets `priorityClassName: corvus-ha`; that CR is cluster-scoped and was deleted. |
| `drop-sts-maxsurge.yaml` | Redis StatefulSet rolling-update field not accepted on this API. |
| `redis-runtime.yaml` | Stock `redis:7.2-alpine` instead of Bitnami; `--requirepass` from the Redis Secret. |
| `redis-url.yaml` | App `REDIS_URL` points at `redis-master` with the password from that Secret. |
| `redis-svc-selector.yaml` | Service selector for a single-replica Redis (no Sentinel-driven master). |
| `postgrest-probe.yaml` | TCP readiness (PostgREST has no `/health` on `/`). |
| `app-pdb.yaml` | PDB minAvailable 1 with 2 app replicas. |

## After it is up

1. Register (or sign in) as `GLOBAL_ADMIN_EMAIL`.
2. Set **Administration → Server settings → General → Server URL** to the
   public HTTPS origin (no trailing slash).
3. Optional: [External Secrets](../../../docs/admin/external-secrets.md) in
   *other* namespaces, using a machine token from this app.
