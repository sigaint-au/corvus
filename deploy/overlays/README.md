# Overlays

An overlay is a kustomize directory that **includes `../../base` and patches
only what your cluster is different from the HA defaults**. You do not edit
`deploy/base/` for hostnames, replica counts, or ingress class.

| Overlay | Intent |
|---------|--------|
| [`prod/`](prod/) | Full HA: nginx ingress, Let's Encrypt, 5 app / 3 Postgres / 3 Redis+Sentinel. Placeholders (`corvus.example.com`). |
| [`staging/`](staging/) | Smaller replica counts, self-signed TLS, `ALLOW_INSECURE_DEFAULTS` for a disposable env. |
| [`corvus-syd/`](corvus-syd/) | **Worked example** of a small existing cluster (Traefik, cert-manager already installed, CNPG 1.28, single Redis, no cluster-scoped objects). See [corvus-syd/README.md](corvus-syd/README.md). |

Copy an overlay rather than mutating `prod/` in place:

```bash
cp -r deploy/overlays/corvus-syd deploy/overlays/my-cluster
# edit my-cluster (table in corvus-syd/README.md)
kubectl kustomize deploy/overlays/my-cluster | less
kubectl apply -k deploy/overlays/my-cluster
```

Bootstrap **Kubernetes Secrets** first (`scripts/bootstrap-secrets.sh <namespace>`).
Overlays never commit passwords, `MASTER_KEY`, or registry credentials.
See [../README.md](../README.md).
