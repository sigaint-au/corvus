# Building & pushing container images

This guide covers building the Sigaint Secret Server container images and
pushing them to a registry. Every step is a **copy-paste code block** —
replace the `…` placeholders with your own values.

## Image overview

| Image | Source | Build or pull? |
|-------|--------|----------------|
| **app** (`secretstore`) | `Dockerfile` at repo root | **Build locally** (this guide) |
| Postgres | `docker.io/library/postgres:16-alpine` | Pulled (from `compose.yml`) |
| PostgREST | `docker.io/postgrest/postgrest:v12.2.3` | Pulled (from `compose.yml`) |

Only the **app** image is built from this repo. Postgres and PostgREST are
pulled from their upstream registries.

### What the app image contains

- Base: `python:3.12-slim`
- Non-root runtime user `appuser` (uid `10001`)
- Python deps from `app/requirements.txt`
- The Flask app in `/app`
- Runs via `gunicorn` (2 workers, 60s timeout) on port `8080`
- **Build context = repo root** (because `compose.yml` uses `build: .`)

---

## 1. Prerequisites

```bash
# One of:
docker --version
podman --version

# Log in to your registry first (see section 4)
```

---

## 2. Build the app image

### 2a. Simple build (default tag)

```bash
# From the repo root (build context = .)
docker build -t secretstore:latest .
```

Podman:

```bash
podman build -t secretstore:latest .
```

### 2b. Tagged build (recommended)

Use a versioned tag plus `latest`:

```bash
docker build -t secretstore:1.2.0 -t secretstore:latest .
```

### 2c. Build via Compose

`compose.yml` already defines the app build context. This builds (or rebuilds)
the app image and starts the stack:

```bash
docker compose up -d --build
```

Podman:

```bash
podman-compose up -d --build
```

---

## 3. Verify the image

```bash
# List images
docker images | grep secretstore

# Inspect the runtime user / entrypoint
docker inspect secretstore:latest \
  --format '{{.Config.User}} | {{.Config.Cmd}} | {{.Config.ExposedPorts}}'
# → 10001 | [gunicorn -b 0.0.0.0:8080 -w 2 --timeout 60 app:app] | map[8080/tcp:{}]

# Smoke test (run without a DB — it will fail to start cleanly, but confirms the image runs)
docker run --rm secretstore:latest python -c "import app; print('ok')"
```

---

## 4. Tag & push to a registry

### 4a. Log in

```bash
# Docker Hub
docker login

# GitHub Container Registry (GHCR)
echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin

# Quay.io
docker login quay.io
```

Podman uses the same commands (`podman login`).

### 4b. Tag for your registry

The tag must include the full registry path.

Docker Hub:

```bash
docker tag secretstore:1.2.0 <dockerhub-user>/secretstore:1.2.0
docker tag secretstore:latest <dockerhub-user>/secretstore:latest
```

GitHub Container Registry:

```bash
docker tag secretstore:1.2.0 ghcr.io/<org>/secretstore:1.2.0
docker tag secretstore:latest ghcr.io/<org>/secretstore:latest
```

Quay:

```bash
docker tag secretstore:1.2.0 quay.io/<org>/secretstore:1.2.0
docker tag secretstore:latest quay.io/<org>/secretstore:latest
```

### 4c. Push

```bash
docker push <registry>/<org>/secretstore:1.2.0
docker push <registry>/<org>/secretstore:latest
```

Podman:

```bash
podman push <registry>/<org>/secretstore:1.2.0
podman push <registry>/<org>/secretstore:latest
```

---

## 5. Multi-architecture builds

Build for `linux/amd64` and `linux/arm64` in one shot with BuildKit:

```bash
# Enable buildx
docker buildx create --use

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/<org>/secretstore:1.2.0 \
  -t <registry>/<org>/secretstore:latest \
  --push .
```

Podman / Buildah:

```bash
podman build \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/<org>/secretstore:1.2.0 \
  -t <registry>/<org>/secretstore:latest \
  --manifest secretstore \
  .

podman manifest push --all secretstore \
  docker://<registry>/<org>/secretstore:latest
```

---

## 6. OpenShift

### 6a. BuildConfig + ImageStream (in-cluster build)

Use the internal registry and an ImageStream so Deployments can pull by tag:

```yaml
# docs/openshift-buildconfig.yaml — example
apiVersion: image.openshift.io/v1
kind: ImageStream
metadata:
  name: secretstore
  namespace: secretstore
---
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: secretstore
  namespace: secretstore
spec:
  source:
    type: Git
    git:
      uri: https://github.com/<org>/secretserver.git
      ref: main
  strategy:
    type: Docker
    dockerStrategy:
      dockerfilePath: Dockerfile
  output:
    to:
      kind: ImageStreamTag
      name: secretstore:latest
```

Apply and trigger a build:

```bash
oc apply -f docs/openshift-buildconfig.yaml
oc start-build secretstore
oc logs -f bc/secretstore
```

### 6b. Push to the OpenShift internal registry

If you build locally and push directly to the cluster registry:

```bash
# Get the internal registry route
oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}'

docker login -u $(oc whoami) -p $(oc whoami -t) \
  $(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')

docker tag secretstore:latest \
  image-registry.openshift-image-registry.svc:5000/secretstore/secretstore:latest

docker push image-registry.openshift-image-registry.svc:5000/secretstore/secretstore:latest
```

> The audit-purge CronJob example in
> [openshift-purge-audit-cronjob.yaml](./openshift-purge-audit-cronjob.yaml)
> references `image-registry.openshift-image-registry.svc:5000/secretstore/secretstore:latest`
> — update it to match your ImageStream.

---

## 7. Hardening & runtime notes

The app image and `compose.yml` already apply several hardening defaults you
should preserve when you build/push:

- **Non-root** runtime user (`appuser`, uid 10001) — never run as root.
- `compose.yml` sets `read_only: true`, drops all capabilities, and uses
  `no-new-privileges:true` for the app container.
- The app refuses to start with baked-in default secrets unless
  `ALLOW_INSECURE_DEFAULTS=1` / `FLASK_ENV=development`.

When you push to a registry:

- Use a **versioned tag** (never rely on `latest` alone for production).
- Sign / scan the image (e.g. `cosign sign`, `trivy image`) if your org requires it:

```bash
# Example: scan with Trivy
trivy image <registry>/<org>/secretstore:1.2.0

# Example: sign with Cosign (after pushing)
cosign sign <registry>/<org>/secretstore:1.2.0
```

---

## Layout

| Path | Role |
|------|------|
| `Dockerfile` | App image definition (build context = repo root) |
| `compose.yml` | Postgres + PostgREST + app (app built from `build: .`) |
| `app/requirements.txt` | Python dependencies installed into the image |
| `docs/building.md` | This file |
| `docs/deploy.md` | Deploy / run / env vars / OIDC / audit purge |
