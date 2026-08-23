# Building and pushing container images

Build the Corvus container image and push it to a registry.
Every step is a **copy-paste code block**: replace the `…` placeholders.

---

## Image overview

| Image | Source | Build or pull? |
|-------|--------|----------------|
| **app** (`corvus`) | `Dockerfile` at repo root | **Build locally** (this guide) |
| Postgres | `docker.io/library/postgres:16-alpine` | Pulled (from `compose.yml`) |
| PostgREST | `docker.io/postgrest/postgrest:v12.2.3` | Pulled (from `compose.yml`) |
| Redis | `docker.io/library/redis:7-alpine` | Pulled (from `compose.yml`) |

Only the **app** image is built from this repo.

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
docker --version   # or: podman --version
```

---

## 2. Build the app image

```bash
# From the repo root (build context = .)
docker build -t corvus:latest .

# Tagged build (recommended)
docker build -t corvus:1.2.0 -t corvus:latest .

# Via Compose (builds + starts the stack)
docker compose up -d --build
```

Podman:

```bash
podman build -t corvus:latest .
podman-compose up -d --build
```

---

## 3. Verify the image

```bash
docker images | grep corvus

docker inspect corvus:latest \
  --format '{{.Config.User}} | {{.Config.Cmd}} | {{.Config.ExposedPorts}}'
# → 10001 | [gunicorn -b 0.0.0.0:8080 -w 2 --timeout 60 app:app] | map[8080/tcp:{}]

docker run --rm corvus:latest python -c "import app; print('ok')"
```

---

## 4. Tag & push to a registry

### Log in

```bash
docker login
# or GHCR:
echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin
# or Quay:
docker login quay.io
```

### Tag for your registry

```bash
# Docker Hub
docker tag corvus:1.2.0 <dockerhub-user>/corvus:1.2.0
docker tag corvus:latest <dockerhub-user>/corvus:latest

# GHCR
docker tag corvus:1.2.0 ghcr.io/<org>/corvus:1.2.0

# Quay
docker tag corvus:1.2.0 quay.io/<org>/corvus:1.2.0
```

### Push

```bash
docker push <registry>/<org>/corvus:1.2.0
docker push <registry>/<org>/corvus:latest
```

---

## 5. Multi-architecture builds

```bash
docker buildx create --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/<org>/corvus:1.2.0 \
  -t <registry>/<org>/corvus:latest \
  --push .
```

Podman / Buildah:

```bash
podman build \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/<org>/corvus:1.2.0 \
  -t <registry>/<org>/corvus:latest \
  --manifest corvus \
  .

podman manifest push --all corvus \
  docker://<registry>/<org>/corvus:latest
```

---

## 6. Kubernetes

See [deploy.md](../admin/deploy.md) for cluster deployment.

---

## Related docs

- [deploy.md](../admin/deploy.md): deployment
- [testing.md](testing.md): running tests
