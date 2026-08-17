# Building & Pushing Container Images

Build the Sigaint Secret Server container image and push it to a registry.
Every step is a **copy-paste code block** — replace the `…` placeholders.

---

## Image overview

| Image | Source | Build or pull? |
|-------|--------|----------------|
| **app** (`secretserver`) | `Dockerfile` at repo root | **Build locally** (this guide) |
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
docker build -t secretserver:latest .

# Tagged build (recommended)
docker build -t secretserver:1.2.0 -t secretserver:latest .

# Via Compose (builds + starts the stack)
docker compose up -d --build
```

Podman:

```bash
podman build -t secretserver:latest .
podman-compose up -d --build
```

---

## 3. Verify the image

```bash
docker images | grep secretserver

docker inspect secretserver:latest \
  --format '{{.Config.User}} | {{.Config.Cmd}} | {{.Config.ExposedPorts}}'
# → 10001 | [gunicorn -b 0.0.0.0:8080 -w 2 --timeout 60 app:app] | map[8080/tcp:{}]

docker run --rm secretserver:latest python -c "import app; print('ok')"
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
docker tag secretserver:1.2.0 <dockerhub-user>/secretserver:1.2.0
docker tag secretserver:latest <dockerhub-user>/secretserver:latest

# GHCR
docker tag secretserver:1.2.0 ghcr.io/<org>/secretserver:1.2.0

# Quay
docker tag secretserver:1.2.0 quay.io/<org>/secretserver:1.2.0
```

### Push

```bash
docker push <registry>/<org>/secretserver:1.2.0
docker push <registry>/<org>/secretserver:latest
```

---

## 5. Multi-architecture builds

```bash
docker buildx create --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/<org>/secretserver:1.2.0 \
  -t <registry>/<org>/secretserver:latest \
  --push .
```

Podman / Buildah:

```bash
podman build \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/<org>/secretserver:1.2.0 \
  -t <registry>/<org>/secretserver:latest \
  --manifest secretserver \
  .

podman manifest push --all secretserver \
  docker://<registry>/<org>/secretserver:latest
```

---

## 6. OpenShift

Use the internal registry and an ImageStream so Deployments can pull by tag.
See [deploy.md](../admin/deploy.md) for the full OpenShift setup.

---

## Related docs

- [deploy.md](../admin/deploy.md) — deployment
- [testing.md](testing.md) — running tests
