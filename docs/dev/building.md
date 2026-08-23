# Building and pushing container images

Build the Corvus app image and push it to Quay.

---

## Image overview

| Image | Source | Build or pull? |
|-------|--------|----------------|
| **app** (`quay.io/sigaint/corvus`) | `Dockerfile` at repo root | **Build and push** (`scripts/build.sh`) |
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
- **Build context = repo root**

---

## 1. Prerequisites

```bash
docker --version   # or: podman --version
podman login quay.io
# or: docker login quay.io
```

---

## 2. Build and push

```bash
scripts/build.sh
```

That builds the Dockerfile and pushes:

- `quay.io/sigaint/corvus:<version>` from `pyproject.toml` (for example `2026.8.23.1`)
- `quay.io/sigaint/corvus:latest`

It also tags `localhost/corvus_app:latest` for the local Compose stack.

Tag only, no registry:

```bash
scripts/build.sh --no-push
```

Overrides:

```bash
IMAGE_REPO=quay.io/sigaint/corvus TAG=2026.8.23.1 scripts/build.sh
```

---

## 3. Verify the image

```bash
podman images | grep sigaint/corvus
# or: docker images | grep sigaint/corvus

podman inspect quay.io/sigaint/corvus:latest \
  --format '{{.Config.User}} | {{.Config.Cmd}} | {{.Config.ExposedPorts}}'
# → 10001 | [gunicorn -b 0.0.0.0:8080 -w 2 --timeout 60 app:app] | map[8080/tcp:{}]

podman run --rm quay.io/sigaint/corvus:latest python -c "import app; print('ok')"
```

---

## 4. Local stack (no push)

```bash
scripts/up.sh          # compose build + start
# or: scripts/rebuild.sh
```

---

## 5. Multi-architecture builds

```bash
docker buildx create --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t quay.io/sigaint/corvus:2026.8.23.1 \
  -t quay.io/sigaint/corvus:latest \
  --push .
```

Podman / Buildah:

```bash
podman build \
  --platform linux/amd64,linux/arm64 \
  -t quay.io/sigaint/corvus:2026.8.23.1 \
  -t quay.io/sigaint/corvus:latest \
  --manifest corvus \
  .

podman manifest push --all corvus \
  docker://quay.io/sigaint/corvus:latest
```

---

## 6. Kubernetes

Point the overlay `images[].newName` / `newTag` at `quay.io/sigaint/corvus`
and the version you pushed. See [deploy.md](../admin/deploy.md) and
[corvus-syd overlay](https://git.sigaint.au/Sigaint/corvus/src/branch/main/deploy/overlays/corvus-syd/README.md).

---

## Related docs

- [deploy.md](../admin/deploy.md): deployment
- [testing.md](testing.md): running tests
