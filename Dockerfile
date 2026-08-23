# Red Hat UBI9-based image. Prod runtime is minimal (no shell toolchain,
# no SoftHSM); the `dev` target adds SoftHSM2/OpenSC for the local Compose
# HSM flow (see compose.yml and docs/dev/hsm.md).
FROM registry.access.redhat.com/ubi9/python-312 AS builder

# Toolchain only for compiling wheels without manylinux coverage
# (python-pkcs11). Nothing here reaches the runtime stage.
RUN microdnf install -y gcc gcc-c++ python3-devel \
    && microdnf clean all

WORKDIR /build
COPY app/requirements.txt .
RUN pip wheel --no-cache-dir -r requirements.txt -w /wheels

FROM registry.access.redhat.com/ubi9/python-312-minimal AS runtime

# Same uid/name as before so K8s securityContexts (runAsUser 10001) and
# Compose tmpfs mounts (/home/appuser) stay valid.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels \
    && chown -R appuser:appuser /app

COPY --chown=appuser:appuser app/ .

# Migration SQL (read by app/core/migrations.py at runtime)
COPY --chown=appuser:appuser db/migrations/ /db/migrations/

COPY --chown=appuser:appuser LICENSE THIRD_PARTY.md /app/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER appuser
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "--timeout", "60", "--graceful-timeout", "30", "--keep-alive", "5", "app:app"]

# Dev-only: SoftHSM2 lives in EPEL, not UBI — kept out of the prod image.
# libsofthsm2.so installs to /usr/lib64/softhsm/ on EL (Debian used /usr/lib).
FROM runtime AS dev
USER root
RUN rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
    && microdnf install -y softhsm2 opensc \
    && microdnf clean all
USER appuser

# Default target: prod.
FROM runtime
