# Red Hat UBI9-based image. Prod runtime is minimal (no shell toolchain,
# no SoftHSM); the `dev` target adds SoftHSM for the local Compose HSM
# flow (see compose.yml and docs/dev/hsm.md).
FROM registry.access.redhat.com/ubi9/python-312 AS builder

# Image defaults to non-root; package installs need root.
USER root
# Toolchain only for compiling wheels without manylinux coverage
# (python-pkcs11). Nothing here reaches the runtime stage.
RUN dnf install -y gcc gcc-c++ python3-devel \
    && dnf clean all

WORKDIR /build
COPY app/requirements.txt .
RUN pip wheel --no-cache-dir -r requirements.txt -w /wheels

FROM registry.access.redhat.com/ubi9/python-312-minimal AS runtime

# Image defaults to non-root (uid 1001); user/pip setup needs root.
USER root
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

# Dev-only: SoftHSM is in RHEL AppStream, not UBI or EPEL 9. Pull the EL9
# package from AlmaLinux AppStream so local Compose can load
# /usr/lib64/libsofthsm2.so. Prod image stays without it.
FROM runtime AS dev
USER root
RUN rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9 \
    && cat > /etc/yum.repos.d/almalinux-appstream.repo <<'EOF'
[almalinux-appstream]
name=AlmaLinux 9 AppStream
baseurl=https://repo.almalinux.org/almalinux/9/AppStream/$basearch/os/
enabled=1
gpgcheck=1
gpgkey=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
EOF
RUN microdnf install -y softhsm \
    && microdnf clean all \
    && rm -f /etc/yum.repos.d/almalinux-appstream.repo
USER appuser

# Default target: prod.
FROM runtime
