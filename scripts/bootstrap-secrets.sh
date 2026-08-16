#!/usr/bin/env bash
# bootstrap-secrets.sh — generate random Secrets for Secret Server and apply them.
#
# Usage:
#   scripts/bootstrap-secrets.sh                # uses current-context namespace
#   scripts/bootstrap-secrets.sh <namespace>    # explicit namespace
#
# The script is idempotent (kubectl apply). Re-running replaces each
# Secret with newly generated values. This DESTROYS any existing
# encryption keys (MASTER_KEY) and re-encryption is required:
#
#   kubectl -n "$NS" exec deploy/secretserver-app -- \
#     flask rekey-project-keys --old-master-key "$OLD_MASTER_KEY"
#
# Requires: kubectl + openssl + Python 3 (for secrets.token_urlsafe).
set -euo pipefail

NS="${1:-$(kubectl config view --minify --output jsonpath='{..namespace}' 2>/dev/null || echo default)}"
DB_USER="${DB_USER:-secretserver-app}"
PG_SUPERUSER="${PG_SUPERUSER:-postgres}"

gen() { python3 -c 'import secrets; print(secrets.token_urlsafe(48))'; }
genpw() { python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))'; }

# Check that the namespace exists; offer to create it.
if ! kubectl get namespace "$NS" >/dev/null 2>&1; then
  echo "namespace '$NS' does not exist; create it first:"
  echo "  kubectl create namespace $NS"
  exit 1
fi

# Generate values.
JWT=$(gen)
MASTER=$(gen)
SESSION=$(gen)
DB_PW=$(genpw)
SUPER_PW=$(genpw)
REDIS_PW=$(genpw)
REDIS_SENT_PW=$(genpw)

PG_SVC="secretserver-postgres-rw.${NS}.svc.cluster.local"
DB_URL="postgresql://${DB_USER}:${DB_PW}@${PG_SVC}:5432/secretserver"
ADMIN_URL="postgresql://${PG_SUPERUSER}:${SUPER_PW}@${PG_SVC}:5432/secretserver"
PGRST_URI="postgresql://${DB_USER}:${DB_PW}@${PG_SVC}:5432/secretserver"

echo "applying Secrets to namespace '$NS'..."

kubectl -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-app-secrets
  labels:
    app.kubernetes.io/part-of: secretserver
type: Opaque
stringData:
  DATABASE_URL: "$DB_URL"
  DATABASE_ADMIN_URL: "$ADMIN_URL"
  JWT_SECRET: "$JWT"
  MASTER_KEY: "$MASTER"
  SECRET_KEY: "$SESSION"
---
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-postgrest-secrets
  labels:
    app.kubernetes.io/part-of: secretserver
type: Opaque
stringData:
  PGRST_DB_URI: "$PGRST_URI"
  PGRST_JWT_SECRET: "$JWT"
---
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-postgres-superuser
  labels:
    app.kubernetes.io/part-of: secretserver
type: Opaque
stringData:
  username: "$PG_SUPERUSER"
  password: "$SUPER_PW"
---
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-postgres-authenticator
  labels:
    app.kubernetes.io/part-of: secretserver
type: Opaque
stringData:
  username: "$DB_USER"
  password: "$DB_PW"
---
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-redis-secrets
  labels:
    app.kubernetes.io/part-of: secretserver
type: Opaque
stringData:
  REDIS_PASSWORD: "$REDIS_PW"
  REDIS_SENTINEL_PASSWORD: "$REDIS_SENT_PW"
EOF

echo
echo "Secrets applied. Saved raw values to /tmp/secretserver-bootstrap.env for 1 minute:"
cat > /tmp/secretserver-bootstrap.env <<EOF
# Generated $(date -u +%FT%TZ) — saved because kubectl get secret -o yaml
# returns base64 only. Delete this file after recording MASTER_KEY
# somewhere durable (your password manager, sealed-secret, etc.).
export MASTER_KEY='$MASTER'
export JWT_SECRET='$JWT'
export SECRET_KEY='$SESSION'
export DB_APP_USER='$DB_USER'
export DB_APP_PASSWORD='$DB_PW'
export PG_SUPERUSER_PASSWORD='$SUPER_PW'
export REDIS_PASSWORD='$REDIS_PW'
export REDIS_SENTINEL_PASSWORD='$REDIS_SENT_PW'
EOF
chmod 600 /tmp/secretserver-bootstrap.env
( sleep 60 && rm -f /tmp/secretserver-bootstrap.env ) &
echo "  /tmp/secretserver-bootstrap.env (auto-deleted in 60s)"
echo
echo "BACK UP MASTER_KEY — losing it makes every encrypted secret unreadable."
