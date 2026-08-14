#!/bin/sh
# Initialise a SoftHSM2 token for the secretserver app, then keep the container
# alive so the shared token directory stays mounted for the app container.
#
# The token lives in a shared volume (mounted at /var/lib/softhsm/tokens in both
# the softhsm2 and app containers). SOFTHSM2_CONF points at the volume so both
# containers agree on the token path.
set -e

TOKEN_DIR="${SOFTHSM2_CONF_DIR:-/var/lib/softhsm/tokens}"
TOKEN_LABEL="${HSM_TOKEN_LABEL:-secretserver}"
SO_PIN="${HSM_SO_PIN:-1234}"
USER_PIN="${HSM_PIN:-1234}"

mkdir -p "$TOKEN_DIR"
cat > "${SOFTHSM2_CONF:-/etc/softhsm/softhsm2.conf}" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

# --init-token is idempotent-ish: it fails if the token already exists.
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*$TOKEN_LABEL"; then
    echo "Initialising SoftHSM2 token '$TOKEN_LABEL'..."
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" --pin "$USER_PIN"
else
    echo "SoftHSM2 token '$TOKEN_LABEL' already initialised."
fi

# The app container runs as uid 10001; grant it read/write to the shared
# token directory so it can open the token and generate keys.
chown -R 10001:10001 "$TOKEN_DIR" 2>/dev/null || true

# Keep the container alive so the volume stays mounted and the token directory
# is shared with the app container.
echo "SoftHSM2 token ready; keeping container alive."
exec sleep infinity
