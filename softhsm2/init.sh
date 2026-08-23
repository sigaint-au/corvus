#!/bin/sh
# Initialise a SoftHSM2 token for the corvus app, write a shared conf
# into the token volume, then keep the container alive so the volume stays
# mounted for the app container.
set -e

TOKEN_DIR="${SOFTHSM2_TOKEN_DIR:-/hsm/tokens}"
TOKEN_LABEL="${HSM_TOKEN_LABEL:-corvus}"
SO_PIN="${HSM_SO_PIN:-1234}"
USER_PIN="${HSM_PIN:-1234}"
# Conf lives on the shared volume so the app container can mount the same file.
CONF_PATH="${SOFTHSM2_CONF:-$TOKEN_DIR/softhsm2.conf}"

mkdir -p "$TOKEN_DIR"
# World-traversable so appuser (uid 10001) can reach the conf and token files.
chmod 755 "$TOKEN_DIR" 2>/dev/null || true
cat > "$CONF_PATH" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
export SOFTHSM2_CONF="$CONF_PATH"

# --init-token fails if the token already exists; treat as success.
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*$TOKEN_LABEL"; then
    echo "Initialising SoftHSM2 token '$TOKEN_LABEL'..."
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" --pin "$USER_PIN"
else
    echo "SoftHSM2 token '$TOKEN_LABEL' already initialised."
fi

# Ready marker for depends_on healthcheck / app readiness.
touch "$TOKEN_DIR/.ready"

# The app container runs as uid 10001; grant it read/write to the shared
# token directory so it can open the token and generate keys.
chown -R 10001:10001 "$TOKEN_DIR" 2>/dev/null || true
chmod 755 "$TOKEN_DIR" 2>/dev/null || true
chmod -R u+rwX,g+rX,o+rX "$TOKEN_DIR" 2>/dev/null || true
printf '%s\n' "$USER_PIN" > "$TOKEN_DIR/hsm-pin"
chown 10001:10001 "$TOKEN_DIR/hsm-pin" 2>/dev/null || true
chmod 600 "$TOKEN_DIR/hsm-pin"

echo "SoftHSM2 token ready; keeping container alive."
exec sleep infinity
