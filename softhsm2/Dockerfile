# SoftHSM2 token-initialiser container for local development.
#
# SoftHSM2 is a *library* (PKCS#11), not a network HSM: the app container loads
# libsofthsm2.so and reads the token directory. This container's job is to
# initialise the token (slot + PIN) into a shared volume that the app container
# also mounts, then stay alive to keep the volume attached.
FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc \
    && rm -rf /var/lib/apt/lists/*

COPY softhsm2/init.sh /init.sh
RUN chmod +x /init.sh

ENTRYPOINT ["/init.sh"]
