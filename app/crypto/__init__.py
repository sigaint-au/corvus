"""AES-256-GCM encryption for secret values and sensitive settings.

FIPS-compliant building blocks: the app master key is derived from
``MASTER_KEY`` with HKDF-SHA256, and values are encrypted with AES-256-GCM
(authenticated encryption; the ``cryptography`` AESGCM primitive). Project
Bring-Your-Own-Key DEKs are raw 32-byte keys wrapped by the master key or an
HSM slot's KEK.

This package also hosts per-project BYOK key management (``project_keys``)
and external HSM integration (``hsm``). The public API of this module is
re-exported here so ``import crypto`` and ``from crypto import encrypt``
continue to work as before.
"""

import json
import logging
import os
from base64 import urlsafe_b64decode, urlsafe_b64encode
from functools import lru_cache
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import cache, db
from core.config import MASTER_KEY, REDIS_DEK_CACHE_TTL

log = logging.getLogger(__name__)
_REDIS_EPOCH_KEY = "secretserver:crypto:project-key:epoch"
_SLOT_EPOCH_KEY = "secretserver:crypto:hsm-slot:epoch"
_TOKEN_PREFIX = "gcm$"
_HKDF_INFO = b"secretserver#master-key#v1"
_AES_KEY_LEN = 32


def _cache_epoch(client) -> str:
    """Return the shared project-key cache epoch."""
    return client.get(_REDIS_EPOCH_KEY) or "0"


def sha256_hex(val: str) -> str:
    """Return the hex-encoded SHA-256 digest of a UTF-8 string.

    Used for tokens, PAT hashes, invite tokens, and other one-way digests.

    Args:
        val: Input string to hash. ``None`` or empty is treated as ``""``.

    Returns:
        Lowercase hex SHA-256 digest (64 characters).

    Example:
        >>> sha256_hex("pat_abc123")
        'e3b0c442...'  # 64-char hex string
        >>> len(sha256_hex("secret"))
        64
    """
    return sha256((val or "").encode("utf-8")).hexdigest()


def master_aes_key(master_key: str) -> bytes:
    """Derive a 32-byte AES-256 key from the master key string via HKDF-SHA256.

    Args:
        master_key: The ``MASTER_KEY`` secret string.

    Returns:
        32 raw key bytes for ``AESGCM``.

    Example:
        >>> key = master_aes_key("long-master-key")
        >>> len(key) == 32
        True
        >>> master_aes_key("long-master-key") == key  # deterministic
        True
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=_AES_KEY_LEN, salt=None, info=_HKDF_INFO)
    return hkdf.derive((master_key or "").encode("utf-8"))


@lru_cache(maxsize=1)
def _aes_key() -> bytes:
    """Return the process-cached AES-256 key derived from ``MASTER_KEY``."""
    return master_aes_key(MASTER_KEY)


def encrypt_with_key(key: bytes, val: str) -> str:
    """Encrypt a string with an explicit AES-256-GCM key (12-byte random nonce).

    Args:
        key: 32-byte AES key.
        val: Plaintext UTF-8 string.

    Returns:
        ``gcm$<base64(nonce || ciphertext || tag)>`` token.

    Example:
        >>> key = master_aes_key("k")
        >>> encrypt_with_key(key, "hello").startswith("gcm$")
        True
    """
    nonce = os.urandom(12)
    ct = AESGCM(bytes(key)).encrypt(nonce, (val or "").encode("utf-8"), None)
    return _TOKEN_PREFIX + urlsafe_b64encode(nonce + ct).decode()


def decrypt_with_key(key: bytes, token: str) -> str:
    """Decrypt a token produced by :func:`encrypt_with_key`.

    Raises:
        ValueError: If the token is malformed or fails GCM authentication
            (wrong key or corrupted ciphertext).

    Example:
        >>> key = master_aes_key("k")
        >>> decrypt_with_key(key, encrypt_with_key(key, "hello"))
        'hello'
    """
    if not token.startswith(_TOKEN_PREFIX):
        raise ValueError("Unknown token format — not an AES-GCM token")
    try:
        blob = urlsafe_b64decode(token[len(_TOKEN_PREFIX) :].encode())
        nonce, body = blob[:12], blob[12:]
        plain = AESGCM(bytes(key)).decrypt(nonce, body, None)
    except Exception as e:
        raise ValueError(
            "Cannot decrypt value — the encryption key does not match the key "
            "used when this was stored (or the ciphertext is corrupt)."
        ) from e
    return plain.decode("utf-8")


def encrypt(val: str) -> str:
    """Encrypt a plaintext string with the app master key (AES-256-GCM).

    Args:
        val: Plaintext UTF-8 string (e.g. secret value, SMTP password).

    Returns:
        ``gcm$`` token string, safe to store in the database.

    Example:
        >>> token = encrypt("db-password")
        >>> token.startswith("gcm$")
        True
        >>> decrypt(token)
        'db-password'
    """
    return encrypt_with_key(_aes_key(), val)


def decrypt(val: str) -> str:
    """Decrypt a token produced by :func:`encrypt` (master key).

    Args:
        val: ``gcm$`` token string previously returned by :func:`encrypt`.

    Returns:
        Original plaintext UTF-8 string.

    Raises:
        ValueError: If the token is corrupt or was encrypted with a different
            master key.

    Example:
        >>> decrypt(encrypt("hello"))
        'hello'
    """
    return decrypt_with_key(_aes_key(), val)


# ── Per-project Bring-Your-Own-Key (BYOK) ────────────────────────────────
# Each project may have a dedicated data-encryption key (DEK). The DEK is a
# random 32-byte AES key. For local keys it is wrapped by MASTER_KEY; for HSM
# keys the 32 raw
# bytes are wrapped by the HSM slot's KEK (see ``hsm.wrap_dek_for_slot``).
# Values encrypted with a project DEK carry ``crypto_provider='project'``;
# values encrypted with the app master key are ``'master'`` (legacy / non-BYOK).
# Resolution is cached in Redis and can be invalidated across replicas after
# key events. Redis contains the wrapped key row, never the unwrapped DEK.


def generate_project_key() -> bytes:
    """Return a new random 32-byte AES-256 data-encryption key (DEK).

    Example:
        >>> len(generate_project_key()) == 32
        True
    """
    return os.urandom(_AES_KEY_LEN)


def wrap_project_key(raw_key: bytes) -> str:
    """Wrap a raw DEK with MASTER_KEY so only the raw key is never stored.

    Example:
        >>> raw = generate_project_key()
        >>> unwrap_project_key(wrap_project_key(raw)) == raw
        True
    """
    return encrypt_with_key(_aes_key(), raw_key.decode("latin-1"))


def unwrap_project_key(key_enc: str) -> bytes:
    """Unwrap a project DEK stored via :func:`wrap_project_key`."""
    return decrypt_with_key(_aes_key(), key_enc).encode("latin-1")


def _project_key(project_id: str) -> dict | None:
    """Return the project's crypto-key row, or None when it has no key."""
    client = None
    cache_key = None
    try:
        client = cache.redis_client()
        if client is not None:
            epoch = _cache_epoch(client)
            cache_key = f"secretserver:crypto:project-key:{epoch}:{project_id}"
            cached = client.get(cache_key)
            if cached is not None:
                return json.loads(cached)
    except Exception as e:
        log.warning("project-key Redis cache read failed: %s", e)
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT key_enc, key_provider, kms_key_ref, hsm_slot_id
                FROM private.project_crypto_keys WHERE project_id = %s
                """,
                (str(project_id),),
            )
            row = cur.fetchone()
        row = dict(row) if row else None
        if client is not None and cache_key is not None and row is not None:
            try:
                client.setex(cache_key, REDIS_DEK_CACHE_TTL, json.dumps(row, default=str))
            except Exception as e:
                log.warning("project-key Redis cache write failed: %s", e)
        return row
    except Exception:
        # Key lookup is best-effort: when it fails (e.g. admin DSN unavailable,
        # table not migrated, or unit-test mocks) fall back to the master key.
        # In FIPS mode the fallback is forbidden (fail closed): a project that
        # owns an HSM/master DEK must not silently decrypt under a different key.
        from core import config

        if config.fips_enabled():
            raise
        return None


def _project_key_enc(project_id: str) -> str | None:
    """Return the wrapped project DEK string, or None when the project has no key."""
    row = _project_key(str(project_id))
    return row["key_enc"] if row else None


def _slot_url(slot_id: str) -> str | None:
    """Return a named HSM slot's PKCS#11 URL, or None when it cannot be read."""
    client = cache.redis_client()
    try:
        if client is not None:
            epoch = client.get(_SLOT_EPOCH_KEY) or "0"
        else:
            epoch = "0"
        key = f"secretserver:crypto:hsm-slot:{epoch}:{slot_id}"
        if client is not None:
            try:
                cached = client.get(key)
                if cached is not None:
                    return cached or None
            except Exception as e:
                log.warning("HSM slot Redis cache read failed: %s", e)
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT pkcs11_url FROM private.hsm_slots WHERE id = %s",
                (str(slot_id),),
            )
            row = cur.fetchone()
        value = row["pkcs11_url"] if row else ""
        if client is not None:
            try:
                client.setex(key, REDIS_DEK_CACHE_TTL, value)
            except Exception as e:
                log.warning("HSM slot Redis cache write failed: %s", e)
        return value or None
    except Exception as e:
        log.warning("HSM slot lookup failed: %s", e)
        return None


def slot_url(slot_id) -> str | None:
    """Public accessor for a named HSM slot's PKCS#11 URL (cached)."""
    return _slot_url(str(slot_id))


def clear_slot_url_cache() -> None:
    """Invalidate cached slot URLs across replicas."""
    client = cache.redis_client()
    try:
        if client is not None:
            client.incr(_SLOT_EPOCH_KEY)
    except Exception as e:
        log.warning("HSM slot Redis cache invalidation failed: %s", e)


def _dek_for(row: dict) -> bytes:
    """Unwrap the project DEK using its key_provider (master or HSM)."""
    if (row.get("key_provider") or "local") == "hsm":
        from crypto.hsm import unwrap_dek_for_slot

        slot_id = row.get("hsm_slot_id")
        if slot_id is None:
            raise RuntimeError("HSM project has no slot assigned")
        slot_url_val = _slot_url(str(slot_id))
        if slot_url_val is None:
            raise RuntimeError("HSM slot not found")
        return unwrap_dek_for_slot(slot_url_val, row["key_enc"], row.get("kms_key_ref"))
    return unwrap_project_key(row["key_enc"])


def project_dek(project_id) -> bytes | None:
    """Return the project's current DEK (raw 32-byte AES key), or None."""
    row = _project_key(str(project_id))
    return _dek_for(row) if row else None


def project_has_key(project_id) -> bool:
    """Return True when the project has a dedicated data-encryption key."""
    return _project_key(str(project_id)) is not None


def clear_project_key_cache() -> None:
    """Invalidate project-key rows for every replica via Redis."""
    # ponytail: Redis outage can leave old entries until TTL; use a DB-backed
    # generation or transactional outbox if cache invalidation must be durable.
    client = cache.redis_client()
    try:
        if client is not None:
            client.incr(_REDIS_EPOCH_KEY)
    except Exception as e:
        log.warning("project-key Redis cache invalidation failed: %s", e)
    clear_slot_url_cache()


def encrypt_for_project(project_id, value: str) -> tuple[str, str]:
    """Encrypt a secret value for a project.

    Uses the project's DEK when one exists (``crypto_provider='project'``),
    otherwise the app master key (``crypto_provider='master'``). The DEK may be
    master-wrapped or HSM-wrapped.

    Returns:
        Tuple ``(ciphertext, crypto_provider)`` for storage.

    Example:
        >>> import uuid
        >>> ct, provider = encrypt_for_project(str(uuid.uuid4()), "value")
        >>> provider in ("master", "project") and ct.startswith("gcm$")
        True
    """
    row = _project_key(str(project_id))
    if row is None:
        return encrypt_with_key(_aes_key(), value), "master"
    return encrypt_with_key(_dek_for(row), value), "project"


def decrypt_for_project(project_id, token: str, provider: str = "master") -> str:
    """Decrypt a secret value using this project's key (or the master fallback).

    Args:
        project_id: Owning project (used to resolve the DEK).
        provider: Row's ``crypto_provider`` — ``'project'`` uses the project
            key, anything else uses the master key.
    """
    try:
        if provider == "project":
            row = _project_key(str(project_id))
            if row is not None:
                return decrypt_with_key(_dek_for(row), token)
        return decrypt_with_key(_aes_key(), token)
    except RuntimeError as e:
        raise ValueError("HSM is unavailable; this secret cannot be decrypted right now.") from e
