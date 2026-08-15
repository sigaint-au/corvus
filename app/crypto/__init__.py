"""Fernet encryption for secret values and sensitive settings.

This package also hosts per-project BYOK key management (``project_keys``)
and external HSM integration (``hsm``). The public API of this module is
re-exported here so ``import crypto`` and ``from crypto import encrypt``
continue to work as before.
"""
from base64 import urlsafe_b64encode
import json
import logging
from hashlib import sha256

from cryptography.fernet import Fernet

from core import cache, db
from core.config import MASTER_KEY, REDIS_DEK_CACHE_TTL

log = logging.getLogger(__name__)
_REDIS_EPOCH_KEY = "secretserver:crypto:project-key:epoch"
_SLOT_EPOCH_KEY = "secretserver:crypto:hsm-slot:epoch"
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


def fernet_for(master_key: str) -> Fernet:
    """Build a Fernet instance from a raw master key string.

    The key is SHA-256 of ``master_key``, then url-safe base64-encoded to
    satisfy Fernet's 32-byte key requirement.
    """
    key = urlsafe_b64encode(sha256(master_key.encode()).digest())
    return Fernet(key)


def _fernet() -> Fernet:
    """Build and cache the Fernet instance derived from ``MASTER_KEY``.

    Cached for process lifetime (see :func:`fernet_for` for an explicit key).
    """
    return fernet_for(MASTER_KEY)


def encrypt(val: str) -> str:
    """Encrypt a plaintext string with the app master key (Fernet).

    Args:
        val: Plaintext UTF-8 string to encrypt (e.g. secret value, SMTP password).

    Returns:
        Fernet token as a UTF-8 string (safe to store in the database).

    Example:
        >>> token = encrypt("db-password")
        >>> token.startswith("gAAAA")
        True
        >>> decrypt(token)
        'db-password'
    """
    return _fernet().encrypt(val.encode()).decode()


def decrypt(val: str) -> str:
    """Decrypt a Fernet token produced by :func:`encrypt`.

    Args:
        val: Fernet ciphertext string previously returned by :func:`encrypt`.

    Returns:
        Original plaintext UTF-8 string.

    Raises:
        ValueError: If the token is corrupt or was encrypted with a different
            master key (wraps cryptography InvalidToken for safer call sites).

    Example:
        >>> decrypt(encrypt("hello"))
        'hello'
    """
    from cryptography.fernet import InvalidToken

    try:
        return _fernet().decrypt(val.encode()).decode()
    except InvalidToken as e:
        raise ValueError(
            "Cannot decrypt secret value — MASTER_KEY does not match the key "
            "used when this secret was stored (or the ciphertext is corrupt)."
        ) from e


# ── Per-project Bring-Your-Own-Key (BYOK) ────────────────────────────────
# Each project may have a dedicated data-encryption key (DEK). The DEK is a
# random Fernet key (``Fernet.generate_key()``: 44-byte urlsafe-b64 of 32 raw
# bytes). For local keys it is wrapped by MASTER_KEY; for HSM keys the 32 raw
# bytes are wrapped by the HSM slot's KEK (see ``hsm.wrap_dek_for_slot``).
# Values encrypted with a project DEK carry ``crypto_provider='project'``;
# values encrypted with the app master key are ``'master'`` (legacy / non-BYOK).
# Resolution is cached in Redis and can be invalidated across replicas after
# key events. Redis contains the wrapped key row, never the unwrapped DEK.


def generate_project_key() -> bytes:
    """Return a new random Fernet data-encryption key (32-byte urlsafe)."""
    return Fernet.generate_key()


def wrap_project_key(raw_key: bytes) -> str:
    """Wrap a raw DEK with MASTER_KEY so only the raw key is never stored."""
    return _fernet().encrypt(raw_key).decode()


def unwrap_project_key(key_enc: str) -> bytes:
    """Unwrap a project DEK stored via :func:`wrap_project_key`."""
    return _fernet().decrypt(key_enc.encode())


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
        # The write path records crypto_provider='master' in that case, so the
        # row stays consistent and decryptable.
        return None


def _project_key_enc(project_id: str) -> str | None:
    """Return the wrapped project DEK string, or None when the project has no key."""
    row = _project_key(str(project_id))
    return row["key_enc"] if row else None


def _slot_url(slot_id: str) -> str | None:
    """Return a named HSM slot's PKCS#11 URL, or None when it cannot be read."""
    client = cache.redis_client()
    try:
        epoch = client.get(_SLOT_EPOCH_KEY) or "0" if client is not None else "0"
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
    """Return the project's current DEK (Fernet key material), or None."""
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
    """
    row = _project_key(str(project_id))
    if row is None:
        return _fernet().encrypt(value.encode()).decode(), "master"
    return Fernet(_dek_for(row)).encrypt(value.encode()).decode(), "project"


def decrypt_for_project(project_id, token: str, provider: str = "master") -> str:
    """Decrypt a secret value using this project's key (or the master fallback).

    Args:
        project_id: Owning project (used to resolve the DEK).
        provider: Row's ``crypto_provider`` — ``'project'`` uses the project
            key, anything else uses the master key.
    """
    from cryptography.fernet import InvalidToken

    try:
        if provider == "project":
            row = _project_key(str(project_id))
            if row is not None:
                return Fernet(_dek_for(row)).decrypt(token.encode()).decode()
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError(
            "Cannot decrypt secret value — the encryption key for this project "
            "does not match the key used when this secret was stored."
        ) from e
    except RuntimeError as e:
        raise ValueError(
            "HSM is unavailable; this secret cannot be decrypted right now."
        ) from e
