"""External HSM (SoftHSM2 / PKCS#11) integration for BYOK.

The HSM holds a single AES-256 key-encryption key (KEK). Project data-encryption
keys (DEKs) are Fernet keys (urlsafe-base64 of 32 raw bytes, as produced by
``Fernet.generate_key()``). The 32 raw bytes are wrapped with the HSM KEK so
the KEK never leaves the HSM and ``MASTER_KEY`` is not on the DEK trust path.

Wrap order of preference:
1. ``AES_KEY_WRAP`` (RFC 3394) when the token supports it
2. ``AES_CBC`` with a random IV (SoftHSM2 always supports this)

Developer note: exercised with SoftHSM2 2.6 + ``python-pkcs11`` 0.7 —
see ``docs/dev/hsm.md``.
"""

from __future__ import annotations

import base64
import logging
import os
import time

log = logging.getLogger(__name__)

# Cached availability check (avoid opening a PKCS#11 session on every render).
_avail_cache: tuple[bool, float] | None = None
_AVAIL_TTL = 30.0

# Raw AES key material inside a Fernet key (before urlsafe-b64 encoding).
_RAW_DEK_LEN = 32
# Fernet.generate_key() length (urlsafe-b64 of 32 bytes).
_FERNET_KEY_LEN = 44
_IV_LEN = 16
# Blob version prefixes so unwrap can tell CBC from key-wrap.
_FMT_CBC = b"\x01"
_FMT_KEY_WRAP = b"\x02"


def _cfg() -> tuple[str, str, str, str]:
    from config import HSM_KEK_LABEL, HSM_PIN, HSM_PKCS11_MODULE, HSM_TOKEN_LABEL

    return HSM_PKCS11_MODULE, HSM_TOKEN_LABEL, HSM_PIN, HSM_KEK_LABEL


def available() -> bool:
    """Return True when HSM is configured and the token can be opened.

    Requires ``HSM_PIN``, a present PKCS#11 module, and a successful session
    open (so a missing/uninit token does not show HSM options in the UI).

    Result is cached for 30 seconds to avoid opening a PKCS#11 session on
    every page load.
    """
    global _avail_cache
    if _avail_cache and time.time() - _avail_cache[1] < _AVAIL_TTL:
        return _avail_cache[0]
    module, _token, pin, _kek = _cfg()
    if not pin or not os.path.exists(module):
        _avail_cache = (False, time.time())
        return False
    try:
        with _session():
            result = True
    except Exception as e:
        log.warning("HSM available() check failed: %s", e)
        result = False
    _avail_cache = (result, time.time())
    return result


def _pkcs11():
    try:
        import pkcs11
    except ImportError as e:
        raise RuntimeError("python-pkcs11 is not installed; cannot use the HSM") from e
    return pkcs11


def _session(rw: bool = True):
    """Open a PKCS#11 session on the configured token (logged in)."""
    pkcs11 = _pkcs11()
    module, token_label, pin, _kek = _cfg()
    try:
        lib = pkcs11.lib(module)
        token = lib.get_token(token_label=token_label)
        return token.open(user_pin=pin, rw=rw)
    except Exception as e:
        raise RuntimeError(f"HSM open failed: {e}") from e


def _find_kek(session, pkcs11, kek_label):
    """Return the KEK secret-key object by label, or None."""
    for obj in session.get_objects(
        {
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
            pkcs11.Attribute.LABEL: kek_label,
        }
    ):
        return obj
    return None


def fernet_key_to_raw(dek: bytes) -> bytes:
    """Normalize a Fernet key or raw 32-byte key to 32 raw bytes for wrapping.

    Accepts:
      - 44-byte ``Fernet.generate_key()`` material (urlsafe base64 of 32 bytes)
      - 32 raw key bytes
    """
    if not isinstance(dek, (bytes, bytearray)):
        raise TypeError("DEK must be bytes")
    if len(dek) == _RAW_DEK_LEN:
        return bytes(dek)
    if len(dek) == _FERNET_KEY_LEN:
        try:
            raw = base64.urlsafe_b64decode(dek)
        except Exception as e:
            raise ValueError("invalid Fernet DEK encoding") from e
        if len(raw) != _RAW_DEK_LEN:
            raise ValueError(
                f"Fernet DEK decoded to {len(raw)} bytes, expected {_RAW_DEK_LEN}"
            )
        return raw
    raise ValueError(
        f"DEK must be {_RAW_DEK_LEN} raw bytes or {_FERNET_KEY_LEN}-byte "
        f"Fernet key, got {len(dek)}"
    )


def raw_to_fernet_key(raw: bytes) -> bytes:
    """Encode 32 raw key bytes as a Fernet-compatible key."""
    if len(raw) != _RAW_DEK_LEN:
        raise ValueError(f"raw DEK must be {_RAW_DEK_LEN} bytes, got {len(raw)}")
    return base64.urlsafe_b64encode(raw)


def ensure_kek() -> str:
    """Create the AES-256 KEK in the HSM if missing; return its label.

    Idempotent — reuses an existing key with the same label.

    Example:
        >>> label = ensure_kek()
        >>> label == 'byok-kek'
        True
    """
    pkcs11 = _pkcs11()
    _module, _token, _pin, kek_label = _cfg()
    with _session() as session:
        key = _find_kek(session, pkcs11, kek_label)
        if key is None:
            # python-pkcs11 0.7: capabilities via Attribute template, not kwargs
            template = {
                pkcs11.Attribute.ENCRYPT: True,
                pkcs11.Attribute.DECRYPT: True,
                pkcs11.Attribute.WRAP: True,
                pkcs11.Attribute.UNWRAP: True,
                pkcs11.Attribute.SENSITIVE: True,
                pkcs11.Attribute.EXTRACTABLE: False,
            }
            try:
                session.generate_key(
                    pkcs11.KeyType.AES,
                    256,
                    label=kek_label,
                    store=True,
                    template=template,
                )
            except Exception:
                # Minimal template if WRAP attributes are rejected
                session.generate_key(
                    pkcs11.KeyType.AES,
                    256,
                    label=kek_label,
                    store=True,
                    template={
                        pkcs11.Attribute.ENCRYPT: True,
                        pkcs11.Attribute.DECRYPT: True,
                        pkcs11.Attribute.SENSITIVE: True,
                    },
                )
            log.info("generated HSM KEK %r", kek_label)
    return kek_label


def kek_label() -> str:
    """Return the configured KEK label (used as ``kms_key_ref``)."""
    return _cfg()[3]


def wrap_dek(dek: bytes) -> str:
    """Wrap a Fernet DEK with the HSM KEK; return base64 blob.

    ``dek`` may be a 44-byte Fernet key (preferred) or 32 raw bytes. Prefer
    AES key-wrap when the token supports it; otherwise AES-CBC + random IV.

    Example:
        >>> from cryptography.fernet import Fernet
        >>> wrapped = wrap_dek(Fernet.generate_key())
        >>> isinstance(wrapped, str)
        True
    """
    raw = fernet_key_to_raw(dek)
    pkcs11 = _pkcs11()
    with _session(rw=False) as session:
        key = _find_kek(session, pkcs11, kek_label())
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek() first")
        # Prefer authenticated AES key wrap when the module supports it.
        kw = getattr(pkcs11.Mechanism, "AES_KEY_WRAP", None)
        if kw is not None:
            try:
                ct = key.encrypt(raw, mechanism=kw)
                return base64.b64encode(_FMT_KEY_WRAP + ct).decode()
            except Exception as e:
                log.debug("AES_KEY_WRAP unavailable, falling back to CBC: %s", e)
        iv = os.urandom(_IV_LEN)
        try:
            ct = key.encrypt(
                raw, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv
            )
        except Exception as e:
            raise RuntimeError(f"HSM wrap failed: {e}") from e
    return base64.b64encode(_FMT_CBC + iv + ct).decode()


def unwrap_dek(wrapped: str) -> bytes:
    """Unwrap a DEK previously produced by :func:`wrap_dek` to a Fernet key.

    Returns 44-byte urlsafe-base64 key material suitable for ``Fernet(key)``.

    Example:
        >>> k = Fernet.generate_key()
        >>> unwrap_dek(wrap_dek(k)) == k
        True
    """
    try:
        blob = base64.b64decode(wrapped)
    except Exception as e:
        raise ValueError("invalid wrapped DEK encoding") from e
    if len(blob) < 2:
        raise ValueError("invalid wrapped DEK length")
    # Legacy blobs (no format prefix): iv(16) || ct(32) from early SoftHSM path
    if blob[0] not in (_FMT_CBC[0], _FMT_KEY_WRAP[0]) and len(blob) == _IV_LEN + _RAW_DEK_LEN:
        fmt, rest = _FMT_CBC, blob
    else:
        fmt, rest = blob[:1], blob[1:]
    pkcs11 = _pkcs11()
    with _session(rw=False) as session:
        key = _find_kek(session, pkcs11, kek_label())
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek() first")
        try:
            if fmt == _FMT_KEY_WRAP:
                kw = getattr(pkcs11.Mechanism, "AES_KEY_WRAP", None)
                if kw is None:
                    raise RuntimeError("AES_KEY_WRAP not supported by python-pkcs11")
                raw = key.decrypt(rest, mechanism=kw)
            elif fmt == _FMT_CBC:
                if len(rest) != _IV_LEN + _RAW_DEK_LEN:
                    raise ValueError("invalid CBC wrapped DEK length")
                iv, ct = rest[:_IV_LEN], rest[_IV_LEN:]
                raw = key.decrypt(
                    ct, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv
                )
            else:
                raise ValueError("unknown wrapped DEK format")
        except ValueError:
            raise
        except Exception as e:
            raise RuntimeError(f"HSM unwrap failed: {e}") from e
    if len(raw) != _RAW_DEK_LEN:
        raise ValueError(f"unwrapped DEK has length {len(raw)}, expected {_RAW_DEK_LEN}")
    return raw_to_fernet_key(raw)
