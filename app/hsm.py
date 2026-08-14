"""External HSM (SoftHSM2 / PKCS#11) integration for BYOK.

The HSM holds a single AES-256 key-encryption key (KEK). Project data-encryption
keys (DEKs, 32-byte Fernet keys) are wrapped with that KEK via AES-CBC — the
KEK never leaves the HSM, so ``MASTER_KEY`` is not in the DEK's trust path for
HSM-backed projects.

This module is a thin wrapper around ``python-pkcs11`` and is only exercised
when :func:`available` is true (``HSM_PIN`` set and the PKCS#11 module present).
Every entry point raises a clear ``RuntimeError`` when the HSM is unavailable
or a call fails, so callers can surface a useful message.

Developer note: the exact PKCS#11 calls here are written for SoftHSM2 2.6 with
``python-pkcs11`` 0.7 — see ``docs/dev/hsm.md``.
"""

from __future__ import annotations

import base64
import logging
import os

log = logging.getLogger(__name__)

# DEK is a 32-byte Fernet key (exactly two AES blocks) → no padding needed.
_DEK_LEN = 32
_IV_LEN = 16


def _cfg() -> tuple[str, str, str, str]:
    from config import HSM_KEK_LABEL, HSM_PIN, HSM_PKCS11_MODULE, HSM_TOKEN_LABEL

    return HSM_PKCS11_MODULE, HSM_TOKEN_LABEL, HSM_PIN, HSM_KEK_LABEL


def available() -> bool:
    """Return True when the HSM is configured and reachable at import time."""
    module, _token, pin, _kek = _cfg()
    return bool(pin) and os.path.exists(module)


def _pkcs11():
    try:
        import pkcs11
    except ImportError as e:
        raise RuntimeError("python-pkcs11 is not installed; cannot use the HSM") from e
    return pkcs11


def _session():
    """Open a PKCS#11 session on the configured token (logged in)."""
    pkcs11 = _pkcs11()
    module, token_label, pin, _kek = _cfg()
    try:
        lib = pkcs11.lib(module)
        token = lib.get_token(token_label=token_label)
        return token.open(user_pin=pin)
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
            session.generate_key(
                pkcs11.KeyType.AES,
                256,
                label=kek_label,
                store=True,
                encrypt=True,
                decrypt=True,
            )
            log.info("generated HSM KEK %r", kek_label)
    return kek_label


def kek_label() -> str:
    """Return the configured KEK label (used as ``kms_key_ref``)."""
    return _cfg()[3]


def wrap_dek(dek: bytes) -> str:
    """Wrap a 32-byte DEK with the HSM KEK (AES-CBC), returning base64(iv||ct).

    Example:
        >>> wrapped = wrap_dek(raw)
        >>> wrapped != raw
        True
    """
    if len(dek) != _DEK_LEN:
        raise ValueError(f"DEK must be {_DEK_LEN} bytes, got {len(dek)}")
    pkcs11 = _pkcs11()
    with _session() as session:
        key = _find_kek(session, pkcs11, kek_label())
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek() first")
        iv = os.urandom(_IV_LEN)
        try:
            ct = key.encrypt(dek, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv)
        except Exception as e:
            raise RuntimeError(f"HSM wrap failed: {e}") from e
    return base64.b64encode(iv + ct).decode()


def unwrap_dek(wrapped: str) -> bytes:
    """Unwrap a DEK previously produced by :func:`wrap_dek`.

    Example:
        >>> unwrap_dek(wrap_dek(raw)) == raw
        True
    """
    try:
        blob = base64.b64decode(wrapped)
    except Exception as e:
        raise ValueError("invalid wrapped DEK encoding") from e
    if len(blob) != _IV_LEN + _DEK_LEN:
        raise ValueError("invalid wrapped DEK length")
    iv, ct = blob[:_IV_LEN], blob[_IV_LEN:]
    pkcs11 = _pkcs11()
    with _session() as session:
        key = _find_kek(session, pkcs11, kek_label())
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek() first")
        try:
            return key.decrypt(ct, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv)
        except Exception as e:
            raise RuntimeError(f"HSM unwrap failed: {e}") from e
