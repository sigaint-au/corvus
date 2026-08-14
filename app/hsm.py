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
from urllib.parse import unquote

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


def parse_pkcs11_url(url: str) -> dict:
    """Parse an RFC 7512 PKCS#11 URI into connection values.

    Format: ``pkcs11:token=...;object=...;slot-id=...?module-path=...&pin-source=...&pin-value=...``

    Returns a dict with keys ``module_path``, ``token_label``, ``kek_label``
    (the ``object`` segment), ``pin``, ``pin_set`` and ``slot_id``.

    Raises:
        ValueError: When ``module-path`` or ``token`` is missing.

    Example:
        >>> parse_pkcs11_url("pkcs11:token=t;object=k?module-path=/m.so&pin-value=1234")
        {'module_path': '/m.so', 'token_label': 't', 'kek_label': 'k', ...}
    """
    url = (url or "").strip()
    if not url.startswith("pkcs11:"):
        raise ValueError("PKCS#11 URL must start with pkcs11:")
    rest = url[len("pkcs11:"):]
    path, _, query = rest.partition("?")

    path_parts: dict[str, str] = {}
    for seg in path.split(";"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            path_parts[k.strip().lower()] = unquote(v.strip())
    query_parts: dict[str, str] = {}
    for seg in query.split("&"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            query_parts[k.strip().lower()] = unquote(v.strip())

    module_path = query_parts.get("module-path")
    if not module_path:
        raise ValueError("PKCS#11 URL missing module-path")
    token_label = path_parts.get("token")
    if not token_label:
        raise ValueError("PKCS#11 URL missing token")

    pin = None
    pin_source = query_parts.get("pin-source")
    pin_value = query_parts.get("pin-value")
    if pin_value is not None:
        pin = pin_value
    elif pin_source:
        with open(pin_source, "r", encoding="utf-8") as fh:
            pin = fh.read().strip()

    slot_id = (
        path_parts.get("slot-id")
        or path_parts.get("slotid")
        or query_parts.get("slot-id")
        or query_parts.get("slotid")
    )
    return {
        "module_path": module_path,
        "token_label": token_label,
        "kek_label": path_parts.get("object"),
        "pin": pin,
        "pin_set": bool(pin),
        "slot_id": slot_id,
    }


def redact_pkcs11_url(url: str) -> str:
    """Redact the PIN from a PKCS#11 URL for display.

    ``pin-value=...`` is masked (``pin-value=***``); ``pin-source`` paths are
    left untouched (they do not expose the PIN).

    Example:
        >>> redact_pkcs11_url("pkcs11:token=t?module-path=/m.so&pin-value=1234")
        'pkcs11:token=t?module-path=/m.so&pin-value=***'
    """
    import re

    return re.sub(r"(?i)(pin-value)=[^&;]*", r"\1=***", url or "")


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


def _session(rw: bool = True, pkcs11_url: str | None = None):
    """Open a PKCS#11 session (logged in).

    When ``pkcs11_url`` is given it is parsed and used for the module, token,
    and PIN; otherwise the global env-var config is used.
    """
    pkcs11 = _pkcs11()
    if pkcs11_url:
        parsed = parse_pkcs11_url(pkcs11_url)
        module = parsed["module_path"]
        token_label = parsed["token_label"]
        pin = parsed["pin"]
    else:
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
    """Create the AES-256 KEK at the configured label if missing.

    Idempotent — reuses an existing key with the same label.

    Example:
        >>> label = ensure_kek()
        >>> label == 'byok-kek'
        True
    """
    return generate_kek(kek_label())


def generate_kek(label: str, pkcs11_url: str | None = None) -> str:
    """Create an AES-256 KEK with ``label`` if missing; return the label.

    Used both for the initial KEK and for KEK rotation (new label). When
    ``pkcs11_url`` is given the KEK is created in that slot instead of the
    global config.

    Example:
        >>> generate_kek("byok-kek-2")
        'byok-kek-2'
    """
    pkcs11 = _pkcs11()
    with _session(rw=True, pkcs11_url=pkcs11_url) as session:
        key = _find_kek(session, pkcs11, label)
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
                    label=label,
                    store=True,
                    template=template,
                )
            except Exception:
                # Minimal template if WRAP attributes are rejected
                session.generate_key(
                    pkcs11.KeyType.AES,
                    256,
                    label=label,
                    store=True,
                    template={
                        pkcs11.Attribute.ENCRYPT: True,
                        pkcs11.Attribute.DECRYPT: True,
                        pkcs11.Attribute.SENSITIVE: True,
                    },
                )
            log.info("generated HSM KEK %r", label)
    return label


def delete_kek(label: str) -> None:
    """Delete a KEK by label (e.g. an old one after KEK rotation).

    Only safe once every project DEK stored under this KEK has been re-wrapped
    to a new KEK — otherwise those projects become unrecoverable.

    Example:
        >>> delete_kek("byok-kek-old")
    """
    pkcs11 = _pkcs11()
    with _session(rw=True) as session:
        for key in session.get_objects(
            {
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.LABEL: label,
            }
        ):
            key.destroy()
            log.info("deleted HSM KEK %r", label)


def kek_label() -> str:
    """Return the configured KEK label (used as ``kms_key_ref``)."""
    return _cfg()[3]


def _wrap_raw(key, pkcs11, raw: bytes) -> str:
    """Wrap raw key bytes with the given KEK object; return a prefixed blob."""
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
        ct = key.encrypt(raw, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv)
    except Exception as e:
        raise RuntimeError(f"HSM wrap failed: {e}") from e
    return base64.b64encode(_FMT_CBC + iv + ct).decode()


def _decode_wrapped_blob(wrapped: str) -> tuple[bytes, bytes]:
    """Return ``(fmt, rest)`` parsed from a wrapped-DEK base64 string."""
    try:
        blob = base64.b64decode(wrapped)
    except Exception as e:
        raise ValueError("invalid wrapped DEK encoding") from e
    if len(blob) < 2:
        raise ValueError("invalid wrapped DEK length")
    # Legacy blobs (no format prefix): iv(16) || ct(32) from early SoftHSM path.
    if blob[0] not in (_FMT_CBC[0], _FMT_KEY_WRAP[0]) and len(blob) == _IV_LEN + _RAW_DEK_LEN:
        return _FMT_CBC, blob
    return blob[:1], blob[1:]


def _unwrap_key(key, pkcs11, fmt: bytes, rest: bytes) -> bytes:
    """Decrypt a wrapped DEK's payload with the given KEK object."""
    if fmt == _FMT_KEY_WRAP:
        kw = getattr(pkcs11.Mechanism, "AES_KEY_WRAP", None)
        if kw is None:
            raise RuntimeError("AES_KEY_WRAP not supported by python-pkcs11")
        return key.decrypt(rest, mechanism=kw)
    if fmt == _FMT_CBC:
        if len(rest) != _IV_LEN + _RAW_DEK_LEN:
            raise ValueError("invalid CBC wrapped DEK length")
        iv, ct = rest[:_IV_LEN], rest[_IV_LEN:]
        return key.decrypt(ct, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv)
    raise ValueError("unknown wrapped DEK format")


def wrap_dek(dek: bytes, label: str | None = None) -> str:
    """Wrap a Fernet DEK with the HSM KEK; return base64 blob.

    ``dek`` may be a 44-byte Fernet key (preferred) or 32 raw bytes. Prefer
    AES key-wrap when the token supports it; otherwise AES-CBC + random IV.
    ``label`` selects the KEK (defaults to the configured label).

    Example:
        >>> from cryptography.fernet import Fernet
        >>> wrapped = wrap_dek(Fernet.generate_key())
        >>> isinstance(wrapped, str)
        True
    """
    raw = fernet_key_to_raw(dek)
    label = label or kek_label()
    pkcs11 = _pkcs11()
    with _session(rw=False) as session:
        key = _find_kek(session, pkcs11, label)
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek() first")
        return _wrap_raw(key, pkcs11, raw)


def unwrap_dek(wrapped: str, label: str | None = None) -> bytes:
    """Unwrap a DEK previously produced by :func:`wrap_dek` to a Fernet key.

    Returns 44-byte urlsafe-base64 key material suitable for ``Fernet(key)``.
    ``label`` selects the KEK (defaults to the configured label).

    Example:
        >>> k = Fernet.generate_key()
        >>> unwrap_dek(wrap_dek(k)) == k
        True
    """
    label = label or kek_label()
    fmt, rest = _decode_wrapped_blob(wrapped)
    pkcs11 = _pkcs11()
    with _session(rw=False) as session:
        key = _find_kek(session, pkcs11, label)
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek() first")
        try:
            raw = _unwrap_key(key, pkcs11, fmt, rest)
        except ValueError:
            raise
        except Exception as e:
            raise RuntimeError(f"HSM unwrap failed: {e}") from e
    if len(raw) != _RAW_DEK_LEN:
        raise ValueError(f"unwrapped DEK has length {len(raw)}, expected {_RAW_DEK_LEN}")
    return raw_to_fernet_key(raw)


# ── Slot-aware variants (named PKCS#11 URLs) ─────────────────────────────


def available_for_slot(pkcs11_url: str) -> bool:
    """Return True when the specified slot's token can be opened."""
    try:
        with _session(rw=False, pkcs11_url=pkcs11_url):
            return True
    except Exception as e:
        log.warning("HSM slot availability check failed: %s", e)
        return False


def status_for_slot(pkcs11_url: str) -> dict:
    """Return slot status in the same shape as :func:`status`."""
    c = parse_pkcs11_url(pkcs11_url)
    result = {
        "available": False,
        "module": c["module_path"],
        "token_label": c["token_label"],
        "kek_label": c["kek_label"],
        "pin_set": bool(c["pin"]),
        "error": None,
        "kek_exists": False,
    }
    if not c["pin"]:
        result["error"] = "Not configured (no PIN in URL)"
        return result
    if not os.path.exists(c["module_path"]):
        result["error"] = f"PKCS#11 module not found: {c['module_path']}"
        return result
    try:
        pkcs11 = _pkcs11()
        with _session(rw=False, pkcs11_url=pkcs11_url) as session:
            result["available"] = True
            result["kek_exists"] = (
                _find_kek(session, pkcs11, c["kek_label"]) is not None
            )
    except Exception as e:
        result["error"] = str(e)
    return result


def ensure_kek_for_slot(pkcs11_url: str) -> str:
    """Ensure the KEK exists in the specified slot; return its label."""
    label = parse_pkcs11_url(pkcs11_url)["kek_label"]
    return generate_kek(label, pkcs11_url=pkcs11_url)


def wrap_dek_for_slot(pkcs11_url: str, dek: bytes) -> tuple[str, str]:
    """Wrap a DEK in the specified slot; return ``(wrapped_blob, kek_label)``."""
    c = parse_pkcs11_url(pkcs11_url)
    raw = fernet_key_to_raw(dek)
    pkcs11 = _pkcs11()
    with _session(rw=False, pkcs11_url=pkcs11_url) as session:
        key = _find_kek(session, pkcs11, c["kek_label"])
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek_for_slot first")
        return _wrap_raw(key, pkcs11, raw), c["kek_label"]


def unwrap_dek_for_slot(pkcs11_url: str, wrapped: str, kek_label: str | None = None) -> bytes:
    """Unwrap a DEK with the KEK in the specified slot to a Fernet key."""
    c = parse_pkcs11_url(pkcs11_url)
    label = kek_label or c["kek_label"]
    fmt, rest = _decode_wrapped_blob(wrapped)
    pkcs11 = _pkcs11()
    with _session(rw=False, pkcs11_url=pkcs11_url) as session:
        key = _find_kek(session, pkcs11, label)
        if key is None:
            raise RuntimeError("HSM KEK not found; call ensure_kek_for_slot first")
        try:
            raw = _unwrap_key(key, pkcs11, fmt, rest)
        except ValueError:
            raise
        except Exception as e:
            raise RuntimeError(f"HSM unwrap failed: {e}") from e
    if len(raw) != _RAW_DEK_LEN:
        raise ValueError(f"unwrapped DEK has length {len(raw)}, expected {_RAW_DEK_LEN}")
    return raw_to_fernet_key(raw)


def wrap_dek_with_label(pkcs11_url: str, dek: bytes, kek_label: str) -> str:
    """Wrap a DEK in the specified slot using an explicit KEK label.

    Used for KEK rotation, where a freshly generated KEK (with a new label) must
    wrap the re-wrapped DEKs.
    """
    raw = fernet_key_to_raw(dek)
    pkcs11 = _pkcs11()
    with _session(rw=False, pkcs11_url=pkcs11_url) as session:
        key = _find_kek(session, pkcs11, kek_label)
        if key is None:
            raise RuntimeError("HSM KEK not found; generate it first")
        return _wrap_raw(key, pkcs11, raw)


def test_connection_for_slot(pkcs11_url: str) -> tuple[bool, str]:
    """Open a read-only session on the slot and check KEK existence."""
    try:
        c = parse_pkcs11_url(pkcs11_url)
        pkcs11 = _pkcs11()
        with _session(rw=False, pkcs11_url=pkcs11_url) as session:
            has = _find_kek(session, pkcs11, c["kek_label"]) is not None
        if not has:
            return False, "token reachable but KEK not present yet"
        return True, "connection OK; KEK present"
    except Exception as e:
        return False, str(e)


def status() -> dict:
    """Return HSM configuration and availability for the admin UI.

    Never exposes the PIN — only whether one is set. Reuses the cached
    :func:`available` check and short-circuits if the HSM is down (no extra
    session open).

    Example:
        >>> s = status()
        >>> s["available"] in (True, False)
        True
    """
    module, token_label, pin, kek_label = _cfg()
    result = {
        "available": False,
        "module": module,
        "token_label": token_label,
        "kek_label": kek_label,
        "pin_set": bool(pin),
        "error": None,
        "kek_exists": False,
    }
    if not pin:
        result["error"] = "Not configured (HSM_PIN not set)"
        return result
    if not os.path.exists(module):
        result["error"] = f"PKCS#11 module not found: {module}"
        return result
    if not available():
        result["error"] = "Could not connect to the HSM token (see app logs)"
        return result
    try:
        pkcs11 = _pkcs11()
        with _session(rw=False) as session:
            result["available"] = True
            result["kek_exists"] = _find_kek(session, pkcs11, result["kek_label"]) is not None
    except Exception as e:
        result["error"] = str(e)
    return result


def test_connection() -> tuple[bool, str]:
    """Verify the HSM token can be opened and the KEK is present.

    Non-destructive: does not create a KEK or write anything. Used by the
    "Test HSM connection" button in Server Settings.

    Example:
        >>> ok, msg = test_connection()
        >>> isinstance(ok, bool)
        True
    """
    try:
        pkcs11 = _pkcs11()
        with _session(rw=False) as session:
            has = _find_kek(session, pkcs11, kek_label()) is not None
        if not has:
            return False, "token reachable but KEK not present yet"
        return True, "connection OK; KEK present"
    except Exception as e:
        return False, str(e)


def test_roundtrip() -> tuple[bool, str]:
    """Perform a wrap/unwrap round-trip with a throwaway DEK.

    Verifies the full HSM path (token open, KEK presence, wrap, unwrap).
    Creates the KEK if missing, so prefer :func:`test_connection` for a
    read-only health check. Returns ``(ok, message)``.
    """
    from cryptography.fernet import Fernet

    try:
        ensure_kek()
        test_dek = Fernet.generate_key()
        wrapped = wrap_dek(test_dek)
        if unwrap_dek(wrapped) != test_dek:
            return False, "wrap/unwrap round-trip mismatch"
        return True, "wrap/unwrap round-trip succeeded"
    except Exception as e:
        return False, str(e)
