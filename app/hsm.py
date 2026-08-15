"""External HSM (PKCS#11) integration for BYOK — named-slot only.

Each HSM is configured as a named slot (a PKCS#11 URL in ``private.hsm_slots``).
A slot's token holds an AES-256 key-encryption key (KEK); project
data-encryption keys (DEKs) are Fernet keys (urlsafe-base64 of 32 raw bytes)
wrapped by that KEK, so the KEK never leaves the HSM and ``MASTER_KEY`` is not
on the DEK trust path.

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
from urllib.parse import unquote

log = logging.getLogger(__name__)

# Raw AES key material inside a Fernet key (before urlsafe-b64 encoding).
_RAW_DEK_LEN = 32
# Fernet.generate_key() length (urlsafe-b64 of 32 bytes).
_FERNET_KEY_LEN = 44
_IV_LEN = 16
# Blob version prefixes so unwrap can tell CBC from key-wrap.
_FMT_CBC = b"\x01"
_FMT_KEY_WRAP = b"\x02"


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
        try:
            with open(pin_source, "r", encoding="utf-8") as fh:
                pin = fh.read().strip()
        except OSError as e:
            raise ValueError(f"Cannot read PIN file {pin_source}: {e}") from e

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


def has_inline_pin(url: str) -> bool:
    """Return True when the URL contains an inline ``pin-value=`` (not ``pin-source``).

    Used by the admin UI to warn that inline PINs are stored in the database.

    Example:
        >>> has_inline_pin("pkcs11:token=t?module-path=/m.so&pin-value=1234")
        True
        >>> has_inline_pin("pkcs11:token=t?module-path=/m.so&pin-source=/p")
        False
    """
    import re

    return bool(re.search(r"(?i)pin-value=", url or ""))


def _pkcs11():
    try:
        import pkcs11
    except ImportError as e:
        raise RuntimeError("python-pkcs11 is not installed; cannot use the HSM") from e
    return pkcs11


def _session(rw: bool, pkcs11_url: str):
    """Open a PKCS#11 session (logged in) against a named slot's PKCS#11 URL."""
    parsed = parse_pkcs11_url(pkcs11_url)
    pkcs11 = _pkcs11()
    try:
        lib = pkcs11.lib(parsed["module_path"])
        token = lib.get_token(token_label=parsed["token_label"])
        return token.open(user_pin=parsed["pin"], rw=rw)
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


def generate_kek(label: str, pkcs11_url: str) -> str:
    """Create an AES-256 KEK with ``label`` in a slot if missing.

    Used for the initial KEK and for KEK rotation (new label).

    Example:
        >>> generate_kek("byok-kek-2", "pkcs11:token=t;object=k?module-path=/m.so&pin-value=x")
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


def delete_kek(pkcs11_url: str, label: str) -> None:
    """Delete a KEK by label from a slot (e.g. an old one after KEK rotation).

    Only safe once every project DEK stored under this KEK has been re-wrapped
    to a new KEK — otherwise those projects become unrecoverable.

    Example:
        >>> delete_kek("pkcs11:token=t;object=k?module-path=/m.so&pin-value=x", "byok-kek-old")
    """
    pkcs11 = _pkcs11()
    with _session(rw=True, pkcs11_url=pkcs11_url) as session:
        for key in session.get_objects(
            {
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.LABEL: label,
            }
        ):
            key.destroy()
            log.info("deleted HSM KEK %r", label)


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


def available_for_slot(pkcs11_url: str) -> bool:
    """Return True when the specified slot's token can be opened."""
    try:
        with _session(rw=False, pkcs11_url=pkcs11_url):
            return True
    except Exception as e:
        log.warning("HSM slot availability check failed: %s", e)
        return False


def status_for_slot(pkcs11_url: str) -> dict:
    """Return slot status: module/token/KEK + availability + error."""
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
            return True, "token reachable, KEK not present (created on first use)"
        return True, "connection OK; KEK present"
    except Exception as e:
        return False, str(e)
