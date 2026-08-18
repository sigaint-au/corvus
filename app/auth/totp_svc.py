"""Per-user TOTP (2FA) and recovery codes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import struct
import time

import qrcode
import qrcode.image.svg

from core import db
from core.config import APP_NAME, SECRET_KEY
from core.settings_svc import branding, get_settings, truthy
from crypto import decrypt, encrypt

log = logging.getLogger(__name__)

RECOVERY_CODE_COUNT = 10
# 16 random bytes → 32 hex chars (128-bit); displayed as 8×4 groups
RECOVERY_CODE_BYTES = 16


class TotpStoreError(Exception):
    """TOTP state could not be read (fail closed — do not skip 2FA)."""


def enforce_global_admins() -> bool:
    """Return whether global admins are required to enroll TOTP.

    Args:
        None.

    Returns:
        True if the totp_enforce_global_admins setting is truthy.

    Example:
        >>> isinstance(enforce_global_admins(), bool)
        True
    """
    return truthy(get_settings().get("totp_enforce_global_admins", "false"))


def user_totp_row(user_id: str) -> dict | None:
    """Load user TOTP fields. Raises TotpStoreError on DB failure (never fail open).

    Args:
        user_id: UUID string of the user to load.

    Returns:
        Dict of user TOTP-related columns (id, email, name, is_global_admin,
        totp_secret_enc, totp_enabled_at), or None if the user does not exist.

    Raises:
        TotpStoreError: If the database cannot be queried (callers must fail closed).

    Example:
        >>> # row = user_totp_row(user_id)
        >>> # row is None or "totp_enabled_at" in row
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, name, is_global_admin,
                       totp_secret_enc, totp_enabled_at
                FROM private.users
                WHERE id = %s::uuid
                """,
                (str(user_id),),
            )
            return cur.fetchone()
    except Exception as e:
        log.exception("user_totp_row failed for %s", user_id)
        raise TotpStoreError("totp store unavailable") from e


def is_enabled(user_id: str) -> bool:
    """Return whether the user has TOTP fully enabled.

    Args:
        user_id: UUID string of the user.

    Returns:
        True if both totp_enabled_at and totp_secret_enc are set.

    Raises:
        TotpStoreError: Propagated from user_totp_row on store failure.

    Example:
        >>> # if is_enabled(uid):
        ... #     challenge = "verify"
    """
    row = user_totp_row(user_id)
    return bool(row and row.get("totp_enabled_at") and row.get("totp_secret_enc"))


def needs_challenge(user_id: str, is_global_admin: bool) -> str | None:
    """Decide post-password 2FA challenge type for a user.

    After password auth: return 'verify', 'enroll', or None.
    enroll = global admin must set up TOTP before using the app.
    Raises TotpStoreError if 2FA state cannot be determined (caller must block login).

    Args:
        user_id: UUID string of the authenticated user.
        is_global_admin: Whether the user is a global admin.

    Returns:
        "verify" if TOTP is already enabled; "enroll" if a global admin must
        set up TOTP under enforcement; None if no challenge is required.

    Raises:
        TotpStoreError: If TOTP state cannot be read (fail closed).

    Example:
        >>> # step = needs_challenge(uid, is_global_admin=False)
        >>> # step in (None, "verify", "enroll")
    """
    enabled = is_enabled(user_id)
    if enabled:
        return "verify"
    if is_global_admin and enforce_global_admins():
        return "enroll"
    return None


def _b32decode(secret: str) -> bytes:
    """Decode a base32 TOTP secret, tolerating missing padding."""
    raw = (secret or "").upper().rstrip("=")
    return base64.b32decode(raw + "=" * ((8 - len(raw) % 8) % 8))


def _totp_code(secret: str, counter: int) -> str:
    """RFC 6238 TOTP code (HMAC-SHA256, 6 digits, 30s period)."""
    digest = hmac.new(_b32decode(secret), struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def new_secret() -> str:
    """Generate a new random base32 TOTP secret (32 chars).

    Args:
        None.

    Returns:
        Base32-encoded secret string for authenticator apps.

    Example:
        >>> s = new_secret()
        >>> len(s) >= 32
        True
    """
    return base64.b32encode(os.urandom(32)).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, email: str) -> str:
    """Build an otpauth:// URI for authenticator apps.

    Args:
        secret: Base32 TOTP secret.
        email: Account label shown in the authenticator (falls back to "user").

    Returns:
        otpauth provisioning URI including issuer from branding/APP_NAME.

    Example:
        >>> uri = provisioning_uri(new_secret(), "a@b.com")
        >>> uri.startswith("otpauth://")
        True
    """
    from urllib.parse import quote

    issuer = branding().get("app_name") or APP_NAME
    label = quote(f"{issuer}:{email or 'user'}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
        "&algorithm=SHA256&digits=6&period=30"
    )


def qr_data_uri(uri: str) -> str:
    """SVG QR as data URI for authenticator apps.

    Args:
        uri: Content to encode (typically an otpauth provisioning URI).

    Returns:
        data:image/svg+xml;base64,... string embeddable in an <img> src.

    Example:
        >>> data = qr_data_uri("otpauth://totp/test?secret=ABC")
        >>> data.startswith("data:image/svg+xml;base64,")
        True
    """
    img = qrcode.make(
        uri,
        image_factory=qrcode.image.svg.SvgPathImage,
        box_size=6,
        border=2,
    )
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def verify_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code against a secret.

    Args:
        secret: Base32 TOTP secret.
        code: User-entered code (whitespace is stripped).

    Returns:
        True if the code is a valid 6-digit TOTP within a ±1 step window;
        False for missing/invalid input or verification errors.

    Example:
        >>> verify_code("", "123456")
        False
    """
    code = _normalize_totp(code)
    if not secret or not code or len(code) != 6 or not code.isdigit():
        return False
    try:
        step = int(time.time()) // 30
        for counter in (step - 1, step, step + 1):
            if hmac.compare_digest(_totp_code(secret, counter), code):
                return True
    except Exception:
        return False
    return False


def _normalize_totp(code: str) -> str:
    """Strip whitespace from a TOTP code string.

    Args:
        code: Raw user-entered TOTP code (may be None-like empty).

    Returns:
        Code with all whitespace removed, or empty string if falsy.

    Example:
        >>> _normalize_totp("12 34 56")
        '123456'
    """
    return "".join(ch for ch in (code or "") if not ch.isspace())


def _normalize_recovery(code: str) -> str:
    """Normalize a recovery code to lowercase hex digits only.

    Args:
        code: Raw recovery code (may include dashes/spaces).

    Returns:
        Lowercase hex string with all non-hex characters removed.

    Example:
        >>> _normalize_recovery("Ab-Cd")
        'abcd'
    """
    return re.sub(r"[^a-f0-9]", "", (code or "").lower())


def hash_recovery_code(code: str) -> str:
    """HMAC-SHA256 with SECRET_KEY so DB leaks alone are not offline-bruteforceable.

    Args:
        code: Plaintext recovery code (normalized before hashing).

    Returns:
        Hex digest of HMAC-SHA256(SECRET_KEY, normalized_code).

    Example:
        >>> h = hash_recovery_code("abcd")
        >>> len(h) == 64
        True
    """
    raw = _normalize_recovery(code)
    key = (SECRET_KEY or "secretstore").encode("utf-8")
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def recovery_hash_matches(code: str, stored: str) -> bool:
    """Constant-time compare of a recovery code against its stored HMAC-SHA256 hash.

    Args:
        code: User-entered recovery code.
        stored: Hash string from private.totp_recovery_codes.code_hash.

    Returns:
        True when the code hashes to ``stored``.

    Example:
        >>> recovery_hash_matches("x", "")
        False
    """
    if not stored:
        return False
    return hmac.compare_digest(hash_recovery_code(code), stored)


def generate_recovery_codes(n: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Generate human-readable recovery codes.

    Args:
        n: Number of codes to generate (default RECOVERY_CODE_COUNT).

    Returns:
        List of hyphen-grouped hex recovery codes (show once to the user).

    Example:
        >>> codes = generate_recovery_codes(2)
        >>> len(codes) == 2 and "-" in codes[0]
        True
    """
    codes = []
    for _ in range(n):
        h = secrets.token_hex(RECOVERY_CODE_BYTES)
        # Group as xxxx-xxxx-... for readability
        parts = [h[i : i + 4] for i in range(0, len(h), 4)]
        codes.append("-".join(parts))
    return codes


def enable(user_id: str, secret: str) -> list[str]:
    """Enable TOTP for user; replace recovery codes.

    Returns plaintext recovery codes (show once).

    Args:
        user_id: UUID string of the user enabling 2FA.
        secret: Base32 TOTP secret to encrypt and store.

    Returns:
        List of plaintext recovery codes (one-time display).

    Example:
        >>> # codes = enable(uid, new_secret())
        >>> # len(codes) == RECOVERY_CODE_COUNT
    """
    enc = encrypt(secret)
    codes = generate_recovery_codes()
    hashes = [hash_recovery_code(c) for c in codes]
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE private.users
            SET totp_secret_enc = %s, totp_enabled_at = now()
            WHERE id = %s::uuid
            """,
            (enc, str(user_id)),
        )
        cur.execute(
            "DELETE FROM private.totp_recovery_codes WHERE user_id = %s::uuid",
            (str(user_id),),
        )
        for h in hashes:
            cur.execute(
                """
                INSERT INTO private.totp_recovery_codes (user_id, code_hash)
                VALUES (%s::uuid, %s)
                """,
                (str(user_id), h),
            )
    return codes


def disable(user_id: str) -> None:
    """Disable TOTP and delete all recovery codes for a user.

    Args:
        user_id: UUID string of the user disabling 2FA.

    Returns:
        None.

    Example:
        >>> # disable(uid)
        >>> # is_enabled(uid)
        False
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE private.users
            SET totp_secret_enc = NULL, totp_enabled_at = NULL
            WHERE id = %s::uuid
            """,
            (str(user_id),),
        )
        cur.execute(
            "DELETE FROM private.totp_recovery_codes WHERE user_id = %s::uuid",
            (str(user_id),),
        )


def regenerate_recovery_codes(user_id: str) -> list[str]:
    """Replace all recovery codes for a user with a fresh set.

    Args:
        user_id: UUID string of the user whose codes to rotate.

    Returns:
        New plaintext recovery codes (show once; previous codes are invalid).

    Example:
        >>> # codes = regenerate_recovery_codes(uid)
        >>> # len(codes) == RECOVERY_CODE_COUNT
    """
    codes = generate_recovery_codes()
    hashes = [hash_recovery_code(c) for c in codes]
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM private.totp_recovery_codes WHERE user_id = %s::uuid",
            (str(user_id),),
        )
        for h in hashes:
            cur.execute(
                """
                INSERT INTO private.totp_recovery_codes (user_id, code_hash)
                VALUES (%s::uuid, %s)
                """,
                (str(user_id), h),
            )
    return codes


def recovery_codes_remaining(user_id: str) -> int:
    """Count unused recovery codes remaining for a user.

    Args:
        user_id: UUID string of the user.

    Returns:
        Number of unused recovery codes, or 0 on database error.

    Example:
        >>> n = recovery_codes_remaining("00000000-0000-0000-0000-000000000000")
        >>> n >= 0
        True
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) AS n FROM private.totp_recovery_codes
                WHERE user_id = %s::uuid AND used_at IS NULL
                """,
                (str(user_id),),
            )
            row = cur.fetchone()
            return int(row["n"]) if row else 0
    except Exception:
        return 0


def verify_user_code(user_id: str, code: str) -> tuple[bool, str]:
    """Verify TOTP or recovery code for an enabled user.

    Returns (ok, method) where method is 'totp', 'recovery', or ''.

    Args:
        user_id: UUID string of the user completing a 2FA challenge.
        code: User-entered TOTP (6 digits) or recovery code.

    Returns:
        Tuple (ok, method): (True, "totp") or (True, "recovery") on success;
        (False, "") if TOTP is not enabled, decrypt fails, or code is wrong.
        Successful recovery codes are marked used.

    Example:
        >>> ok, method = verify_user_code("00000000-0000-0000-0000-000000000000", "000000")
        >>> ok is False and method == ""
        True
    """
    row = user_totp_row(user_id)
    if not row or not row.get("totp_secret_enc") or not row.get("totp_enabled_at"):
        return False, ""
    try:
        secret = decrypt(row["totp_secret_enc"])
    except Exception:
        log.exception("totp decrypt failed")
        return False, ""

    totp_code = _normalize_totp(code)
    if len(totp_code) == 6 and totp_code.isdigit():
        if verify_code(secret, totp_code):
            return True, "totp"
        return False, ""

    # Recovery code path (new: 32 hex / 16 bytes; legacy: 8 hex / 4 bytes)
    raw = _normalize_recovery(code)
    if len(raw) not in (8, RECOVERY_CODE_BYTES * 2):
        return False, ""
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, code_hash FROM private.totp_recovery_codes
                WHERE user_id = %s::uuid AND used_at IS NULL
                """,
                (str(user_id),),
            )
            rows = cur.fetchall() or []
            hit = None
            for r in rows:
                if recovery_hash_matches(raw, r.get("code_hash") or ""):
                    hit = r
                    break
            if not hit:
                return False, ""
            cur.execute(
                """
                UPDATE private.totp_recovery_codes
                SET used_at = now()
                WHERE id = %s::uuid
                """,
                (str(hit["id"]),),
            )
            return True, "recovery"
    except Exception:
        log.exception("recovery code verify failed")
        return False, ""
