"""Per-user TOTP (2FA) and recovery codes."""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import re
import secrets
from datetime import datetime, timezone

import pyotp
import qrcode
import qrcode.image.svg

from config import APP_NAME
from settings_svc import branding
from crypto import decrypt, encrypt
import db
from settings_svc import get_settings, truthy

log = logging.getLogger(__name__)

RECOVERY_CODE_COUNT = 10
# Display as xxxx-xxxx (8 hex chars)
RECOVERY_CODE_BYTES = 4


def enforce_global_admins() -> bool:
    return truthy(get_settings().get("totp_enforce_global_admins", "false"))


def user_totp_row(user_id: str) -> dict | None:
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
    except Exception:
        log.debug("user_totp_row failed", exc_info=True)
        return None


def is_enabled(user_id: str) -> bool:
    row = user_totp_row(user_id)
    return bool(row and row.get("totp_enabled_at") and row.get("totp_secret_enc"))


def needs_challenge(user_id: str, is_global_admin: bool) -> str | None:
    """
    After password auth: return 'verify', 'enroll', or None.
    enroll = global admin must set up TOTP before using the app.
    """
    enabled = is_enabled(user_id)
    if enabled:
        return "verify"
    if is_global_admin and enforce_global_admins():
        return "enroll"
    return None


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    totp = pyotp.TOTP(secret)
    issuer = branding().get("app_name") or APP_NAME
    return totp.provisioning_uri(name=email or "user", issuer_name=issuer)


def qr_data_uri(uri: str) -> str:
    """SVG QR as data URI for authenticator apps."""
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
    code = _normalize_totp(code)
    if not secret or not code or len(code) != 6 or not code.isdigit():
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


def _normalize_totp(code: str) -> str:
    return re.sub(r"\s+", "", code or "")


def _normalize_recovery(code: str) -> str:
    return re.sub(r"[^a-f0-9]", "", (code or "").lower())


def hash_recovery_code(code: str) -> str:
    raw = _normalize_recovery(code)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_recovery_codes(n: int = RECOVERY_CODE_COUNT) -> list[str]:
    codes = []
    for _ in range(n):
        h = secrets.token_hex(RECOVERY_CODE_BYTES)
        codes.append(f"{h[:4]}-{h[4:]}")
    return codes


def encrypt_secret(secret: str) -> str:
    return encrypt(secret)


def decrypt_secret(enc: str) -> str:
    return decrypt(enc)


def enable(user_id: str, secret: str) -> list[str]:
    """
    Enable TOTP for user; replace recovery codes.
    Returns plaintext recovery codes (show once).
    """
    enc = encrypt_secret(secret)
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
    """
    Verify TOTP or recovery code. Returns (ok, method) where method is
    'totp', 'recovery', or ''.
    """
    row = user_totp_row(user_id)
    if not row or not row.get("totp_secret_enc") or not row.get("totp_enabled_at"):
        return False, ""
    try:
        secret = decrypt_secret(row["totp_secret_enc"])
    except Exception:
        log.exception("totp decrypt failed")
        return False, ""

    totp_code = _normalize_totp(code)
    if len(totp_code) == 6 and totp_code.isdigit():
        if verify_code(secret, totp_code):
            return True, "totp"
        return False, ""

    # Recovery code path
    raw = _normalize_recovery(code)
    if len(raw) != RECOVERY_CODE_BYTES * 2:
        return False, ""
    ch = hash_recovery_code(raw)
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM private.totp_recovery_codes
                WHERE user_id = %s::uuid AND code_hash = %s AND used_at IS NULL
                LIMIT 1
                """,
                (str(user_id), ch),
            )
            hit = cur.fetchone()
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
