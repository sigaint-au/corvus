"""Per-project crypto key management (BYOK, local-key tier).

Each project may have a dedicated data-encryption key (DEK) stored wrapped by
the app MASTER_KEY in ``private.project_crypto_keys``. This module manages the
row lifecycle (create, adopt) and re-encrypts existing secrets onto the
project key. Key resolution itself lives in :mod:`crypto`.
"""

from __future__ import annotations

import logging

import crypto
import db

log = logging.getLogger(__name__)


def ensure_project_key(project_id, provider: str = "local") -> bool:
    """Create and store a project DEK if the project does not have one.

    ``provider`` is ``'local'`` (DEK wrapped by MASTER_KEY) or ``'hsm'`` (DEK
    wrapped by the HSM KEK). Idempotent; returns True when a new key was
    created.

    Example:
        >>> if ensure_project_key(pid):
        ...     # project now has a dedicated data-encryption key
        ...     pass
    """
    created = False
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM private.project_crypto_keys WHERE project_id = %s",
            (str(project_id),),
        )
        if not cur.fetchone():
            raw = crypto.generate_project_key()
            if provider == "hsm":
                import hsm

                hsm.ensure_kek()
                key_enc = hsm.wrap_dek(raw)
                kms_ref = hsm.kek_label()
            else:
                key_enc = crypto.wrap_project_key(raw)
                kms_ref = None
            cur.execute(
                """
                INSERT INTO private.project_crypto_keys
                  (project_id, key_enc, key_provider, kms_key_ref)
                VALUES (%s, %s, %s, %s)
                """,
                (str(project_id), key_enc, provider, kms_ref),
            )
            created = True
    crypto.clear_project_key_cache()
    return created


def project_crypto_status(project_id) -> dict | None:
    """Return the project's key row (provider, kms ref, created_at) or None.

    Example:
        >>> status = project_crypto_status(pid)
        >>> (status or {}).get("key_provider")
        'local'
    """
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id AS key_id, key_provider, kms_key_ref, created_at
                FROM private.project_crypto_keys
                WHERE project_id = %s
                """,
                (str(project_id),),
            )
            row = cur.fetchone()
        return dict(row) if row else None
    except Exception:
        return None


def count_master_rows(project_id) -> int:
    """Count secret rows still encrypted with the app master key."""
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  (SELECT count(*)::int FROM api.secrets
                    WHERE project_id = %s AND crypto_provider = 'master')
                + (SELECT count(*)::int FROM api.secret_versions v
                    JOIN api.secrets s ON s.id = v.secret_id
                    WHERE s.project_id = %s AND v.crypto_provider = 'master')
                  AS n
                """,
                (str(project_id), str(project_id)),
            )
            return int((cur.fetchone() or {}).get("n") or 0)
    except Exception:
        return 0


def adopt_project_key(project_id) -> int:
    """Re-encrypt all master-keyed secrets/versions into the project DEK.

    Creates the project key on demand. Runs in a single admin connection with a
    per-row ``try/except`` so one corrupt row cannot abort the whole batch;
    failed rows keep ``crypto_provider='master'`` and stay decryptable, so the
    run can be retried. Returns the number of rows re-encrypted.

    Example:
        >>> n = adopt_project_key(pid)
        >>> n >= 0
        True
    """
    ensure_project_key(project_id)
    re_encrypted = 0
    with db.connect_admin(autocommit=False) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, value_enc FROM api.secrets
            WHERE project_id = %s AND crypto_provider = 'master' AND deleted_at IS NULL
            """,
            (str(project_id),),
        )
        secret_rows = cur.fetchall() or []
        cur.execute(
            """
            SELECT v.id, v.value_enc FROM api.secret_versions v
            JOIN api.secrets s ON s.id = v.secret_id
            WHERE s.project_id = %s AND v.crypto_provider = 'master'
            """,
            (str(project_id),),
        )
        version_rows = cur.fetchall() or []
        for row in secret_rows:
            try:
                plaintext = crypto.decrypt(row["value_enc"])
                new_enc, _ = crypto.encrypt_for_project(project_id, plaintext)
            except Exception:
                continue
            cur.execute(
                "UPDATE api.secrets SET value_enc = %s, crypto_provider = 'project' "
                "WHERE id = %s",
                (new_enc, str(row["id"])),
            )
            re_encrypted += 1
        for row in version_rows:
            try:
                plaintext = crypto.decrypt(row["value_enc"])
                new_enc, _ = crypto.encrypt_for_project(project_id, plaintext)
            except Exception:
                continue
            cur.execute(
                "UPDATE api.secret_versions SET value_enc = %s, crypto_provider = 'project' "
                "WHERE id = %s",
                (new_enc, str(row["id"])),
            )
            re_encrypted += 1
        conn.commit()
    crypto.clear_project_key_cache()
    log.info("project key adopted: %s row(s) re-encrypted", re_encrypted)
    return re_encrypted


def rewrap_project_keys(old_master_key: str) -> int:
    """Re-wrap every project DEK from an old MASTER_KEY to the current one.

    Called when ``MASTER_KEY`` is rotated: each DEK is unwrapped with the old
    key and re-wrapped with the current key so BYOK projects survive the
    rotation. Returns the number of project keys re-wrapped.

    Example:
        >>> n = rewrap_project_keys("old-master-key")
        >>> n >= 0
        True
    """
    old = crypto.fernet_for(old_master_key)
    re_wrapped = 0
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT project_id, key_enc, key_provider FROM private.project_crypto_keys"
        )
        for row in cur.fetchall() or []:
            if (row.get("key_provider") or "local") != "local":
                # HSM-wrapped DEKs don't depend on MASTER_KEY — nothing to do.
                continue
            try:
                raw = old.decrypt(row["key_enc"].encode())
            except Exception:
                # Already wrapped under the new key, or unreadable — leave it.
                continue
            cur.execute(
                "UPDATE private.project_crypto_keys SET key_enc = %s, updated_at = now() "
                "WHERE project_id = %s",
                (crypto.wrap_project_key(raw), str(row["project_id"])),
            )
            re_wrapped += 1
    crypto.clear_project_key_cache()
    log.info("re-wrapped %s project key(s) to the current MASTER_KEY", re_wrapped)
    return re_wrapped
