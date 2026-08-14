"""Per-project crypto key management (BYOK, local-key tier).

Each project may have a dedicated data-encryption key (DEK) stored wrapped by
the app MASTER_KEY in ``private.project_crypto_keys``. This module manages the
row lifecycle (create, adopt) and re-encrypts existing secrets onto the
project key. Key resolution itself lives in :mod:`crypto`.
"""

from __future__ import annotations

import logging
import secrets

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


def adopt_project_key(project_id, provider: str = "local") -> int:
    """Re-encrypt all master-keyed secrets/versions into the project DEK.

    Creates the project key on demand. ``provider`` is passed to
    :func:`ensure_project_key` so the correct key-encryption key (MASTER_KEY or
    HSM KEK) is used when the project key must be created on demand. Runs in a
    single admin connection with a per-row ``try/except`` so one corrupt row
    cannot abort the whole batch; failed rows keep ``crypto_provider='master'``
    and stay decryptable, so the run can be retried. Returns the number of rows
    re-encrypted.

    Example:
        >>> n = adopt_project_key(pid)
        >>> n >= 0
        True
    """
    ensure_project_key(project_id, provider=provider)
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


def migrate_project_key(project_id, new_provider: str = "hsm") -> int:
    """Re-wrap the project DEK under a new key provider.

    Generates a fresh DEK, wraps it with the new provider (``'hsm'`` or
    ``'local'``), re-encrypts all project-keyed secrets and versions from the
    old DEK to the new one, and updates ``private.project_crypto_keys``.
    Returns the number of rows re-encrypted.

    Example:
        >>> n = migrate_project_key(pid, "hsm")
        >>> n >= 0
        True
    """
    from cryptography.fernet import Fernet

    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT key_provider FROM private.project_crypto_keys WHERE project_id = %s",
            (str(project_id),),
        )
        existing = cur.fetchone()
    if existing is None:
        # No project key yet — just create one under the requested provider.
        ensure_project_key(project_id, provider=new_provider)
        return adopt_project_key(project_id, provider=new_provider)

    old_dek = crypto.project_dek(project_id)
    if old_dek is None:
        raise RuntimeError("project key exists but its DEK could not be resolved")
    old_fernet = Fernet(old_dek)

    new_raw = crypto.generate_project_key()
    if new_provider == "hsm":
        import hsm

        hsm.ensure_kek()
        new_enc = hsm.wrap_dek(new_raw)
        new_ref = hsm.kek_label()
    else:
        new_enc = crypto.wrap_project_key(new_raw)
        new_ref = None
    new_fernet = Fernet(new_raw)

    re_encrypted = 0
    with db.connect_admin(autocommit=False) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, value_enc FROM api.secrets
            WHERE project_id = %s AND crypto_provider = 'project' AND deleted_at IS NULL
            """,
            (str(project_id),),
        )
        secret_rows = cur.fetchall() or []
        cur.execute(
            """
            SELECT v.id, v.value_enc FROM api.secret_versions v
            JOIN api.secrets s ON s.id = v.secret_id
            WHERE s.project_id = %s AND v.crypto_provider = 'project'
            """,
            (str(project_id),),
        )
        version_rows = cur.fetchall() or []
        for row in secret_rows:
            try:
                plaintext = old_fernet.decrypt(row["value_enc"].encode()).decode()
                new_enc_value = new_fernet.encrypt(plaintext.encode()).decode()
            except Exception:
                continue
            cur.execute(
                "UPDATE api.secrets SET value_enc = %s WHERE id = %s",
                (new_enc_value, str(row["id"])),
            )
            re_encrypted += 1
        for row in version_rows:
            try:
                plaintext = old_fernet.decrypt(row["value_enc"].encode()).decode()
                new_enc_value = new_fernet.encrypt(plaintext.encode()).decode()
            except Exception:
                continue
            cur.execute(
                "UPDATE api.secret_versions SET value_enc = %s WHERE id = %s",
                (new_enc_value, str(row["id"])),
            )
            re_encrypted += 1
        cur.execute(
            """
            UPDATE private.project_crypto_keys
            SET key_enc = %s, key_provider = %s, kms_key_ref = %s, updated_at = now()
            WHERE project_id = %s
            """,
            (new_enc, new_provider, new_ref, str(project_id)),
        )
        conn.commit()
    crypto.clear_project_key_cache()
    log.info(
        "project key migrated to %s: %s row(s) re-encrypted", new_provider, re_encrypted
    )
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


def rotate_hsm_kek() -> int:
    """Rotate the HSM KEK: re-wrap every HSM-backed DEK under a fresh KEK.

    Generates a new KEK (new label), re-wraps each HSM-backed DEK from its
    current KEK to the new one, and updates ``key_enc``/``kms_key_ref``.
    Returns the number of HSM-backed projects re-wrapped. The old KEK is left
    in place (inert once unreferenced) so a partial run can be retried.

    Example:
        >>> n = rotate_hsm_kek()
        >>> n >= 0
        True
    """
    import hsm

    new_label = f"{hsm.kek_label()}-{secrets.token_hex(4)}"
    hsm.generate_kek(new_label)
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT project_id, key_enc, kms_key_ref
            FROM private.project_crypto_keys
            WHERE key_provider = 'hsm'
            """
        )
        rows = cur.fetchall() or []
    re_wrapped = 0
    for row in rows:
        try:
            raw = hsm.unwrap_dek(row["key_enc"], row.get("kms_key_ref"))
            new_enc = hsm.wrap_dek(raw, new_label)
        except Exception:
            continue
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.project_crypto_keys
                SET key_enc = %s, kms_key_ref = %s, updated_at = now()
                WHERE project_id = %s
                """,
                (new_enc, new_label, str(row["project_id"])),
            )
        re_wrapped += 1
    crypto.clear_project_key_cache()
    log.info("rotated HSM KEK: %s project(s) re-wrapped to %r", re_wrapped, new_label)
    return re_wrapped


def encryption_summary() -> dict:
    """Return per-project encryption posture for the admin Encryption tab.

    Returns ``{"counts": {...}, "projects": [...]}`` where each project row has
    team/project name, provider, key created-at, key id, and pending (master)
    row count. Managed projects (no key row) are included with provider
    ``'managed'``.
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT p.id AS project_id, p.name AS project_name,
                   t.name AS team_name,
                   k.key_provider, k.created_at AS key_created_at, k.id AS key_id
            FROM api.projects p
            JOIN api.teams t ON t.id = p.team_id
            LEFT JOIN private.project_crypto_keys k ON k.project_id = p.id
            ORDER BY t.name, p.name
            """
        )
        rows = cur.fetchall() or []
    counts = {"managed": 0, "local": 0, "hsm": 0}
    projects = []
    for r in rows:
        provider = (r.get("key_provider") or "managed")
        if provider not in ("local", "hsm"):
            provider = "managed"
        counts[provider] = counts.get(provider, 0) + 1
        projects.append(
            {
                "project_id": str(r["project_id"]),
                "project_name": r["project_name"],
                "team_name": r["team_name"],
                "provider": provider,
                "key_created_at": r.get("key_created_at"),
                "key_id": str(r["key_id"]) if r.get("key_id") else None,
                "pending": count_master_rows(str(r["project_id"])),
            }
        )
    return {"counts": counts, "projects": projects}


def migrate_all_local_to_hsm() -> int:
    """Migrate every local-BYOK project to an HSM-wrapped key.

    Returns the number of projects migrated.
    """
    import hsm

    if not hsm.available():
        raise RuntimeError("HSM is not configured")
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT project_id FROM private.project_crypto_keys
            WHERE key_provider = 'local'
            """
        )
        ids = [str(r["project_id"]) for r in (cur.fetchall() or [])]
    migrated = 0
    for pid in ids:
        try:
            migrate_project_key(pid, "hsm")
            migrated += 1
        except Exception as e:
            log.warning("migrate_all_local_to_hsm: project %s failed: %s", pid, e)
    return migrated
