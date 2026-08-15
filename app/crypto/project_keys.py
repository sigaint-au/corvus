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
from core import db

log = logging.getLogger(__name__)


def ensure_project_key(project_id, provider: str = "local", hsm_slot_id=None) -> bool:
    """Create and store a project DEK if the project does not have one.

    ``provider`` is ``'local'`` (DEK wrapped by MASTER_KEY) or ``'hsm'`` (DEK
    wrapped by a named slot's KEK — ``hsm_slot_id`` is then required).
    Idempotent; returns True when a new key was created.

    Example:
        >>> if ensure_project_key(pid, provider="hsm", hsm_slot_id=slot):
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
                from crypto import hsm

                if hsm_slot_id is None:
                    raise RuntimeError("HSM provider requires a named slot")
                slot_url = crypto.slot_url(hsm_slot_id)
                if not slot_url:
                    raise RuntimeError("named HSM slot not found")
                key_enc, kms_ref = hsm.wrap_dek_for_slot(slot_url, raw)
            else:
                key_enc = crypto.wrap_project_key(raw)
                kms_ref = None
            cur.execute(
                """
                INSERT INTO private.project_crypto_keys
                  (project_id, key_enc, key_provider, kms_key_ref, hsm_slot_id)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (str(project_id), key_enc, provider, kms_ref,
                 str(hsm_slot_id) if hsm_slot_id is not None else None),
            )
            created = True
    crypto.clear_project_key_cache()
    return created


def project_crypto_status(project_id) -> dict | None:
    """Return the project's key row (provider, kms ref, created_at) or None.

    Includes ``hsm_slot_id`` and (when set) ``hsm_slot_name``.

    Example:
        >>> status = project_crypto_status(pid)
        >>> (status or {}).get("key_provider")
        'local'
    """
    slot_name = None
    try:
        with db.connect_admin() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id AS key_id, key_provider, kms_key_ref, created_at, hsm_slot_id
                FROM private.project_crypto_keys
                WHERE project_id = %s
                """,
                (str(project_id),),
            )
            row = cur.fetchone()
            if row and row.get("hsm_slot_id"):
                cur.execute(
                    "SELECT name FROM private.hsm_slots WHERE id = %s",
                    (str(row["hsm_slot_id"]),),
                )
                srow = cur.fetchone()
                slot_name = srow["name"] if srow else None
        status = dict(row) if row else None
        if status is not None:
            status["hsm_slot_name"] = slot_name
        return status
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


def adopt_project_key(project_id, provider: str = "local", hsm_slot_id=None) -> int:
    """Re-encrypt all master-keyed secrets/versions into the project DEK.

    Creates the project key on demand. ``provider`` is passed to
    :func:`ensure_project_key` so the correct key-encryption key (MASTER_KEY or
    HSM KEK) is used when the project key must be created on demand; when
    ``provider='hsm'`` and ``hsm_slot_id`` is given the key is created in that
    named slot. Runs in a single admin connection with a per-row ``try/except``
    so one corrupt row cannot abort the whole batch; failed rows keep
    ``crypto_provider='master'`` and stay decryptable, so the run can be
    retried. Returns the number of rows re-encrypted.

    Example:
        >>> n = adopt_project_key(pid, provider="hsm", hsm_slot_id=slot)
        >>> n >= 0
        True
    """
    ensure_project_key(project_id, provider=provider, hsm_slot_id=hsm_slot_id)
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


def migrate_project_key(project_id, new_provider: str = "hsm", target_slot_id=None) -> int:
    """Re-wrap the project DEK under a new key provider (and optionally slot).

    When moving between two HSM slots (already HSM, ``target_slot_id`` given)
    the existing DEK is simply re-wrapped by the target slot's KEK — no secret
    re-encryption. In all other cases a fresh DEK is generated, wrapped with
    the new provider/slot, and every project-keyed secret/version is
    re-encrypted. Returns the number of rows re-encrypted.

    Example:
        >>> n = migrate_project_key(pid, "hsm", target_slot_id=slot)
        >>> n >= 0
        True
    """
    from cryptography.fernet import Fernet

    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT key_provider, hsm_slot_id FROM private.project_crypto_keys WHERE project_id = %s",
            (str(project_id),),
        )
        existing = cur.fetchone()
    if existing is None:
        # No project key yet — just create one under the requested provider.
        ensure_project_key(project_id, provider=new_provider, hsm_slot_id=target_slot_id)
        return adopt_project_key(project_id, provider=new_provider, hsm_slot_id=target_slot_id)

    cur_provider = existing.get("key_provider") or "local"
    cur_slot = existing.get("hsm_slot_id")

    if (
        new_provider == "hsm"
        and target_slot_id is not None
        and cur_provider == "hsm"
        and (cur_slot is None or str(cur_slot) != str(target_slot_id))
    ):
        # Same DEK, different slot: re-wrap only (no secret re-encryption).
        slot_url = crypto.slot_url(target_slot_id)
        if not slot_url:
            raise RuntimeError("named HSM slot not found")
        old_dek = crypto.project_dek(project_id)
        if old_dek is None:
            raise RuntimeError("project key exists but its DEK could not be resolved")
        from crypto import hsm

        new_enc, new_ref = hsm.wrap_dek_for_slot(slot_url, old_dek)
        with db.connect_admin(autocommit=False) as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE private.project_crypto_keys
                SET key_enc = %s, kms_key_ref = %s, hsm_slot_id = %s, updated_at = now()
                WHERE project_id = %s
                """,
                (new_enc, new_ref, str(target_slot_id), str(project_id)),
            )
            conn.commit()
        crypto.clear_project_key_cache()
        log.info("project DEK re-wrapped to slot %s", target_slot_id)
        return 0

    old_dek = crypto.project_dek(project_id)
    if old_dek is None:
        raise RuntimeError("project key exists but its DEK could not be resolved")
    old_fernet = Fernet(old_dek)

    new_raw = crypto.generate_project_key()
    if new_provider == "hsm":
        from crypto import hsm

        if target_slot_id is None:
            raise RuntimeError("HSM provider requires a named slot")
        slot_url = crypto.slot_url(target_slot_id)
        if not slot_url:
            raise RuntimeError("named HSM slot not found")
        new_enc, new_ref = hsm.wrap_dek_for_slot(slot_url, new_raw)
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
            SET key_enc = %s, key_provider = %s, kms_key_ref = %s, hsm_slot_id = %s, updated_at = now()
            WHERE project_id = %s
            """,
            (new_enc, new_provider, new_ref,
             str(target_slot_id) if target_slot_id is not None else None,
             str(project_id)),
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


def rotate_hsm_kek(slot_id) -> int:
    """Rotate a named slot's KEK, re-wrapping its HSM-backed DEKs.

    Generates a new KEK (new label) in the slot and re-wraps every project
    linked to that slot. Returns the number of projects re-wrapped.

    Example:
        >>> n = rotate_hsm_kek(slot_id)
        >>> n >= 0
        True
    """
    from crypto import hsm

    slot_url = crypto.slot_url(slot_id)
    if not slot_url:
        raise RuntimeError("named HSM slot not found")
    parsed = hsm.parse_pkcs11_url(slot_url)
    new_label = f"{parsed['kek_label']}-{secrets.token_hex(4)}"
    hsm.generate_kek(new_label, pkcs11_url=slot_url)
    re_wrapped = 0
    with db.connect_admin(autocommit=False) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT project_id, key_enc, kms_key_ref
            FROM private.project_crypto_keys
            WHERE key_provider = 'hsm' AND hsm_slot_id = %s
            """,
            (str(slot_id),),
        )
        for row in cur.fetchall() or []:
            try:
                raw = hsm.unwrap_dek_for_slot(
                    slot_url, row["key_enc"], row.get("kms_key_ref")
                )
                new_enc = hsm.wrap_dek_with_label(slot_url, raw, new_label)
            except Exception:
                continue
            cur.execute(
                """
                UPDATE private.project_crypto_keys
                SET key_enc = %s, kms_key_ref = %s, updated_at = now()
                WHERE project_id = %s
                """,
                (new_enc, new_label, str(row["project_id"])),
            )
            re_wrapped += 1
        conn.commit()
    crypto.clear_project_key_cache()
    log.info("rotated HSM KEK for slot %s: %s project(s)", slot_id, re_wrapped)
    return re_wrapped


def encryption_summary() -> dict:
    """Return per-project encryption posture for the admin Encryption tab.

    Returns ``{"counts": {...}, "projects": [...]}`` where each project row has
    team/project name, provider, key created-at, key id, slot name, and pending
    (master) row count. Managed projects (no key row) are included with provider
    ``'managed'``.
    """
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT p.id AS project_id, p.name AS project_name,
                   t.name AS team_name,
                   k.key_provider, k.created_at AS key_created_at, k.id AS key_id,
                   k.hsm_slot_id, s.name AS hsm_slot_name,
                   ((SELECT count(*) FROM api.secrets s2
                      WHERE s2.project_id = p.id
                        AND s2.crypto_provider = 'master' AND s2.deleted_at IS NULL)
                  + (SELECT count(*) FROM api.secret_versions v
                      JOIN api.secrets s3 ON s3.id = v.secret_id
                      WHERE s3.project_id = p.id AND v.crypto_provider = 'master')) AS pending
            FROM api.projects p
            JOIN api.teams t ON t.id = p.team_id
            LEFT JOIN private.project_crypto_keys k ON k.project_id = p.id
            LEFT JOIN private.hsm_slots s ON s.id = k.hsm_slot_id
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
                "hsm_slot_id": str(r["hsm_slot_id"]) if r.get("hsm_slot_id") else None,
                "hsm_slot_name": r.get("hsm_slot_name"),
                "pending": int(r.get("pending") or 0),
            }
        )
    return {"counts": counts, "projects": projects}


def migrate_all_local_to_hsm(target_slot_id) -> int:
    """Migrate every local-BYOK project to an HSM-wrapped key in a slot.

    ``target_slot_id`` is required. Returns the number of projects migrated.
    """
    if target_slot_id is None:
        raise RuntimeError("a target HSM slot is required")
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
            migrate_project_key(pid, "hsm", target_slot_id=target_slot_id)
            migrated += 1
        except Exception as e:
            log.warning("migrate_all_local_to_hsm: project %s failed: %s", pid, e)
    return migrated


def link_legacy_to_slot(slot_id) -> int:
    """Associate legacy HSM projects (hsm_slot_id IS NULL) with a slot.

    Only links projects whose stored DEK was wrapped by a KEK that matches the
    slot's KEK label (parsed from its PKCS#11 URL) — this guarantees all rows
    remain decryptable. Metadata-only (no re-encryption). Returns the number of
    projects linked.
    """
    from crypto import hsm

    slot_url = crypto.slot_url(slot_id)
    if not slot_url:
        raise RuntimeError("named HSM slot not found")
    if not hsm.available_for_slot(slot_url):
        raise RuntimeError("HSM slot is not reachable; cannot verify KEK label")
    slot_kek = hsm.parse_pkcs11_url(slot_url)["kek_label"]
    with db.connect_admin(autocommit=False) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE private.project_crypto_keys
            SET hsm_slot_id = %s, updated_at = now()
            WHERE key_provider = 'hsm' AND hsm_slot_id IS NULL AND kms_key_ref = %s
            """,
            (str(slot_id), slot_kek),
        )
        n = cur.rowcount
        conn.commit()
    crypto.clear_project_key_cache()
    log.info("linked %s legacy HSM project(s) to slot %s", n, slot_id)
    return n
