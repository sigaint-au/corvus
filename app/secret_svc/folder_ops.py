"""Folder commands: ensure/list/create/delete/move within a project."""
import logging

from werkzeug.exceptions import Forbidden, NotFound

import audit

log = logging.getLogger(__name__)


def ensure_path(cur, project_id, path):
    """Materialize folder ancestors for a path, returning the leaf folder id."""
    cur.execute(
        "SELECT private.ensure_folder_path(%s::uuid, %s, api.current_user_id()) AS fid",
        (str(project_id), path),
    )
    row = cur.fetchone()
    return str(row["fid"]) if row and row["fid"] else None


def list_children(cur, project_id, folder_id, page, q):
    """List child folders + leaf secrets at one level, paginated."""
    from ui import paging

    folder_uuid = str(folder_id) if folder_id else None
    folder_param = folder_uuid if folder_uuid else None

    if q:
        like = f"%{q}%"
        cur.execute(
            """
            SELECT count(*) AS n FROM (
              SELECT f.id FROM api.folders f
              WHERE f.project_id = %s AND f.parent_id IS NOT DISTINCT FROM %s
                AND f.name ILIKE %s
              UNION ALL
              SELECT s.id FROM api.secrets s
              WHERE s.project_id = %s AND s.folder_id IS NOT DISTINCT FROM %s
                AND s.deleted_at IS NULL
                AND (s.key ILIKE %s OR s.note ILIKE %s)
            ) sub
            """,
            (str(project_id), folder_param, like,
             str(project_id), folder_param, like, like),
        )
    else:
        cur.execute(
            """
            SELECT (
              SELECT count(*) FROM api.folders f
              WHERE f.project_id = %s AND f.parent_id IS NOT DISTINCT FROM %s
            ) + (
              SELECT count(*) FROM api.secrets s
              WHERE s.project_id = %s AND s.folder_id IS NOT DISTINCT FROM %s
                AND s.deleted_at IS NULL
            ) AS n
            """,
            (str(project_id), folder_param,
             str(project_id), folder_param),
        )
    total = int((cur.fetchone() or {}).get("n") or 0)
    pager = paging.page_window(total, page)
    pager.update(
        endpoint="project_detail",
        project_id=project_id,
        tab="secrets",
        folder=folder_uuid or "",
        q=q,
    )

    folders = []
    cur.execute(
        """
        SELECT f.id, f.name, f.path, f.parent_id,
               (SELECT count(*) FROM api.secrets s
                WHERE s.folder_id = f.id AND s.deleted_at IS NULL) AS secret_count,
               (SELECT count(*) FROM api.folders c WHERE c.parent_id = f.id) AS child_count
        FROM api.folders f
        WHERE f.project_id = %s AND f.parent_id IS NOT DISTINCT FROM %s
        ORDER BY f.name
        LIMIT %s OFFSET %s
        """,
        (str(project_id), folder_param, pager["limit"], pager["offset"]),
    )
    folders = cur.fetchall() or []

    folder_count = len(folders)
    secret_limit = max(0, pager["limit"] - folder_count)
    secret_offset = max(0, pager["offset"] - folder_count)

    from secret_svc.secret_kinds import expires_status, secret_due_status

    secrets = []
    if secret_limit > 0:
        cur.execute(
            """
            SELECT s.id, s.key, s.note, s.kind, s.created_at, s.updated_at, s.expires_at,
                   s.rotation_interval_days, s.rotation_owner, s.rotation_next_at, s.rotated_at,
                   s.requires_approval, s.access_mode,
                   s.last_accessed_at,
                   api.can_access_secret(s.id, 'reveal') AS can_reveal,
                   CASE
                     WHEN s.requires_approval IS TRUE THEN true
                     WHEN s.requires_approval IS FALSE THEN false
                     ELSE COALESCE(p.require_reveal_approval, false)
                   END AS needs_approval,
                   COALESCE(t.allow_reveal_requests, true) AS allow_reveal_requests
            FROM api.secrets s
            JOIN api.projects p ON p.id = s.project_id
            JOIN api.teams t ON t.id = p.team_id
            WHERE s.project_id = %s AND s.folder_id IS NOT DISTINCT FROM %s
              AND s.deleted_at IS NULL
            ORDER BY s.key
            LIMIT %s OFFSET %s
            """,
            (str(project_id), folder_param, secret_limit, secret_offset),
        )
        secrets = cur.fetchall() or []
        ids = [str(s["id"]) for s in secrets]
        pinned = set()
        if ids:
            cur.execute(
                """
                SELECT secret_id FROM api.secret_pins
                WHERE user_id = api.current_user_id()
                  AND secret_id = ANY(%s::uuid[])
                """,
                (ids,),
            )
            pinned = {str(x["secret_id"]) for x in (cur.fetchall() or [])}
        for r in secrets:
            r["due"] = secret_due_status(r)
            r["rotation_due"] = expires_status(r.get("rotation_next_at"))
            r["is_pinned"] = str(r["id"]) in pinned
            r["needs_approval"] = bool(r.get("needs_approval"))
            r["reveal_access"] = "allowed"
            mode = (r.get("access_mode") or "inherit").strip() or "inherit"
            r["access_mode"] = mode
            r["access_restricted"] = mode != "inherit"

    rows = folders + secrets
    return rows, pager, folders, secrets


def create_folder(cur, project_id, path, *, actor_email=None):
    """Create a folder (and ancestors); audit folder_created."""
    from lib.folders import validate_path
    path = validate_path(path)
    cur.execute(
        "SELECT private.ensure_folder_path(%s::uuid, %s, api.current_user_id()) AS fid",
        (str(project_id), path),
    )
    row = cur.fetchone()
    if not row or not row.get("fid"):
        raise Forbidden("Could not create folder")
    fid = str(row["fid"])
    audit.log_org(
        cur,
        project_id=project_id,
        action="folder_created",
        detail=f"folder={fid} path={path}",
        actor_email=actor_email,
    )
    return fid


def delete_folder(cur, folder_id, *, project_id, recursive=False, actor_email=None):
    """Delete a folder; recursive trashes descendant secrets first."""
    cur.execute(
        "SELECT id FROM api.folders WHERE id = %s AND project_id = %s",
        (str(folder_id), str(project_id)),
    )
    if not cur.fetchone():
        raise NotFound("Folder not found")

    cur.execute(
        "SELECT count(*) AS n FROM api.secrets WHERE folder_id = %s AND deleted_at IS NULL",
        (str(folder_id),),
    )
    secret_count = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute(
        "SELECT count(*) AS n FROM api.folders WHERE parent_id = %s",
        (str(folder_id),),
    )
    child_count = int((cur.fetchone() or {}).get("n") or 0)

    if (secret_count > 0 or child_count > 0) and not recursive:
        raise Forbidden(
            "Folder is not empty. Use recursive delete or remove contents first."
        )

    if recursive:
        # Soft-delete every descendant secret (trash); trashed secrets keep
        # folder_id so restore lands back in the folder.
        cur.execute(
            """
            WITH RECURSIVE subtree AS (
              SELECT id FROM api.folders WHERE id = %s
              UNION ALL
              SELECT f.id FROM api.folders f
              JOIN subtree s ON f.parent_id = s.id
            )
            UPDATE api.secrets
            SET deleted_at = now()
            WHERE deleted_at IS NULL
              AND folder_id IN (SELECT id FROM subtree)
            """,
            (str(folder_id),),
        )
        # Delete folder rows that have no remaining live/trashed secrets,
        # bottom-up, so an ancestor is never dropped under a live child.
        # cap at max depth (16): each pass clears >= one level, so <= 16 rounds needed.
        for _ in range(17):
            cur.execute(
                """
                DELETE FROM api.folders
                WHERE id IN (
                  WITH RECURSIVE subtree AS (
                    SELECT id FROM api.folders WHERE id = %s
                    UNION ALL
                    SELECT f.id FROM api.folders f
                    JOIN subtree s ON f.parent_id = s.id
                  ) SELECT id FROM subtree
                )
                  AND NOT EXISTS (
                    SELECT 1 FROM api.folders c
                    WHERE c.parent_id = api.folders.id
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM api.secrets s
                    WHERE s.folder_id = api.folders.id
                  )
                RETURNING id
                """,
                (str(folder_id),),
            )
            if not cur.fetchall():
                break

    else:
        cur.execute("DELETE FROM api.folders WHERE id = %s", (str(folder_id),))

    audit.log_org(
        cur,
        project_id=project_id,
        action="folder_deleted",
        detail=f"folder={folder_id} recursive={recursive}",
        actor_email=actor_email,
    )


def move_folder(cur, folder_id, new_path, *, project_id, actor_email=None):
    """Rename/move a folder, rewriting descendant paths and secret keys."""
    new_path = new_path.strip("/")
    from lib.folders import validate_path
    validate_path(new_path)

    cur.execute(
        "SELECT id, path, project_id FROM api.folders WHERE id = %s",
        (str(folder_id),),
    )
    folder = cur.fetchone()
    if not folder:
        raise NotFound("Folder not found")
    old_path = folder["path"]
    if old_path == new_path:
        return str(folder_id)

    # Check for collisions
    prefix_len = len(old_path) + 1
    cur.execute(
        """
        SELECT count(*) AS n FROM api.secrets
        WHERE project_id = %s AND deleted_at IS NULL
          AND (key = %s OR key LIKE %s)
          AND key != %s
        """,
        (str(project_id), new_path, f"{new_path}/%", old_path),
    )
    existing = int((cur.fetchone() or {}).get("n") or 0)
    if existing > 0:
        raise Forbidden("Target path collides with existing secrets")

    cur.execute(
        "SELECT count(*) AS n FROM api.folders WHERE project_id = %s AND path = %s AND id != %s",
        (str(project_id), new_path, str(folder_id)),
    )
    if (cur.fetchone() or {}).get("n", 0) > 0:
        raise Forbidden("Target path already exists as a folder")

    # Rewrite folder paths (descendants)
    cur.execute(
        """
        UPDATE api.folders
        SET path = %s || substr(path, %s),
            name = CASE WHEN id = %s THEN %s ELSE name END,
            updated_at = now()
        WHERE project_id = %s
          AND (path = %s OR path LIKE %s)
        """,
        (new_path, prefix_len, str(folder_id), new_path.rsplit("/", 1)[-1] or new_path,
         str(project_id), old_path, f"{old_path}/%"),
    )

    # Rewrite secret keys
    cur.execute(
        """
        UPDATE api.secrets
        SET key = %s || substr(key, %s)
        WHERE project_id = %s AND deleted_at IS NULL
          AND (key = %s OR key LIKE %s)
        """,
        (new_path, prefix_len, str(project_id), old_path, f"{old_path}/%"),
    )

    audit.log_org(
        cur,
        project_id=project_id,
        action="folder_moved",
        detail=f"folder={folder_id} from={old_path} to={new_path}",
        actor_email=actor_email,
    )
    return str(folder_id)
