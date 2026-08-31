from __future__ import annotations


def materialize_folder_path(cur, project_id, segments: tuple[str, ...]):
    parent_id = None
    path_parts = []
    for name in segments:
        path_parts.append(name)
        cur.execute(
            "SELECT private.materialize_folder_path(%s::uuid, %s::uuid, %s, %s) AS id",
            (project_id, parent_id, name, "/".join(path_parts)),
        )
        row = cur.fetchone()
        parent_id = row["id"] if row else None
    return parent_id


def delete_empty_folder(cur, project_id, folder_id):
    """Delete a folder and its empty descendants, refusing any secrets."""
    cur.execute(
        """
        WITH RECURSIVE descendants(id) AS (
          SELECT id FROM api.folders
          WHERE project_id = %s AND id = %s::uuid
          UNION ALL
          SELECT f.id FROM api.folders f
          JOIN descendants d ON d.id = f.parent_id
          WHERE f.project_id = %s
        )
        SELECT EXISTS (
          SELECT 1 FROM api.secrets s
          JOIN descendants d ON d.id = s.folder_id
           WHERE s.project_id = %s
        ) AS blocked
        """,
        (str(project_id), str(folder_id), str(project_id), str(project_id)),
    )
    if (cur.fetchone() or {}).get("blocked"):
        raise ValueError("Folder contains secrets")
    cur.execute(
        """
        DELETE FROM api.folders
        WHERE project_id = %s AND id = %s::uuid
        RETURNING id
        """,
        (str(project_id), str(folder_id)),
    )
    row = cur.fetchone()
    return row["id"] if isinstance(row, dict) and row else (row[0] if row else None)


def parse_secret_path(key: str) -> tuple[tuple[str, ...], str]:
    if not key or "\\" in key:
        raise ValueError("Secret key must be a slash-separated path")
    parts = tuple(key.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise ValueError("Secret key contains an invalid path segment")
    return parts[:-1], parts[-1]


def visible_folder_paths(secret_rows) -> list[str]:
    """Return folder prefixes represented by rows already allowed by RLS."""
    paths = set()
    for row in secret_rows or []:
        parts = str(row.get("key") or "").split("/")
        paths.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return sorted(paths)
