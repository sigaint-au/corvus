"""Versioned SQL migration runner.

Migrations live in ``db/migrations/*.sql`` and are applied once, in filename
order, by ``apply_pending()``. Applied versions and their checksums are
recorded in ``private.schema_migrations`` (admin-only; the ``private`` schema
is not exposed to PostgREST).

The squashed baseline (``0001_init.sql``) is applied by
``docker-entrypoint-initdb.d`` on a fresh volume. On startup, if the schema
already exists but the migrations table is empty, it is seeded as applied so
existing volumes never re-run baseline DDL; only additive migrations run.

The caller is responsible for holding the ``pg_advisory_lock`` serialization
around ``apply_pending()`` (see :func:`schema.ensure_schema`).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

log = __import__("logging").getLogger(__name__)

# Repo root in dev (app/../db/migrations); /db/migrations in the container
# (Dockerfile copies db/migrations -> /db/migrations).
_env_migrations_dir = os.environ.get("MIGRATIONS_DIR", "")
MIGRATIONS_DIR = (
    Path(_env_migrations_dir)
    if _env_migrations_dir
    else Path(__file__).resolve().parents[2] / "db" / "migrations"
)

# The baseline migration is applied by docker-entrypoint on a fresh volume and
# must not be re-run on existing volumes (it contains non-idempotent DDL).
BASELINE_VERSIONS = ("0001",)

_MIGRATIONS_TABLE = "private.schema_migrations"


def _split_sql_statements(sql: str) -> list[str]:
    """Split a SQL script into statements, respecting dollar-quoted bodies."""
    stmts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(sql)
    in_dollar = False
    dollar_tag = ""
    while i < n:
        if not in_dollar and sql[i] == "-" and i + 1 < n and sql[i + 1] == "-":
            # line comment
            while i < n and sql[i] != "\n":
                buf.append(sql[i])
                i += 1
            continue
        if not in_dollar and sql[i] == "$":
            # start dollar quote $$ or $tag$
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] == "_"):
                j += 1
            if j < n and sql[j] == "$":
                dollar_tag = sql[i : j + 1]
                in_dollar = True
                buf.append(dollar_tag)
                i = j + 1
                continue
        if in_dollar:
            if sql.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                in_dollar = False
                dollar_tag = ""
                continue
            buf.append(sql[i])
            i += 1
            continue
        if sql[i] == ";":
            chunk = "".join(buf).strip()
            if chunk:
                stmts.append(chunk)
            buf = []
            i += 1
            continue
        buf.append(sql[i])
        i += 1
    chunk = "".join(buf).strip()
    if chunk:
        stmts.append(chunk)
    return stmts


def _migration_files() -> list[Path]:
    """Return migration SQL files in lexical (version) order."""
    if not MIGRATIONS_DIR.is_dir():
        return []
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def _version_of(path: Path) -> str:
    """Extract the leading version number (e.g. ``0004``) from a filename."""
    return path.name.split("_", 1)[0]


def _normalize_sql(sql: str) -> str:
    """Normalize SQL by stripping comments and joining lines to allow checksum stability.

    This allows adding documentation comments or changing whitespace in a
    migration file without breaking the checksum of an already-applied migration.
    """
    lines: list[str] = []
    for line in sql.splitlines():
        # Remove line comments
        content = line.split("--", 1)[0].strip()
        if content:
            lines.append(content)
    return " ".join(lines).lower()


def _checksum(sql: str) -> str:
    """SHA-256 hex digest of normalized migration SQL."""
    normalized = _normalize_sql(sql)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _ensure_table(cur) -> None:
    """Create the migration-tracking table if it does not exist."""
    cur.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_MIGRATIONS_TABLE} (
          version text PRIMARY KEY,
          applied_at timestamptz NOT NULL DEFAULT now(),
          checksum text NOT NULL,
          applied_by text,
          application_name text
        )
        """
    )
    cur.execute(
        f"REVOKE ALL ON {_MIGRATIONS_TABLE} FROM authenticator, authenticated, anon"
    )


def _applied_checksums(cur) -> dict[str, str]:
    """Return a mapping of applied migration version -> checksum."""
    cur.execute(f"SELECT version, checksum FROM {_MIGRATIONS_TABLE}")
    return {str(r["version"]): str(r["checksum"]) for r in (cur.fetchall() or [])}


def _squashed_baseline_exists(cur) -> bool:
    """Return True when the current fresh-install baseline is present."""
    cur.execute(
        "SELECT to_regclass('private.squashed_baseline_marker') IS NOT NULL AS ok"
    )
    return bool((cur.fetchone() or {}).get("ok"))


def _migration_specs() -> list[tuple[str, str, str]]:
    """Return ``(version, sql, checksum)`` for every migration file, in order."""
    specs: list[tuple[str, str, str]] = []
    for path in _migration_files():
        sql = path.read_text()
        specs.append((_version_of(path), sql, _checksum(sql)))
    return specs


def pending_migrations(cur) -> list[tuple[str, str]]:
    """Return unapplied migrations as ``(version, sql)`` pairs, in order.

    Raises ``RuntimeError`` when an already-applied version's checksum no
    longer matches its file (schema drift).
    """
    _ensure_table(cur)
    applied = _applied_checksums(cur)
    pending: list[tuple[str, str]] = []
    for version, sql, checksum in _migration_specs():
        if version in applied:
            if applied[version] != checksum:
                raise RuntimeError(
                    f"migration {version} checksum mismatch: recorded "
                    f"{applied[version]} != current {checksum} (schema drift detected)"
                )
            continue
        pending.append((version, sql))
    return pending


def apply_pending(cur) -> None:
    """Apply all pending migrations, recording each version after it succeeds.

    Every migration is applied within its own transaction. The checksum is
    recorded only after all statements in the file succeed.
    """
    _ensure_table(cur)
    applied = _applied_checksums(cur)
    if not applied and not _squashed_baseline_exists(cur):
        raise RuntimeError(
            "database is not initialized with the squashed baseline; "
            "restore a backup taken after 0001, or recreate the database"
        )
    seed_baseline = not applied

    for version, sql, checksum in _migration_specs():
        if version in applied:
            if applied[version] != checksum:
                raise RuntimeError(
                    f"migration {version} checksum mismatch: recorded "
                    f"{applied[version]} != current {checksum} (schema drift detected)"
                )
            continue
        if seed_baseline and version in BASELINE_VERSIONS:
            cur.execute(
                f"""
                INSERT INTO {_MIGRATIONS_TABLE} (version, checksum, applied_by, application_name)
                VALUES (%s, %s, current_user, current_setting('application_name', true))
                ON CONFLICT (version) DO NOTHING
                """,
                (version, checksum),
            )
            log.info("seeded baseline migration %s", version)
            continue

        # Wrap each migration in a sub-transaction (savepoint) or trust the
        # caller's transaction. Since the caller usually holds an advisory lock
        # and we use cur.execute(), we use a SAVEPOINT to allow partial
        # rollback of just this migration file if it fails.
        savepoint = f"migration_{version}"
        cur.execute(f"SAVEPOINT {savepoint}")
        try:
            # Psycopg allows executing multiple statements in one execute() call
            # if they are separated by semicolons. This is safer than manual splitting.
            cur.execute(sql)

            cur.execute(
                f"INSERT INTO {_MIGRATIONS_TABLE} (version, checksum, applied_by, application_name) VALUES (%s, %s, current_user, current_setting('application_name', true))",
                (version, checksum),
            )
            cur.execute(f"RELEASE SAVEPOINT {savepoint}")
            log.info("applied migration %s", version)
        except Exception as e:
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            log.error("failed to apply migration %s: %s", version, e)
            raise
