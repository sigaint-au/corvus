# Metadata Inheritance (team → project → secret) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Metadata defined on a team appears on all its projects and secrets, metadata on a project appears on its secrets, and higher-level keys cannot be overridden lower down.

**Architecture:** Two new tables (`api.team_meta`, `api.project_meta`) with a `private.guard_meta_precedence()` trigger that rejects writes of a key that exists higher in the hierarchy. `private.secret_meta_rows()` is rewritten to return merged rows with a `source` column (`team`/`project`/`secret`). UI meta tabs on team and project detail pages; PAT management endpoints for team/project meta; the PAT list endpoint switches to merged rows.

**Tech Stack:** Flask + HTMX (server-rendered, oat.ink UI), PostgreSQL RLS + triggers, psycopg, pytest with mocked DB (no Postgres needed for tests).

**Spec:** The requirements are the examples in this header: team meta `mark.hahl.team=team1` must be visible on the project and secret pages and in PAT metadata output; a key defined at team level must be rejected if written at project or secret level (and project-level keys rejected at secret level). Lower levels may still define their own distinct keys.

## Global Constraints

- Python 3.10+ required (`str | None` syntax). Run tests with `pytest` from repo root; **tests mock the DB — no Postgres needed**.
- **Migrations are the sole source of truth for DDL.** Never edit `db/migrations/0001_init.sql` or any released migration. This plan adds `db/migrations/0017_team_project_meta.sql` (next free number; 0001–0016 exist). Migrations contain no `BEGIN;`/`COMMIT;` (the runner splits and applies statements itself).
- Metadata key regex everywhere: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (same as existing `api.secret_meta` CHECK). Value max length: 2000 (truncate silently, matching existing behavior).
- Precedence: team > project > secret. Guard error message (SQL): `metadata key % is defined at team level and cannot be overridden` (project level analogously). UI flash copy: `Metadata key is defined at team/project level and cannot be overridden.`
- Machine-token roles use `service-read`/`service-reveal`/`service-write`; UI/RBAC role names are `team-owner`, `team-admin`, etc. Meta write permissions: team meta = `team-owner`/`team-admin`; project meta = `api.can_admin_project`.
- User-facing copy plain. Tables wrapped in `<div class="table">`. Subnav uses `page-subnav` links with `?tab=` URLs; project subnav links use paired `hx-get` + `href` (hx-target `#project-panel`).
- Shell commands: prefix with `rtk` where supported (`rtk git ...`, `rtk pytest ...`). Commit messages: plain subject, no AI/Co-Authored-By trailers.
- Lint/format/type-check at the end of every task: `tox -e lint` (or `make lint`), `make format` before committing if ruff complains.

---

### Task 1: Migration 0017 — tables, precedence guard, RLS, merged secret_meta_rows

**Files:**
- Create: `db/migrations/0017_team_project_meta.sql`
- Test: `tests/test_meta.py` (new file)

**Interfaces:**
- Consumes: existing `api.secret_meta`, `api.secrets.project_id`, `api.projects.team_id`, `api.team_role(uuid)`, `api.can_read_project(uuid)`, `api.can_admin_project(uuid)`, `api.can_access_secret(uuid, text)` (all defined in `db/migrations/0001_init.sql`).
- Produces: `api.team_meta(team_id, key, value, updated_at)`, `api.project_meta(project_id, key, value, updated_at)`, guard trigger on all three meta tables, and `private.secret_meta_rows(p_secret uuid)` now `RETURNS TABLE(key text, value text, updated_at timestamptz, source text)`. Later tasks query these table/function names exactly.

- [ ] **Step 1: Write the failing schema test**

Create `tests/test_meta.py`:

```python
"""Team/project metadata inheritance: schema + routes (DB mocked, no Postgres)."""

from __future__ import annotations

from pathlib import Path

from tests.helpers import REPO_ROOT

MIGRATION = REPO_ROOT / "db" / "migrations" / "0017_team_project_meta.sql"


def migration_sql() -> str:
    return MIGRATION.read_text()


class TestSchema:
    def test_migration_file_exists(self):
        assert MIGRATION.exists()

    def test_team_meta_table(self):
        sql = migration_sql()
        assert "CREATE TABLE IF NOT EXISTS api.team_meta" in sql
        assert "REFERENCES api.teams(id) ON DELETE CASCADE" in sql
        assert "PRIMARY KEY (team_id, key)" in sql
        assert "key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'" in sql

    def test_project_meta_table(self):
        sql = migration_sql()
        assert "CREATE TABLE IF NOT EXISTS api.project_meta" in sql
        assert "REFERENCES api.projects(id) ON DELETE CASCADE" in sql
        assert "PRIMARY KEY (project_id, key)" in sql

    def test_guard_function_and_triggers(self):
        sql = migration_sql()
        assert "FUNCTION private.guard_meta_precedence()" in sql
        assert "is defined at team level and cannot be overridden" in sql
        assert "is defined at project level and cannot be overridden" in sql
        for table in ("team_meta", "project_meta", "secret_meta"):
            assert f"CREATE TRIGGER {table}_guard BEFORE INSERT OR UPDATE ON api.{table}" in sql

    def test_rls_policies(self):
        sql = migration_sql()
        for frag in (
            "ENABLE ROW LEVEL SECURITY",
            "api.team_role(team_id) IS NOT NULL",
            "api.team_role(team_id) IN ('team-owner', 'team-admin')",
            "api.can_read_project(project_id)",
            "api.can_admin_project(project_id)",
        ):
            assert frag in sql, frag

    def test_grants(self):
        sql = migration_sql()
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_meta, api.project_meta TO authenticated" in sql
        assert "GRANT EXECUTE ON FUNCTION private.guard_meta_precedence() TO authenticator, authenticated" in sql

    def test_secret_meta_rows_returns_source(self):
        sql = migration_sql()
        assert "CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)" in sql
        assert "RETURNS TABLE(key text, value text, updated_at timestamptz, source text)" in sql
        assert "source = 'secret'" in sql
        assert "source = 'project'" in sql
        assert "'team' AS source" in sql
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_meta.py -v`
Expected: FAIL — `test_migration_file_exists` errors with `FileNotFoundError` (0017 does not exist yet).

- [ ] **Step 3: Write the migration**

Create `db/migrations/0017_team_project_meta.sql`:

```sql
-- 0017: Team- and project-level metadata with precedence (team > project > secret).
-- Keys defined higher in the hierarchy cannot be overridden lower down.

CREATE TABLE IF NOT EXISTS api.team_meta (
    team_id    uuid NOT NULL REFERENCES api.teams(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    value      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, key)
);

CREATE TABLE IF NOT EXISTS api.project_meta (
    project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    value      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, key)
);

-- Guard: reject writes of a key that already exists higher in the hierarchy.
CREATE OR REPLACE FUNCTION private.guard_meta_precedence() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = api, private
AS $fn$
DECLARE
    v_team_id    uuid;
    v_project_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'team_meta' THEN
        RETURN NEW;
    ELSIF TG_TABLE_NAME = 'project_meta' THEN
        SELECT team_id INTO v_team_id FROM api.projects WHERE id = NEW.project_id;
        IF EXISTS (SELECT 1 FROM api.team_meta WHERE team_id = v_team_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at team level and cannot be overridden', NEW.key;
        END IF;
        RETURN NEW;
    ELSE  -- secret_meta
        SELECT project_id INTO v_project_id FROM api.secrets WHERE id = NEW.secret_id;
        SELECT team_id    INTO v_team_id    FROM api.projects WHERE id = v_project_id;
        IF EXISTS (SELECT 1 FROM api.team_meta WHERE team_id = v_team_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at team level and cannot be overridden', NEW.key;
        END IF;
        IF EXISTS (SELECT 1 FROM api.project_meta WHERE project_id = v_project_id AND key = NEW.key) THEN
            RAISE EXCEPTION 'metadata key % is defined at project level and cannot be overridden', NEW.key;
        END IF;
        RETURN NEW;
    END IF;
END;
$fn$;

DROP TRIGGER IF EXISTS team_meta_guard ON api.team_meta;
CREATE TRIGGER team_meta_guard BEFORE INSERT OR UPDATE ON api.team_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

DROP TRIGGER IF EXISTS project_meta_guard ON api.project_meta;
CREATE TRIGGER project_meta_guard BEFORE INSERT OR UPDATE ON api.project_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

DROP TRIGGER IF EXISTS secret_meta_guard ON api.secret_meta;
CREATE TRIGGER secret_meta_guard BEFORE INSERT OR UPDATE ON api.secret_meta
    FOR EACH ROW EXECUTE FUNCTION private.guard_meta_precedence();

-- RLS: read for anyone with visibility, write for admins only.
ALTER TABLE api.team_meta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS team_meta_select ON api.team_meta;
CREATE POLICY team_meta_select ON api.team_meta FOR SELECT TO authenticated
    USING (api.team_role(team_id) IS NOT NULL);
DROP POLICY IF EXISTS team_meta_admin ON api.team_meta;
CREATE POLICY team_meta_admin ON api.team_meta FOR ALL TO authenticated
    USING (api.team_role(team_id) IN ('team-owner', 'team-admin'))
    WITH CHECK (api.team_role(team_id) IN ('team-owner', 'team-admin'));

ALTER TABLE api.project_meta ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_meta_select ON api.project_meta;
CREATE POLICY project_meta_select ON api.project_meta FOR SELECT TO authenticated
    USING (api.can_read_project(project_id));
DROP POLICY IF EXISTS project_meta_admin ON api.project_meta FOR ALL;
CREATE POLICY project_meta_admin ON api.project_meta FOR ALL TO authenticated
    USING (api.can_admin_project(project_id))
    WITH CHECK (api.can_admin_project(project_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON api.team_meta, api.project_meta TO authenticated;
GRANT EXECUTE ON FUNCTION private.guard_meta_precedence() TO authenticator, authenticated;

-- Merged read view for secrets: inherited metadata flows down.
-- Precedence on key collision: team > project > secret. Adds a source column.
CREATE OR REPLACE FUNCTION private.secret_meta_rows(p_secret uuid)
RETURNS TABLE(key text, value text, updated_at timestamptz, source text)
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = api, private
AS $fn$
WITH scope AS (
    SELECT s.project_id AS project_id, p.team_id AS team_id
    FROM api.secrets s
    JOIN api.projects p ON p.id = s.project_id
    WHERE s.id = p_secret
),
own AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.secret_meta m
    WHERE m.secret_id = p_secret
),
pm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.project_meta m
    JOIN scope ON scope.project_id = m.project_id
),
tm AS (
    SELECT m.key, m.value, m.updated_at
    FROM api.team_meta m
    JOIN scope ON scope.team_id = m.team_id
),
merged AS (
    SELECT key, value, updated_at, 'team' AS source FROM tm
    UNION ALL
    SELECT key, value, updated_at, 'project' AS source FROM pm
    UNION ALL
    SELECT key, value, updated_at, 'secret' AS source FROM own
)
SELECT DISTINCT ON (key) key, value, updated_at, source
FROM merged
WHERE api.can_access_secret(p_secret, 'read')
ORDER BY key, source = 'secret', source = 'project';
$fn$;
```

Notes for the implementer:
- `ORDER BY key, source = 'secret', source = 'project'` + `DISTINCT ON (key)` picks team first, then project, then secret for a duplicated key (boolean `false` sorts before `true`).
- The trigger on `api.secret_meta` also fires on the `DO UPDATE` arm of existing upserts, so overrides are blocked on both insert and update.
- `SECURITY DEFINER` on the guard is required: a project admin may have no team role, and the guard must still read `api.team_meta`/`api.project_meta`.
- No `BEGIN;`/`COMMIT;` — the migrations runner splits and applies statements itself.
- Grants on `api.secret_meta` and EXECUTE on the rewritten `secret_meta_rows` already exist from 0001 and survive `CREATE OR REPLACE`; do not re-grant.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_meta.py -v`
Expected: PASS (all 7 schema tests).

- [ ] **Step 5: Run the full suite to verify nothing else broke**

Run: `pytest`
Expected: PASS — all pre-existing tests still pass (they mock the DB; the new file is additive).

- [ ] **Step 6: Commit**

```bash
rtk git add db/migrations/0017_team_project_meta.sql tests/test_meta.py
rtk git commit -m "feat: team/project metadata tables with precedence guard"
```

---

### Task 2: Team metadata — UI tab and write routes

**Files:**
- Modify: `app/routes/teams/teams.py` (tab whitelist ~line 101, demote ~line 133, tab-data elif chain ~line 136+, render kwargs ~line 340; new route functions after `update_team_settings`)
- Modify: `app/routes/teams/__init__.py` (imports ~line 38-44, register ~line 47-78)
- Modify: `app/templates/team.html` (subnav is_admin block lines 38-49, content chain lines 53-62)
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: `api.team_meta` table (Task 1); `db.team(cur, team_id)` helper; `audit.log_org(cur, team_id=..., action=..., detail=...)`; `db.as_user` context manager; flask `flash`/`redirect`/`url_for`.
- Produces: endpoints `POST /teams/<uuid:team_id>/meta` (form fields `key`, `value`) and `POST /teams/<uuid:team_id>/meta/<meta_key>/delete`; endpoint function names `upsert_team_meta`, `delete_team_meta`; template context key `team_meta` (list of rows with `.key`, `.value`, `.updated_at`); template variables `team_meta` + `is_admin` on the `team_detail` render.

- [ ] **Step 1: Write the failing route tests**

Append to `tests/test_meta.py` (add these imports at the top of the file, merging with the existing ones):

```python
from unittest.mock import MagicMock, patch

from uuid import uuid4

from core import db as core_db


def _login(client, uid):
    with client.session_transaction() as s:
        s["user_id"] = str(uid)
        s["email"] = "u@ex.com"


class TestTeamMetaRoutes:
    def setup_method(self, method=None):
        import app as store

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.tid = uuid4()
        _login(self.client, uuid4())

    def test_upsert_ok(self):
        from routes.teams import teams as teams_mod

        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"r": "team-owner"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/teams/{self.tid}/meta",
                data={"key": "mark.hahl.team", "value": "team1"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" in sql
        assert "ON CONFLICT (team_id, key) DO UPDATE" in sql
        conn.commit.assert_called()

    def test_upsert_denied_for_non_admin(self):
        from routes.teams import teams as teams_mod

        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"r": "team-member"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/teams/{self.tid}/meta",
                data={"key": "k", "value": "v"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" not in sql
        conn.commit.assert_not_called()

    def test_upsert_bad_key_redirects_without_insert(self):
        from routes.teams import teams as teams_mod

        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"r": "team-owner"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/teams/{self.tid}/meta",
                data={"key": "bad key!", "value": "v"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" not in sql

    def test_delete_ok(self):
        from routes.teams import teams as teams_mod

        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"r": "team-admin"}, {"key": "k"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(f"/teams/{self.tid}/meta/k/delete")
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.team_meta" in sql
        conn.commit.assert_called()


class TestTeamMetaTemplates:
    def test_team_subnav_has_meta_link(self):
        src = (REPO_ROOT / "app" / "templates" / "team.html").read_text()
        assert "tab='meta'" in src or 'tab="meta"' in src
        assert "upsert_team_meta" in src

    def test_team_meta_registered(self):
        from tests.helpers import routes_module_src

        src = routes_module_src("teams")
        assert '"/teams/<uuid:team_id>/meta"' in src
        assert '"/teams/<uuid:team_id>/meta/<meta_key>/delete"' in src
```

Also extend the top-of-file imports to include:

```python
from core import db as core_db
```

(The `from tests.helpers import REPO_ROOT` import from Task 1 stays.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_meta.py -v`
Expected: FAIL — routes don't exist yet (404s on the POSTs, `upsert_team_meta` missing from team.html, registrations missing).

- [ ] **Step 3: Implement the routes**

In `app/routes/teams/teams.py`:

1. Add to the tab whitelist at line 101 — change:

```python
    if tab not in ("projects", "members", "groups", "activity", "access", "settings", "webhooks"):
```

to:

```python
    if tab not in ("projects", "members", "groups", "activity", "access", "settings", "webhooks", "meta"):
```

2. Change the demote line (~133-134) from:

```python
    if tab in ("settings", "access", "webhooks") and not is_admin:
        tab = "projects"
```

to:

```python
    if tab in ("settings", "access", "webhooks", "meta") and not is_admin:
        tab = "projects"
```

3. Inside the same `with db.as_user(...) as conn, conn.cursor() as cur:` block, add a branch to the tab-data elif chain (place it next to the existing `settings` branch):

```python
        elif tab == "meta":
            cur.execute(
                "SELECT key, value, updated_at FROM api.team_meta WHERE team_id = %s ORDER BY key",
                (str(team_id),),
            )
            team_meta = cur.fetchall() or []
```

4. Add `team_meta=team_meta` to the `render_template(...)` kwargs (near `active_tab=tab, is_admin=is_admin`). If `team_meta` may be unbound when the render happens for other tabs, pre-initialize `team_meta: list = []` in the pre-init block near line 103-115.

5. Add the two new route functions after `update_team_settings` (copy the role-check prologue from it):

```python
@authz.login_required
def upsert_team_meta(team_id):
    meta_url = url_for("team_detail", team_id=team_id, tab="meta")
    key = (request.form.get("key") or "").strip()
    value = (request.form.get("value") or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", key):
        flash("Metadata key must start with a letter/digit and use only A-Z, a-z, 0-9, ., _, - (max 64)", "error")
        return redirect(meta_url)
    if len(value) > 2000:
        value = value[:2000]
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        role = (cur.fetchone() or {}).get("r")
        if role not in ("team-owner", "team-admin"):
            flash("Only owners or admins can manage team metadata", "error")
            return redirect(meta_url)
        try:
            cur.execute(
                "INSERT INTO api.team_meta (team_id, key, value, updated_at) VALUES (%s, %s, %s, now()) "
                "ON CONFLICT (team_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                (str(team_id), key, value),
            )
            audit.log_org(cur, team_id=str(team_id), action="team_meta", detail=f"meta {key}")
            conn.commit()
            flash(f"Metadata “{key}” saved", "ok")
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                flash("Metadata key is defined at team/project level and cannot be overridden.", "error")
            else:
                flash("Could not save the metadata. Try again.", "error")
    return redirect(meta_url)


@authz.login_required
def delete_team_meta(team_id, meta_key):
    meta_url = url_for("team_detail", team_id=team_id, tab="meta")
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.team_role(%s) AS r", (str(team_id),))
        role = (cur.fetchone() or {}).get("r")
        if role not in ("team-owner", "team-admin"):
            flash("Only owners or admins can manage team metadata", "error")
            return redirect(meta_url)
        try:
            cur.execute(
                "DELETE FROM api.team_meta WHERE team_id = %s AND key = %s RETURNING key",
                (str(team_id), meta_key),
            )
            if not cur.fetchone():
                conn.rollback()
                flash("Field not found or not permitted", "error")
            else:
                audit.log_org(cur, team_id=str(team_id), action="team_meta", detail=f"meta {meta_key}")
                conn.commit()
                flash(f"Metadata “{meta_key}” removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not remove the metadata. Try again.", "error")
    return redirect(meta_url)
```

6. Add `import re` at the top of `teams.py` with the other stdlib imports.

In `app/routes/teams/__init__.py`:

7. Add `delete_team_meta`, `upsert_team_meta` to the import list from `.teams` (lines 38-44).
8. In `register(app)` add:

```python
    app.post("/teams/<uuid:team_id>/meta")(upsert_team_meta)
    app.post("/teams/<uuid:team_id>/meta/<meta_key>/delete")(delete_team_meta)
```

- [ ] **Step 4: Implement the template changes**

In `app/templates/team.html`:

1. In the is_admin subnav block (lines 38-49), after the Settings link, add:

```html
        <a href="{{ url_for('team_detail', team_id=team.id, tab='meta') }}" class="page-subnav-link {% if active_tab == 'meta' %}active{% endif %}"{% if active_tab == 'meta' %} aria-current="page"{% endif %}>Metadata</a>
```

2. In the content chain (lines 53-62), before the final `{% endif %}` (or alongside the settings branch), add:

```html
    {% elif active_tab == 'meta' and is_admin %}
    <section>
      <h2>Team metadata</h2>
      <p class="muted">Metadata here appears on every project and secret in the team. Lower levels cannot override these keys.</p>
      <form method="post" action="{{ url_for('upsert_team_meta', team_id=team.id) }}" class="row">
        <input type="hidden" name="_csrf" value="{{ csrf_token }}">
        <label>Key <input name="key" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" maxlength="64" placeholder="e.g. cost-center"></label>
        <label>Value <input name="value" maxlength="2000"></label>
        <button type="submit">Save</button>
      </form>
      {% if team_meta %}
      <div class="table">
        <table>
          <thead><tr><th>Key</th><th>Value</th><th>Updated</th><th></th></tr></thead>
          <tbody>
            {% for m in team_meta %}
            <tr>
              <td><code class="k">{{ m.key }}</code></td>
              <td>{{ m.value }}</td>
              <td>{{ m.updated_at.strftime('%Y-%m-%d %H:%M') if m.updated_at else '' }}</td>
              <td class="acts">
                <form method="post" action="{{ url_for('delete_team_meta', team_id=team.id, meta_key=m.key) }}" class="inline" onsubmit="return confirm('Remove metadata “{{ m.key }}”?')">
                  <input type="hidden" name="_csrf" value="{{ csrf_token }}">
                  <button type="submit" class="link danger">Remove</button>
                </form>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <p class="empty">No team metadata yet.</p>
      {% endif %}
    </section>
    {% endif %}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_meta.py -v`
Expected: PASS — including the new `TestTeamMetaRoutes` and `TestTeamMetaTemplates` classes.

- [ ] **Step 6: Run the full suite and lint**

Run: `pytest` then `tox -e lint`
Expected: PASS both.

- [ ] **Step 7: Commit**

```bash
rtk git add app/routes/teams/teams.py app/routes/teams/__init__.py app/templates/team.html tests/test_meta.py
rtk git commit -m "feat: team metadata tab with precedence-protected keys"
```

---

### Task 3: Project metadata — UI tab and write routes

**Files:**
- Modify: `app/routes/projects/detail.py` (tab whitelist lines 119-130, demote lines 188-194, tab-data elif chain from line 197, render ctx 425-479; new route functions after `update_project_settings`)
- Modify: `app/routes/projects/__init__.py` (imports lines 15-21, register lines 30-44)
- Modify: `app/templates/project.html` (subnav lines 44-77)
- Modify: `app/templates/partials/project_content.html` (elif chain lines 1-13)
- Create: `app/templates/partials/project_meta.html`
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: `api.project_meta` (Task 1); `project_detail`'s existing permission queries (`api.can_admin_project`); `audit.log_org`.
- Produces: endpoints `POST /projects/<uuid:project_id>/meta` and `POST /projects/<uuid:project_id>/meta/<meta_key>/delete`; endpoint function names `upsert_project_meta`, `delete_project_meta`; template context key `project_meta`; new partial `partials/project_meta.html` included for `active_tab == 'meta'`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_meta.py`:

```python
class TestProjectMetaRoutes:
    def setup_method(self, method=None):
        import app as store

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        _login(self.client, uuid4())

    def test_upsert_ok(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"a": True}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/projects/{self.pid}/meta",
                data={"key": "env", "value": "prod"},
            )
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.project_meta" in sql
        conn.commit.assert_called()

    def test_upsert_denied(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"a": False}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(f"/projects/{self.pid}/meta", data={"key": "env", "value": "prod"})
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.project_meta" not in sql
        conn.commit.assert_not_called()

    def test_delete_ok(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"a": True}, {"key": "env"}]
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(f"/projects/{self.pid}/meta/env/delete")
        assert resp.status_code == 302
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.project_meta" in sql
        conn.commit.assert_called()

    def test_project_meta_template_and_registration(self):
        from tests.helpers import routes_module_src

        subnav = (REPO_ROOT / "app" / "templates" / "project.html").read_text()
        assert "tab='meta'" in subnav
        content = (REPO_ROOT / "app" / "templates" / "partials" / "project_content.html").read_text()
        assert 'project_meta.html' in content
        assert (REPO_ROOT / "app" / "templates" / "partials" / "project_meta.html").exists()
        src = routes_module_src("projects")
        assert '"/projects/<uuid:project_id>/meta"' in src
        assert '"/projects/<uuid:project_id>/meta/<meta_key>/delete"' in src
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_meta.py::TestProjectMetaRoutes -v`
Expected: FAIL — routes 404, partial missing.

- [ ] **Step 3: Implement routes and template**

In `app/routes/projects/detail.py`:

1. Add `"meta"` to the tab whitelist (lines 119-130).
2. Add to the demote block (188-194), right after the settings demote:

```python
    if tab == "meta" and not can_admin:
        tab = "secrets"
```

3. In the tab-data elif chain inside the `with db.as_user(...)` block, add (near the settings branch):

```python
        elif tab == "meta":
            cur.execute(
                "SELECT key, value, updated_at FROM api.project_meta WHERE project_id = %s ORDER BY key",
                (str(project_id),),
            )
            project_meta = cur.fetchall() or []
```

Pre-initialize `project_meta: list = []` alongside the other tab variables if the render can happen without that branch running.

4. Add `project_meta=project_meta` to the render kwargs (ctx dict, lines 425-479).

5. Add the route functions after `update_project_settings`:

```python
@authz.login_required
def upsert_project_meta(project_id):
    meta_url = url_for("project_detail", project_id=project_id, tab="meta")
    key = (request.form.get("key") or "").strip()
    value = (request.form.get("value") or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", key):
        flash("Metadata key must start with a letter/digit and use only A-Z, a-z, 0-9, ., _, - (max 64)", "error")
        return redirect(meta_url)
    if len(value) > 2000:
        value = value[:2000]
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
        if not (cur.fetchone() or {}).get("a"):
            flash("You don't have permission to do that", "error")
            return redirect(meta_url)
        cur.execute("SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),))
        team_id = (cur.fetchone() or {}).get("team_id")
        try:
            cur.execute(
                "INSERT INTO api.project_meta (project_id, key, value, updated_at) VALUES (%s, %s, %s, now()) "
                "ON CONFLICT (project_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                (str(project_id), key, value),
            )
            audit.log_org(cur, team_id=str(team_id), project_id=str(project_id), action="project_meta", detail=f"meta {key}")
            conn.commit()
            flash(f"Metadata “{key}” saved", "ok")
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                flash("Metadata key is defined at team/project level and cannot be overridden.", "error")
            else:
                flash("Could not save the metadata. Try again.", "error")
    return redirect(meta_url)


@authz.login_required
def delete_project_meta(project_id, meta_key):
    meta_url = url_for("project_detail", project_id=project_id, tab="meta")
    with db.as_user(session["user_id"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT api.can_admin_project(%s) AS a", (str(project_id),))
        if not (cur.fetchone() or {}).get("a"):
            flash("You don't have permission to do that", "error")
            return redirect(meta_url)
        cur.execute("SELECT team_id FROM api.projects WHERE id = %s", (str(project_id),))
        team_id = (cur.fetchone() or {}).get("team_id")
        try:
            cur.execute(
                "DELETE FROM api.project_meta WHERE project_id = %s AND key = %s RETURNING key",
                (str(project_id), meta_key),
            )
            if not cur.fetchone():
                conn.rollback()
                flash("Field not found or not permitted", "error")
            else:
                audit.log_org(cur, team_id=str(team_id), project_id=str(project_id), action="project_meta", detail=f"meta {meta_key}")
                conn.commit()
                flash(f"Metadata “{meta_key}” removed", "ok")
        except Exception:
            conn.rollback()
            flash("Could not remove the metadata. Try again.", "error")
    return redirect(meta_url)
```

6. Add `import re` to the stdlib imports at the top of `detail.py`.

In `app/routes/projects/__init__.py`:

7. Add `delete_project_meta`, `upsert_project_meta` to the import from `.detail` (lines 15-21) and register:

```python
    app.post("/projects/<uuid:project_id>/meta")(upsert_project_meta)
    app.post("/projects/<uuid:project_id>/meta/<meta_key>/delete")(delete_project_meta)
```

In `app/templates/project.html`:

8. In the `{% if can_admin %}` subnav block (next to Access/Webhooks), add the paired hx-get/href link:

```html
        <a hx-get="{{ url_for('project_detail', project_id=project.id, tab='meta') }}" hx-target="#project-panel" hx-swap="innerHTML" hx-push-url="true" href="{{ url_for('project_detail', project_id=project.id, tab='meta') }}" class="page-subnav-link {% if active_tab == 'meta' %}active{% endif %}"{% if active_tab == 'meta' %} aria-current="page"{% endif %}>Metadata</a>
```

In `app/templates/partials/project_content.html`:

9. Add to the elif chain (before the fallback `{% else %}`):

```html
    {% elif active_tab == 'meta' and can_admin %}{% include "partials/project_meta.html" %}
```

Create `app/templates/partials/project_meta.html`:

10.

```html
<section>
  <h2>Project metadata</h2>
  <p class="muted">Metadata here appears on every secret in the project. Keys defined on the team are inherited and cannot be changed here.</p>
  <form method="post" action="{{ url_for('upsert_project_meta', project_id=project_id) }}" class="row">
    <input type="hidden" name="_csrf" value="{{ csrf_token }}">
    <label>Key <input name="key" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" maxlength="64" placeholder="e.g. env"></label>
    <label>Value <input name="value" maxlength="2000"></label>
    <button type="submit">Save</button>
  </form>
  {% if project_meta %}
  <div class="table">
    <table>
      <thead><tr><th>Key</th><th>Value</th><th>Updated</th><th></th></tr></thead>
      <tbody>
        {% for m in project_meta %}
        <tr>
          <td><code class="k">{{ m.key }}</code></td>
          <td>{{ m.value }}</td>
          <td>{{ m.updated_at.strftime('%Y-%m-%d %H:%M') if m.updated_at else '' }}</td>
          <td class="acts">
            <form method="post" action="{{ url_for('delete_project_meta', project_id=project_id, meta_key=m.key) }}" class="inline" onsubmit="return confirm('Remove metadata “{{ m.key }}”?')">
              <input type="hidden" name="_csrf" value="{{ csrf_token }}">
              <button type="submit" class="link danger">Remove</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <p class="empty">No project metadata yet.</p>
  {% endif %}
</section>
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_meta.py -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest` then `tox -e lint`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
rtk git add app/routes/projects/detail.py app/routes/projects/__init__.py app/templates/project.html app/templates/partials/project_content.html app/templates/partials/project_meta.html tests/test_meta.py
rtk git commit -m "feat: project metadata tab with team-key inheritance"
```

---

### Task 4: Secret meta tab — inherited rows and override flash

**Files:**
- Modify: `app/routes/secrets/crud.py` (`upsert_secret_meta`, lines 119-174 — the except branch)
- Modify: `app/templates/secret_view.html` (meta tab table, lines ~117-142)
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: `private.secret_meta_rows` rows now include `source` ('team'/'project'/'secret') from Task 1; existing `upsert_secret_meta` route.
- Produces: inherited metadata rows display with a muted source label and no Remove form; guard violations flash "Metadata key is defined at team/project level and cannot be overridden." instead of the generic save error.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_meta.py`:

```python
class TestSecretMetaOverride:
    def setup_method(self, method=None):
        import app as store

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.sid = uuid4()
        _login(self.client, uuid4())

    def test_override_violation_flashes_friendly_error(self):
        from routes.secrets import crud as crud_mod

        conn, cur = MagicMock(), MagicMock()
        calls = {"n": 0}

        def execute(sql, *a, **k):
            calls["n"] += 1
            if "INSERT INTO api.secret_meta" in sql:
                raise Exception("metadata key mark.hahl.team is defined at team level and cannot be overridden")
            if "api.can_access_secret" in sql:
                cur.fetchone.side_effect = [{"w": True}]
            else:
                cur.fetchone.return_value = {}

        cur.execute.side_effect = execute
        with patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.post(
                f"/projects/{self.pid}/secrets/{self.sid}/meta",
                data={"key": "mark.hahl.team", "value": "x"},
            )
        assert resp.status_code == 302

    def test_template_shows_source_and_hides_remove_for_inherited(self):
        src = (REPO_ROOT / "app" / "templates" / "secret_view.html").read_text()
        assert "m.source" in src
        assert "inherited" in src.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_meta.py::TestSecretMetaOverride -v`
Expected: `test_template_shows_source...` FAIL (no `m.source` in template yet). The route test passes already (generic except catches everything) but is kept as a regression guard.

- [ ] **Step 3: Implement**

In `app/routes/secrets/crud.py`, change the except branch of `upsert_secret_meta` from:

```python
        except Exception:
            conn.rollback()
            flash("Could not save the secret. Try again.", "error")
```

to:

```python
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                flash("Metadata key is defined at team/project level and cannot be overridden.", "error")
            else:
                flash("Could not save the secret. Try again.", "error")
```

In `app/templates/secret_view.html`, in the meta table body row loop, change the value/Remove cells to:

```html
              <td><code class="k">{{ m.key }}</code></td>
              <td>{{ m.value }}</td>
              {% if m.source and m.source != 'secret' %}
              <td><span class="muted">inherited · {{ m.source }}</span></td>
              {% endif %}
```

and gate the Remove cell on the row being secret-owned. Concretely, wrap the existing Remove `<td class="acts">...</td>` in:

```html
              {% if not m.source or m.source == 'secret' %}
              <td class="acts">
                ...existing Remove form...
              </td>
              {% endif %}
```

and change the empty-acts header cell logic: keep the existing `{% if can_write %}<th></th>{% endif %}` in thead (the column exists whenever the user can write; inherited rows simply leave the acts cell empty). The simplest correct form: keep the acts cell for secret-owned rows only, and render an empty `<td></td>` for inherited rows when `can_write` is true so columns stay aligned:

```html
              {% if can_write and (not m.source or m.source == 'secret') %}
              ...existing acts cell...
              {% elif can_write %}
              <td></td>
              {% endif %}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_meta.py -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest` then `tox -e lint`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
rtk git add app/routes/secrets/crud.py app/templates/secret_view.html tests/test_meta.py
rtk git commit -m "feat: show inherited metadata on secret page, friendly override error"
```

---

### Task 5: PAT management API — secret meta override returns 409

**Files:**
- Modify: `app/routes/mgmt_api/secrets.py` (`mgmt_upsert_secret_meta` try/except, lines ~84-95)
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: existing `mgmt_upsert_secret_meta` (PATCH `{base}/projects/<project_ref>/secrets/<path:key>/meta`).
- Produces: HTTP 409 with `{"error": "metadata key is defined at team/project level and cannot be overridden"}` when the DB precedence guard fires; other failures still propagate (500).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_meta.py`:

```python
class TestMgmtSecretMetaOverride:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_upsert_override_returns_409(self):
        conn, cur = MagicMock(), MagicMock()

        def execute(sql, *a, **k):
            if "INSERT INTO api.secret_meta" in sql:
                raise Exception("metadata key k is defined at team level and cannot be overridden")
            if "api.can_access_secret" in sql:
                cur.fetchone.side_effect = [{"w": True}]
            else:
                cur.fetchone.return_value = {"id": str(self.sid)}

        cur.execute.side_effect = execute
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/projects/{self.pid}/secrets/mykey/meta",
                data={"value": "x"},
                headers=self.headers,
            )
        assert resp.status_code == 409
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_meta.py::TestMgmtSecretMetaOverride -v`
Expected: FAIL — current code re-raises, producing 500.

- [ ] **Step 3: Implement**

In `app/routes/mgmt_api/secrets.py`, `mgmt_upsert_secret_meta`, change:

```python
        except Exception:
            conn.rollback()
            raise
```

to:

```python
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                return (
                    jsonify({"error": "metadata key is defined at team/project level and cannot be overridden"}),
                    409,
                )
            raise
```

Apply the same change in `mgmt_delete_secret_meta` (deleting an inherited key is impossible by construction — the row only exists in `api.secret_meta` if it is secret-owned — but a failed delete that hits the guard should not 500).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_meta.py::TestMgmtSecretMetaOverride -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint, commit**

Run: `pytest` then `tox -e lint`

```bash
rtk git add app/routes/mgmt_api/secrets.py tests/test_meta.py
rtk git commit -m "feat: mgmt API returns 409 when overriding inherited metadata"
```

---

### Task 6: PAT management API — team metadata endpoints

**Files:**
- Modify: `app/routes/mgmt_api/teams.py` (new functions at end of file)
- Modify: `app/routes/mgmt_api/__init__.py` (imports + registrations in the teams block, lines 39-48 / 65-79)
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: `.helpers._require_pat`, `.helpers._resolve_team`; `_META_KEY_RE`, `_META_VALUE_MAX` from `.secrets`; `api.team_meta` table; `audit.log_org`.
- Produces: `PATCH /api/v1/manage/teams/<team_ref>/meta/<meta_key>` (body `{"value": "..."}`) → `mgmt_upsert_team_meta(team_ref, meta_key)`; `DELETE /api/v1/manage/teams/<team_ref>/meta/<meta_key>` → `mgmt_delete_team_meta(team_ref, meta_key)`. Responses mirror the secret meta endpoints: 200 `{"ok": true, "team_ref": ..., "meta_key": ..., "value": ...}`, 400 bad key, 403 forbidden, 404 not found, 409 override attempt.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_meta.py`:

```python
class TestMgmtTeamMeta:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.tid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_requires_pat(self):
        with self._pats:
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/k",
                data={"value": "v"},
                headers={"Authorization": "Bearer ss_notapat"},
            )
        assert resp.status_code == 401

    def test_upsert_ok(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"id": str(self.tid)}, {"r": "team-owner"}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/mark.hahl.team",
                data={"value": "team1"},
                headers=self.headers,
            )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True and body["meta_key"] == "mark.hahl.team"
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.team_meta" in sql
        conn.commit.assert_called()

    def test_upsert_bad_key_400(self):
        conn, cur = MagicMock(), MagicMock()
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/bad%20key",
                data={"value": "v"},
                headers=self.headers,
            )
        assert resp.status_code == 400

    def test_upsert_denied_403(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"id": str(self.tid)}, {"r": "team-member"}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/teams/{self.tid}/meta/k",
                data={"value": "v"},
                headers=self.headers,
            )
        assert resp.status_code == 403

    def test_delete_ok(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"id": str(self.tid)}, {"r": "team-owner"}, {"key": "k"}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.delete(f"/api/v1/manage/teams/{self.tid}/meta/k", headers=self.headers)
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.team_meta" in sql
```

Add the missing import at the top of the file:

```python
from auth import pats
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_meta.py::TestMgmtTeamMeta -v`
Expected: FAIL — 404s, routes unregistered.

- [ ] **Step 3: Implement**

In `app/routes/mgmt_api/teams.py`, add at the end (imports come from the existing header: `jsonify`, `request`, `audit`, `db`, `_require_pat`, `_resolve_team`; add `from .secrets import _META_KEY_RE, _META_VALUE_MAX`):

```python
def _team_meta_allowed(cur, tid: str) -> bool:
    cur.execute("SELECT api.team_role(%s) AS r", (tid,))
    return (cur.fetchone() or {}).get("r") in ("team-owner", "team-admin")


def mgmt_upsert_team_meta(team_ref, meta_key):
    uid, err = _require_pat()
    if err:
        return err
    if not _META_KEY_RE.match(meta_key):
        return (
            jsonify({"error": "metadata key must start with a letter/digit and use only A-Z a-z 0-9 . _ - (max 64)"}),
            400,
        )
    value = (request.get_json(silent=True) or {}).get("value") or ""
    value = value[:_META_VALUE_MAX]
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        if not _team_meta_allowed(cur, tid):
            return jsonify({"error": "forbidden"}), 403
        try:
            cur.execute(
                "INSERT INTO api.team_meta (team_id, key, value, updated_at) VALUES (%s, %s, %s, now()) "
                "ON CONFLICT (team_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                (tid, meta_key, value),
            )
            audit.log_org(cur, team_id=tid, action="team_meta", detail=f"meta {meta_key}")
            conn.commit()
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                return (
                    jsonify({"error": "metadata key is defined at team/project level and cannot be overridden"}),
                    409,
                )
            raise
    return jsonify({"ok": True, "team_ref": team_ref, "meta_key": meta_key, "value": value})


def mgmt_delete_team_meta(team_ref, meta_key):
    uid, err = _require_pat()
    if err:
        return err
    if not _META_KEY_RE.match(meta_key):
        return jsonify({"error": "metadata key must start with a letter/digit and use only A-Z a-z 0-9 . _ - (max 64)"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        tid = _resolve_team(cur, team_ref)
        if not tid:
            return jsonify({"error": "not found"}), 404
        if not _team_meta_allowed(cur, tid):
            return jsonify({"error": "forbidden"}), 403
        cur.execute("SELECT 1 FROM api.team_meta WHERE team_id = %s AND key = %s", (tid, meta_key))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404
        cur.execute("DELETE FROM api.team_meta WHERE team_id = %s AND key = %s", (tid, meta_key))
        audit.log_org(cur, team_id=tid, action="team_meta", detail=f"meta {meta_key}")
        conn.commit()
    return jsonify({"ok": True, "team_ref": team_ref, "meta_key": meta_key})
```

Note: for this endpoint the key comes from the URL (`<meta_key>`), not the JSON body — unlike the secret endpoints where the secret key occupies the path.

In `app/routes/mgmt_api/__init__.py`:

1. Add to the `.teams` import block: `mgmt_delete_team_meta`, `mgmt_upsert_team_meta`.
2. In `register(app)`, in the teams block, add:

```python
    app.patch(f"{base}/teams/<team_ref>/meta/<meta_key>")(mgmt_upsert_team_meta)
    app.delete(f"{base}/teams/<team_ref>/meta/<meta_key>")(mgmt_delete_team_meta)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_meta.py::TestMgmtTeamMeta -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint, commit**

Run: `pytest` then `tox -e lint`

```bash
rtk git add app/routes/mgmt_api/teams.py app/routes/mgmt_api/__init__.py tests/test_meta.py
rtk git commit -m "feat: mgmt API team metadata PATCH/DELETE endpoints"
```

---

### Task 7: PAT management API — project metadata endpoints

**Files:**
- Modify: `app/routes/mgmt_api/projects.py` (new functions at end of file)
- Modify: `app/routes/mgmt_api/__init__.py` (imports + registrations in the projects block)
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: `.helpers._require_pat`, `.helpers._resolve_project`; `_META_KEY_RE`, `_META_VALUE_MAX` from `.secrets`; `api.project_meta`; `audit.log_org`.
- Produces: `PATCH /api/v1/manage/projects/<project_ref>/meta/<meta_key>` → `mgmt_upsert_project_meta(project_ref, meta_key)`; `DELETE /api/v1/manage/projects/<project_ref>/meta/<meta_key>` → `mgmt_delete_project_meta(project_ref, meta_key)`. Same status-code contract as Task 6, with `api.can_admin_project` as the permission check.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_meta.py`:

```python
class TestMgmtProjectMeta:
    def setup_method(self, method=None):
        import app as store
        from auth import pats

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_upsert_ok(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {"a": True}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/projects/{self.pid}/meta/env",
                data={"value": "prod"},
                headers=self.headers,
            )
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "INSERT INTO api.project_meta" in sql
        conn.commit.assert_called()

    def test_upsert_denied_403(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {"a": False}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.patch(
                f"/api/v1/manage/projects/{self.pid}/meta/env",
                data={"value": "prod"},
                headers=self.headers,
            )
        assert resp.status_code == 403

    def test_delete_ok(self):
        conn, cur = MagicMock(), MagicMock()
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {"a": True}, {"key": "env"}]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.delete(f"/api/v1/manage/projects/{self.pid}/meta/env", headers=self.headers)
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "DELETE FROM api.project_meta" in sql
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_meta.py::TestMgmtProjectMeta -v`
Expected: FAIL — 404s.

- [ ] **Step 3: Implement**

In `app/routes/mgmt_api/projects.py`, add (imports from existing header; add `from .secrets import _META_KEY_RE, _META_VALUE_MAX`):

```python
def mgmt_upsert_project_meta(project_ref, meta_key):
    uid, err = _require_pat()
    if err:
        return err
    if not _META_KEY_RE.match(meta_key):
        return (
            jsonify({"error": "metadata key must start with a letter/digit and use only A-Z a-z 0-9 . _ - (max 64)"}),
            400,
        )
    value = (request.get_json(silent=True) or {}).get("value") or ""
    value = value[:_META_VALUE_MAX]
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS a", (pid,))
        if not (cur.fetchone() or {}).get("a"):
            return jsonify({"error": "forbidden"}), 403
        try:
            cur.execute(
                "INSERT INTO api.project_meta (project_id, key, value, updated_at) VALUES (%s, %s, %s, now()) "
                "ON CONFLICT (project_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                (pid, meta_key, value),
            )
            audit.log_org(cur, project_id=pid, action="project_meta", detail=f"meta {meta_key}")
            conn.commit()
        except Exception as exc:
            conn.rollback()
            if "cannot be overridden" in str(exc):
                return (
                    jsonify({"error": "metadata key is defined at team/project level and cannot be overridden"}),
                    409,
                )
            raise
    return jsonify({"ok": True, "project_ref": project_ref, "meta_key": meta_key, "value": value})


def mgmt_delete_project_meta(project_ref, meta_key):
    uid, err = _require_pat()
    if err:
        return err
    if not _META_KEY_RE.match(meta_key):
        return jsonify({"error": "metadata key must start with a letter/digit and use only A-Z a-z 0-9 . _ - (max 64)"}), 400
    with db.as_user(uid) as conn, conn.cursor() as cur:
        pid = _resolve_project(cur, project_ref)
        if not pid:
            return jsonify({"error": "not found"}), 404
        cur.execute("SELECT api.can_admin_project(%s) AS a", (pid,))
        if not (cur.fetchone() or {}).get("a"):
            return jsonify({"error": "forbidden"}), 403
        cur.execute("SELECT 1 FROM api.project_meta WHERE project_id = %s AND key = %s", (pid, meta_key))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404
        cur.execute("DELETE FROM api.project_meta WHERE project_id = %s AND key = %s", (pid, meta_key))
        audit.log_org(cur, project_id=pid, action="project_meta", detail=f"meta {meta_key}")
        conn.commit()
    return jsonify({"ok": True, "project_ref": project_ref, "meta_key": meta_key})
```

In `app/routes/mgmt_api/__init__.py`:

1. Add `mgmt_delete_project_meta`, `mgmt_upsert_project_meta` to the `.projects` import.
2. Register in the projects block:

```python
    app.patch(f"{base}/projects/<project_ref>/meta/<meta_key>")(mgmt_upsert_project_meta)
    app.delete(f"{base}/projects/<project_ref>/meta/<meta_key>")(mgmt_delete_project_meta)
```

Note: Flask route matching is order-independent here because `<project_ref>` (string) will also match a secret path only if no more specific route exists first — but `.../meta/<meta_key>` is more specific than `.../secrets/<path:key>/meta/<meta_key>`? No — they differ in the `secrets/` literal segment, so they cannot collide. A PATCH to `/projects/X/meta/k` never matches the secrets rule, which requires `/secrets/` in the path.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_meta.py::TestMgmtProjectMeta -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint, commit**

Run: `pytest` then `tox -e lint`

```bash
rtk git add app/routes/mgmt_api/projects.py app/routes/mgmt_api/__init__.py tests/test_meta.py
rtk git commit -m "feat: mgmt API project metadata PATCH/DELETE endpoints"
```

---

### Task 8: ESO/PAT list — metadata from merged rows

**Files:**
- Modify: `app/routes/eso/secrets.py` (list meta PAT branch main query, line ~275)
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: rewritten `private.secret_meta_rows(s.id)` from Task 1.
- Produces: the PAT meta list endpoint returns merged metadata (team/project keys included) per secret. The `q=` search filter stays on `api.secret_meta` (searches secret-owned keys only — deliberate scope cut).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_meta.py`:

```python
class TestEsoListMergedMeta:
    def setup_method(self, method=None):
        import app as store
        from auth import pats
        from routes import eso as eso_routes

        store.app.config["TESTING"] = True
        self.client = store.app.test_client()
        self.pid = uuid4()
        self.uid = uuid4()
        self.headers = {"Authorization": "Bearer pat_test"}
        self._pats = patch.object(pats, "resolve", return_value=self.uid)

    def test_list_uses_secret_meta_rows(self):
        conn, cur = MagicMock(), MagicMock()
        row = {
            "id": str(uuid4()),
            "key": "svc",
            "note": None,
            "kind": "credential",
            "expires_at": None,
            "rotation_interval_days": None,
            "rotation_owner": None,
            "rotation_next_at": None,
            "rotated_at": None,
            "created_at": None,
            "updated_at": None,
            "last_accessed_at": None,
            "metadata": {"mark.hahl.team": "team1"},
        }
        cur.fetchone.side_effect = [{"id": str(self.pid)}, {}, {}, {}, {}]
        cur.fetchall.return_value = [row]
        with self._pats, patch.object(core_db, "as_user", return_value=conn):
            resp = self.client.get(f"/eso/v1/projects/{self.pid}/secrets?meta=1", headers=self.headers)
        assert resp.status_code == 200
        sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
        assert "FROM private.secret_meta_rows(s.id) m" in sql
        items = resp.get_json()["items"]
        assert items[0]["metadata"]["mark.hahl.team"] == "team1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_meta.py::TestEsoListMergedMeta -v`
Expected: FAIL — SQL still reads `FROM api.secret_meta m WHERE m.secret_id = s.id`.

- [ ] **Step 3: Implement**

In `app/routes/eso/secrets.py`, in the PAT list meta branch main query (line ~275), replace:

```sql
COALESCE((SELECT jsonb_object_agg(m.key, m.value) FROM api.secret_meta m WHERE m.secret_id = s.id), '{}'::jsonb) AS metadata
```

with:

```sql
COALESCE((SELECT jsonb_object_agg(m.key, m.value) FROM private.secret_meta_rows(s.id) m), '{}'::jsonb) AS metadata
```

Everything else in the branch (q filter, json decode, `_meta_item`, audit, commit) is unchanged. `q=` search keeps matching only secret-owned metadata (`api.secret_meta`) — that is the deliberate scope cut; inherited keys are surfaced in results, not in search.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_meta.py::TestEsoListMergedMeta -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest` then `tox -e lint`
Expected: PASS. If `tests/test_eso.py` meta-list tests assert on the old SQL string, update those assertions to expect `private.secret_meta_rows(s.id)`.

- [ ] **Step 6: Commit**

```bash
rtk git add app/routes/eso/secrets.py tests/test_meta.py
rtk git commit -m "feat: PAT meta list returns inherited team/project metadata"
```

---

## Self-Review Checklist (run after implementation, before final PR)

1. **Spec coverage:** team meta visible on project + secret ✓ (Tasks 1, 2, 3, 4); PAT get returns merged rows ✓ (Task 1 — `eso/secrets.py` get already reads `secret_meta_rows`, extra `source` column is ignored by the dict comprehension at line ~137); PAT list merged ✓ (Task 8); no override lower down ✓ (Task 1 guard + friendly errors in Tasks 4, 5, 6, 7); management endpoints ✓ (Tasks 6, 7).
2. **Machine-token path untouched:** `private.machine_list_meta` output has no metadata column and is not changed by this plan — machine clients unaffected.
3. **Test the collision case manually after deploy** (not mockable in the suite): set team meta `k`, then attempt project meta `k` → expect flash "Metadata key is defined at team/project level and cannot be overridden." and 409 via PAT.