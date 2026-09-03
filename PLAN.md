# PLAN.md — Folders as objects / tree view

First-class folders inside a project, with a one-level tree in the secrets UI
and folder-scope RBAC. Hierarchical keys already exist (`prod/db/password`,
agent `hosts/web01`); they are opaque unique strings with no container, no
folder ACL, and a flat paged table.

Do not edit `db/migrations/0001_init.sql`. This feature is additive migration
`0003_folders.sql`.

---

## 1. Goal

An operator can:

1. See a project’s secrets as a directory tree (folders first, then leaves).
2. Create an empty folder and create secrets inside it.
3. Bind a user or group to a folder so that grant inherits to descendant
   secrets with `access_mode = inherit`.
4. Move/rename a folder (rewrites descendant keys in one transaction).
5. Keep every existing API key (`GET /eso/v1/.../secrets/prod/db/password`)
   working without a client change.

Success: `hosts/web01` and `prod/db/password` show up under folders `hosts/`
and `prod/db/`; a `secret-reveal` binding on folder `prod` lets a contractor
reveal `prod/*` inherit secrets and nothing else.

---

## 2. Non-goals (this work)

- Changing the unique identity of a secret. The live unique key remains
  `api.secrets.key` (full path). ESO, CLI, machine-token globs, and
  corvus-agent keep using that string.
- Folder-scoped machine tokens. Tokens stay exact-key / glob allow-lists.
- Tree view on the team-wide `/secrets` list, Shared, Trash, search, or
  due-dashboard. Those stay flat (full key).
- Infinite-expand accordion of the whole project in one query.
- Folders that span projects or teams.
- Auto-deleting a folder when its last secret is removed.
- CSI / sidecar / Vault KV-v2 compatibility.

---

## 3. Locked design

### 3.1 S3-style paths, not a POSIX filesystem

A **secret** is a file. A **folder** is a prefix. Both may exist at the same
path segment, because that already happens in production data:

| Row | Meaning |
|-----|---------|
| secret key `prod` | leaf at project root |
| folder path `prod` | container for `prod/db`, `prod/api-key` |

The tree at project root shows **both**: a secret named `prod` and a folder
named `prod/`. Do **not** forbid this on backfill. Do **not** invent a
synthetic rename (`prod` → `prod-file`).

### 3.2 Folder path = key prefix

```
secret key:     prod/db/password
folders:        prod          (parent_id NULL)
                prod/db       (parent_id → prod)
secret.folder_id → prod/db
```

- `api.folders.path` has **no** leading or trailing slash.
- Folder **name** is the last segment (`db`).
- Root of the tree is `folder_id IS NULL` (not a real row).
- Max depth: **16** segments. Segment charset: `^[A-Za-z0-9._-]{1,64}$`.
  Reject empty segments, `.`, `..`, `//`, leading/trailing `/`.

The full secret key is always `folder.path + '/' + leaf` (or just `leaf` at
root). Moving a folder rewrites keys so globs like `prod/*` stay coherent.

### 3.3 Tree UI is one directory at a time

Project → Secrets with `?folder=<uuid-or-empty>`:

- Breadcrumb: `Secrets / prod / db`
- Rows: child folders (name, secret count the caller can see), then leaf
  secrets at this level (leaf name in the Key column; `title` = full key)
- Search `q=` on this tab **escapes** to the existing flat paged list
- “All secrets” link: same flat list, no `folder` param
- Default: tree when the project has at least one folder row; otherwise
  today’s table (so empty/simple projects do not change)

Page size stays `paging.DEFAULT_PAGE_SIZE` (25), applied to
`(folders + secrets)` at this level, folders first.

### 3.4 RBAC: folder sits on the scope chain

```
cluster → team → project → folder → …parent folders… → folder → secret
```

`api.rbac_scope_chain('secret', sid)` becomes:

```
secret, folder, parent-folder*, project, team, cluster
```

`api.rbac_scope_chain('folder', fid)` becomes:

```
folder, parent-folder*, project, team, cluster
```

Bindings:

- Reuse built-in `secret-read` / `secret-reveal` / `secret-write` **at folder
  scope** (not new role names).
- `restricted` secrets still ignore ancestor folder/project/team bindings.
  Folder ACL is an inherit-mode grant, same as a project binding. Admin floor
  (`can_admin_project`) is unchanged.
- Project admins manage folder bindings (`can_manage_rbac('folder', fid)`
  true iff they can manage the parent project).
- Machine tokens **do not** consult folder bindings.

### 3.5 Lifecycle

| Action | Behaviour |
|--------|-----------|
| Create secret with `/` in key | `ensure_folder_path` for every ancestor; set `folder_id` |
| Create secret without `/` | `folder_id` NULL (or the current UI folder if the form prefix is set) |
| Create empty folder | insert folder + ancestors; no secret |
| Rename/move folder | rewrite `folders.path` + descendant `folders.path` + descendant `secrets.key` in one transaction; refuse if a target key/path collides |
| Delete empty folder | hard-delete folder row (CASCADE bindings); refuse if children or secrets |
| Delete folder recursive | soft-delete descendant **secrets** (trash, existing path); then delete folder rows that have no remaining live/trashed secrets. Trashed secrets keep `folder_id` so restore lands back in the folder |
| Restore secret | `ensure_folder_path` again |
| Last secret leaves a folder | folder stays (may hold ACL). User deletes it explicitly |

---

## 4. Schema — `db/migrations/0003_folders.sql`

Idempotent. Do not wrap in BEGIN/COMMIT (runner does). Next number after
`0002_cli_session_tokens.sql`.

### 4.1 `api.folders`

```sql
CREATE TABLE IF NOT EXISTS api.folders (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES api.projects(id) ON DELETE CASCADE,
  parent_id  uuid REFERENCES api.folders(id) ON DELETE CASCADE,
  name       text NOT NULL
               CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$'
                  AND name NOT IN ('.', '..')),
  path       text NOT NULL
               CHECK (path ~ '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,15}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES private.users(id) ON DELETE SET NULL,
  UNIQUE (project_id, path),
  CHECK (
    (parent_id IS NULL AND path = name)
    OR (parent_id IS NOT NULL AND path LIKE '%/' || name)
  )
);
CREATE INDEX IF NOT EXISTS folders_project_parent_idx
  ON api.folders (project_id, parent_id);
```

Root folders: `parent_id IS NULL`, `path = name`.

### 4.2 `api.secrets.folder_id`

```sql
ALTER TABLE api.secrets
  ADD COLUMN IF NOT EXISTS folder_id uuid
    REFERENCES api.folders(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS secrets_folder_idx
  ON api.secrets (folder_id) WHERE deleted_at IS NULL;
```

`ON DELETE SET NULL` so a mistaken folder drop does not cascade-delete
secrets. App delete-folder path removes children first; SET NULL is the
safety net.

### 4.3 Path helper + backfill

`private.ensure_folder_path(p_project uuid, p_path text, p_actor uuid)`
SECURITY DEFINER, `row_security = off`:

- Normalize: strip slashes, reject illegal segments / depth.
- Upsert each ancestor by `(project_id, path)`.
- Return the leaf folder id (NULL if `p_path` is empty).

Backfill live **and** trashed secrets whose key contains `/`. Set
`folder_id` to the parent prefix (everything before the last `/`). Empty
prefix → NULL.

Grant EXECUTE to `authenticator`, `authenticated`.

### 4.4 RBAC: add `folder` scope

Replace / extend (CREATE OR REPLACE + DROP CONSTRAINT / ADD):

- `rbac.bindings.scope_kind` CHECK includes `'folder'`.
- `rbac.validate_binding_scope`: `secret-%` allowed at `secret` **or**
  `folder`. `service-%` stays project/secret only.
- `api.rbac_scope_chain`: walk `parent_id` with a recursive CTE, cap 16,
  then project → team → cluster.
- `api.can_manage_rbac('folder', id)`: `can_admin_project(folder.project_id)`.
- `api.can()` deleted-secret short-circuit unchanged; add nothing folder-specific
  beyond the chain.

Keep `RBAC_RESOURCES` without a required `folders` resource for v1: folder
bindings use existing `secret-*` roles whose rules already name `secrets`.
Listing/creating folders is gated by `can_read_project` / `can_write_project`
(same as creating a secret). Folder **ACL** is the new power; folder CRUD
is a project write.

### 4.5 RLS on `api.folders`

FORCE RLS. Policies:

| Command | Using |
|---------|--------|
| SELECT | `api.can_read_project(project_id)` |
| INSERT / UPDATE / DELETE | `api.can_write_project(project_id)` |

Folder **names** are metadata, like secret keys on a list the caller can
already see. Restricted mode still hides the secret **row**. Do not try to
hide folder names of restricted subtrees in v1 (same leak as today’s key
list for inherit secrets).

GRANT SELECT, INSERT, UPDATE, DELETE ON `api.folders` TO `authenticated`.

### 4.6 Audit / webhooks

Org-audit actions (free text, existing `private.audit_org`):

- `folder_created`
- `folder_deleted`
- `folder_moved`

Webhook events, add under Project events in `config.WEBHOOK_EVENTS`:

- `org.folder_created`
- `org.folder_deleted`
- `org.folder_moved`

Payload: `project_id`, `folder_id`, `path`, `old_path` (moved only),
`actor_email`, `timestamp`. No secret values.

Do **not** add folder actions to `secret_audit` CHECK. Key rewrites from a
folder move emit `secret.updated` per secret (existing action) plus one
`folder_moved` org event.

---

## 5. Application code

### 5.1 Path utilities — `app/lib/folders.py` (new)

Pure functions, no DB:

- `split_key(key) -> (folder_path | None, leaf)`
- `join_key(folder_path, leaf) -> key`
- `segments(path) -> list[str]`
- `validate_path(path) -> str`  (normalized or raise `ValueError`)
- `validate_key(key) -> str`    (same rules; used by create/upsert)

Call `validate_key` from `upsert_secret_command` **before** encrypt/insert so
UI, ESO, and mgmt API share one rule. Today there is no server-side key
charset check (only an HTML `pattern`).

### 5.2 Commands — `app/secret_svc/folder_ops.py` (new)

Cursor in, werkzeug errors out (same pattern as `commands.py`):

| Function | Does |
|----------|------|
| `ensure_path(cur, project_id, path)` | `SELECT private.ensure_folder_path(...)` |
| `list_children(cur, project_id, folder_id, page, q)` | child folders + leaf secrets; pager |
| `create_folder(cur, project_id, path)` | ensure + audit |
| `delete_folder(cur, folder_id, *, recursive=False)` | refuse if non-empty unless recursive |
| `move_folder(cur, folder_id, new_path)` | rewrite descendants; collision check |

Hook `ensure_path` into `_upsert_secret` / `upsert_secret_command` so every
write surface (UI, ESO PUT, import) materializes folders.

On key change (rare today; move will use it): recompute `folder_id`.

### 5.3 List queries

`_load_secrets_page` stays as the flat list (search / “All secrets”).

New `_load_folder_page(cur, project_id, folder_id, page)`:

```sql
-- folders
SELECT f.id, f.name, f.path, f.parent_id,
       (SELECT count(*) FROM api.secrets s
         WHERE s.folder_id = f.id AND s.deleted_at IS NULL) AS secret_count,
       (SELECT count(*) FROM api.folders c WHERE c.parent_id = f.id) AS child_count
FROM api.folders f
WHERE f.project_id = %s
  AND f.parent_id IS NOT DISTINCT FROM %s
ORDER BY f.name

-- secrets at this level
SELECT … existing secret list columns …
FROM api.secrets s
WHERE s.project_id = %s
  AND s.folder_id IS NOT DISTINCT FROM %s
  AND s.deleted_at IS NULL
ORDER BY s.key
```

Secret count is RLS-filtered (user connection). Union in Python: folders
first, then secrets; one pager over the combined list.

### 5.4 Routes

Register next to secret routes in `app/routes/secrets/__init__.py` (or a
tiny `routes/secrets/folders.py`):

| Method | Path | Action |
|--------|------|--------|
| GET | `/projects/<uuid:project_id>/folders/<uuid:folder_id>` | redirect to secrets tab with `folder=` |
| POST | `/projects/<uuid:project_id>/folders` | create (`name` or `path`; optional `parent_id`) |
| POST | `/projects/<uuid:project_id>/folders/<uuid:folder_id>/delete` | delete; `recursive=1` |
| POST | `/projects/<uuid:project_id>/folders/<uuid:folder_id>/move` | `new_path` |
| POST | `/projects/<uuid:project_id>/folders/<uuid:folder_id>/access/bindings` | reuse secret binding panel at folder scope |

`project_detail` (`routes/projects/detail.py`) reads `folder` query param
(UUID). Invalid/foreign UUID → flash + root. Pass `current_folder`,
`folder_crumbs`, `tree_folders`, `secrets` into `project_secrets.html`.

Create-secret forms: hidden `folder_id` or prefix so the inline form in a
folder creates `prod/db/<key>` rather than a root key. Advanced form key
input prefilled with `prod/db/`.

### 5.5 Bindings UI

- `config.RBAC_SCOPE_KINDS` add `"folder"`.
- `_role_dropdown_for_scope('folder')` = `RBAC_SECRET_ROLE_DROPDOWN`.
- `_role_allowed_at_scope`: `secret-*` allowed at `secret` and `folder`.
- Bindings page: folder picker when `scope=folder` (list folders in the
  selected project).
- Secret view Access tab unchanged.
- New **Folder access** panel: same `partials/access_bindings_panel.html`
  with `scope_kind=folder`. Open from the folder row menu.

`routes/rbac/bindings.py` already branches on `scope_kind`; add a folders
list query next to `secrets = []`.

### 5.6 Templates / CSS / JS

- `partials/project_secrets.html`: breadcrumb, “New folder”, view toggle
  (Tree / All), folder rows above the existing secret table.
- `partials/folder_row.html`: name, counts, menu (Open, Access, Rename,
  Delete).
- `partials/folder_form.html`: dialog, native `<dialog>` like the rest.
- Key column in tree mode: **leaf** only (`split_key`); `title` = full key.
  Flat mode: full key, unchanged.
- `app.css`: folder row icon (inline SVG, `currentColor`, stroke 1.5),
  breadcrumb under `.section-head`. No new color. Respect 720px breakpoint;
  table still scrolls horizontally.
- `app.js`: bulk toolbar ignores folder rows (checkboxes only on secrets).

No new JS framework. HTMX for create/delete/move if the secrets tab already
swaps as a partial; otherwise full POST + redirect like secret create.

### 5.7 Management + ESO APIs

**ESO `/eso/v1`:** no URL change. PUT with a slashed key materializes
folders. List remains a flat key→value map (ESO does not understand
folders). Optional list query `prefix=prod/db` is **not** required for v1
(CLI can filter client-side; add later if cheap).

**Mgmt API** (`routes/mgmt_api/`, PAT):

```
GET    /api/v1/manage/projects/<id>/folders?parent=<uuid|->
POST   /api/v1/manage/projects/<id>/folders          { "path": "prod/db" }
POST   /api/v1/manage/projects/<id>/folders/<fid>/move    { "path": "staging/db" }
DELETE /api/v1/manage/projects/<id>/folders/<fid>?recursive=1
```

Plus existing secret CRUD; response may include `folder_id` and `folder_path`
on secret JSON (`_meta_item` in `routes/eso/helpers.py`).

**CLI** (sibling `secretserver-cli`, after server ships):

```
corvus get folders
corvus create folder prod/db
corvus delete folder prod/db [--yes] [--recursive]
corvus mv folder prod/db staging/db
corvus get secrets --folder prod/db
```

CLI is a follow-up commit in that repo, not a blocker for the server PR.

### 5.8 Import / export

- Export keys unchanged (full path).
- Import of `prod/db/password` goes through `upsert_secret_command` →
  folders appear automatically.
- No separate folder list in `.env` / CSV.

---

## 6. Implementation order

Ship as one branch if small enough; split only at these hard lines.

### Slice A — schema + path helpers (no UI)

1. `0003_folders.sql`: table, `folder_id`, `ensure_folder_path`, backfill,
   RLS, grants, `scope_kind` CHECK, `validate_binding_scope`,
   `rbac_scope_chain`, `can_manage_rbac`.
2. Update `tests/test_migrations.py::test_migrations_ship_in_order` to
   `["0001_init.sql", "0002_cli_session_tokens.sql", "0003_folders.sql"]`.
3. Schema string assertions in `tests/test_schema.py` / `tests/test_org_access.py`
   (`api.folders`, `folder` in CHECK, CTE in `rbac_scope_chain`).
4. `app/lib/folders.py` + unit tests (no DB): split/join/validate, depth,
   `..`, `//`.

### Slice B — write path + tree list

1. `folder_ops.py` + hook in `upsert_secret_command`.
2. `_load_folder_page`; `project_detail` `folder=` query param.
3. Templates + CSS: breadcrumb, folder rows, create-folder dialog, leaf
   names, Tree/All toggle.
4. Prefill create-secret key from current folder.
5. Mock-DB tests for create-with-slash calling `ensure_folder_path`, list
   children SQL shape, pager combining folders+secrets.

### Slice C — ACL

1. Bindings UI + `access_bindings_panel` on a folder.
2. Tests: inherit secret in folder is revealable via folder `secret-reveal`
   binding; `restricted` secret in the same folder is **not**; project-admin
   still can; machine token unchanged.
3. Docs: `docs/admin/rbac.md` scope diagram; `docs/admin/rbac-internals.md`
   chain; `docs/user/guide.md` tree + folder access.

### Slice D — move / recursive delete

1. `move_folder`: collision query
   `EXISTS (SELECT 1 FROM api.secrets WHERE project_id=… AND key = ANY(new_keys))`.
2. Rewrite keys with `replace(key, old_path || '/', new_path || '/')` **and**
   exact `key = old_path || '/' || leaf` only under that prefix (do not
   clobber `prod2/...` when moving `prod`).
3. Recursive delete → existing `delete_secret_command` per descendant, then
   folder DELETEs.
4. Org audit + webhook events.
5. Tests for collision refuse, prefix isolation, restore still parented.

### Slice E — APIs + docs polish

1. Mgmt API routes + `docs/dev/api.md`.
2. `_meta_item` grows `folder_id` / `folder_path` (additive JSON).
3. `docs/dev/database.md` table list; `CHANGELOG.md`; user guide screenshots
   later (not a merge blocker).
4. CLI follow-up in `secretserver-cli`.

---

## 7. Files to touch (expected)

| Area | Files |
|------|--------|
| Migration | `db/migrations/0003_folders.sql` (new) |
| Config | `app/core/config.py` (`RBAC_SCOPE_KINDS`, `WEBHOOK_EVENTS`) |
| Path lib | `app/lib/folders.py` (new) |
| Commands | `app/secret_svc/folder_ops.py` (new), `commands.py`, `secret_ops.py` |
| Routes | `routes/secrets/folders.py` (new), `routes/secrets/__init__.py`, `routes/projects/detail.py`, `routes/rbac/helpers.py`, `routes/rbac/bindings.py`, `routes/mgmt_api/secrets.py` or `folders.py`, `routes/eso/helpers.py` |
| Audit | `app/audit/constants.py` |
| UI | `templates/partials/project_secrets.html`, `folder_row.html`, `folder_form.html`, `secret_new.html`, `app.css` |
| Tests | `tests/test_folders.py` (new), `test_migrations.py`, `test_schema.py`, `test_org_access.py`, `test_secrets.py`, `test_rbac.py` |
| Docs | `docs/user/guide.md`, `docs/admin/rbac.md`, `docs/admin/rbac-internals.md`, `docs/dev/api.md`, `docs/dev/database.md`, `docs/admin/webhooks.md`, `CHANGELOG.md` |

Do not change corvus-agent. `key_prefix = "hosts/"` becomes a real folder in
the project after backfill; the agent already PUTs `hosts/<hostname>`.

---

## 8. Tests (minimum)

Mock DB like the rest of the suite (`tests/helpers.py`). No Postgres required
for unit tests.

**Path (`test_folders.py`)**

- `a/b/c` → folder `a/b`, leaf `c`
- root key `API_KEY` → folder `None`, leaf `API_KEY`
- reject `""`, `/a`, `a/`, `a//b`, `a/./b`, `a/../b`, 17 segments, spaces,
  `..`

**SQL source (`test_migrations.py`, `test_schema.py`)**

- `0003` present and ordered
- `CREATE TABLE IF NOT EXISTS api.folders`
- `folder_id` on `api.secrets`
- `ensure_folder_path`
- `scope_kind IN (..., 'folder')`
- `secret-%` allowed at folder in `validate_binding_scope`
- recursive folder walk in `rbac_scope_chain`

**Commands (mocked cursor)**

- upsert `prod/db/x` calls `ensure_folder_path` with `prod/db`
- list children orders folders then secrets
- move refuses collision
- delete empty OK; delete non-empty without recursive raises
- recursive delete calls secret delete then folder delete

**RBAC (string + mocked `can`)**

- folder binding uses `secret-reveal`
- restricted secret not covered by folder binding (document via
  `can_access_secret_row` still branching on `mode = 'restricted'` first —
  no code change needed if scope chain is only consulted in inherit)

**UI**

- `project_detail` passes `current_folder` when `folder=` set
- tree template renders folder rows; flat template omits them
- create form prefix when inside a folder

Live tests (`test_live_secrets.py`) optional follow-up: create `tree/a` and
`tree/b`, GET project tab with folder uuid, assert both leaves.

---

## 9. Docs copy (user-facing)

Secrets tab:

- “Folders group secrets by the `/` in the key. `prod/db/password` lives in
  `prod/db`. A secret named `prod` and a folder `prod/` can both exist.”
- “Access on a folder applies to inherit secrets under it. Restricted
  secrets still need their own bindings.”
- “Moving a folder renames every key under it. Machine-token exact keys
  must be updated; globs like `prod/*` follow the new path only if you
  change the glob.”

RBAC internals: replace the chain diagram
`cluster → team → project → secret` with
`cluster → team → project → folder → secret`.

---

## 10. Risks

| Risk | Mitigation |
|------|------------|
| Backfill of large projects | Single SQL CTE; batched if needed. Folders are few vs secrets. |
| `can()` extra CTE per secret row | Depth ≤ 16; index `folders.parent_id`. Same pattern as today’s project/team lookups. |
| Move rewrites keys machines depend on | Confirm dialog lists count of keys; audit `folder_moved`. |
| Coexisting secret `prod` and folder `prod` confuses UI | Folder row always shown with trailing `/` in the name column. |
| HTML `pattern` vs server `validate_key` | Server is source of truth; keep the input pattern in sync. |
| SET NULL on folder delete orphans `folder_id` | App never deletes a folder with children; backfill/ensure on next upsert. |
| Scope CHECK drop in 0003 on live DB | `ALTER TABLE rbac.bindings DROP CONSTRAINT` by name discovered via
  `pg_constraint`, then ADD. Idempotent `DO $$ … $$` block. |

---

## 11. Out of tree / later

- `corvus` CLI folder commands (`secretserver-cli`).
- `prefix=` on ESO list.
- Folder-scoped machine tokens.
- Drag-and-drop in the UI.
- Tree on `/secrets` (team-wide) — keys would need a project column anyway.
- Hiding folder names that only contain restricted secrets.

---

## 12. Done when

1. Migration `0003_folders.sql` applies on a DB that already has `0001`+`0002`.
2. Existing slashed keys backfill into folders; ESO GET by full key still
   returns the value.
3. Project Secrets tab has a working tree (breadcrumb, open folder, create
   folder, create secret in folder).
4. A `secret-reveal` binding on a folder grants reveal to inherit descendants
   and not to `restricted` descendants.
5. Folder move rewrites keys without colliding; recursive delete uses trash.
6. `pytest` + `tox -e lint` pass; user + RBAC + API docs updated.
