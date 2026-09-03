"""DB-driven role catalog: scope vocab lives in ``rbac.roles``, config is fallback.

Every function takes an open cursor and reads ``(name, description, scopes,
precedence, built_in)`` from ``rbac.roles``. When the table is unreachable
or empty (unit tests, early bootstrap), they fall back to the static
registry in ``core.config`` — the same mapping the baseline backfill in
``0001_init.sql`` applies, so behavior is identical either way.
"""

from __future__ import annotations

from flask import g, has_app_context

from core import config

FALLBACK_PRECEDENCE = {
    name: rank
    for rank, name in enumerate(reversed(config.DIRECTORY_MAP_TEAM_ROLES), start=1)
}

# Tier anchors for team gates. Gates compare catalog precedence against these
# built-in names (built-ins cannot be renamed or deleted); custom roles slot
# in by precedence, so tier semantics survive new roles. Templates and routes
# must use the helpers below, never these literals.
OWNER_TIER = "team-owner"
MANAGE_TIER = "team-admin"
MEMBER_TIER = "team-member"
VIEWER_TIER = "team-viewer"


def _rank(catalog: dict[str, dict], name: str | None) -> int:
    """Precedence of ``name`` in ``catalog`` (0 when unknown)."""
    if not name:
        return 0
    try:
        return int((catalog.get(name) or {}).get("precedence") or 0)
    except (TypeError, ValueError):
        return 0


def team_role_at_least(cur, role_name: str | None, tier: str) -> bool:
    """True when ``role_name`` sits at or above ``tier`` in team precedence.

    Fail-closed: False when the role or the tier is unknown, so a missing
    catalog row denies rather than grants.
    """
    catalog = role_catalog(cur)
    tier_rank = _rank(catalog, tier)
    if tier_rank <= 0:
        return False
    return _rank(catalog, role_name) >= tier_rank


def highest_team_role(cur) -> str | None:
    """Name of the top-precedence team-scope role (ownership tier)."""
    catalog = role_catalog(cur)
    team = {
        name: _rank(catalog, name)
        for name, info in catalog.items()
        if "team" in (info.get("scopes") or [])
    }
    if not team:
        return None
    top = max(team.values())
    return sorted(n for n, r in team.items() if r == top)[0]


def team_tier_role(cur, tier: str) -> str:
    """Usable role name for ``tier``: the tier itself when it exists in team
    vocab, else the lowest-precedence team role (safe default), else the
    tier literal (preserves legacy behavior when the catalog is empty)."""
    names = role_names_for_scope(cur, "team")
    if tier in names:
        return tier
    if names:
        catalog = role_catalog(cur)
        return min(names, key=lambda n: (_rank(catalog, n), n))
    return tier


def default_team_role(cur) -> str:
    """Default role for invites and add-member forms (member tier)."""
    return team_tier_role(cur, MEMBER_TIER)


# Preferred defaults per scope when the caller supplies nothing. Validation
# is always against the live vocab; the preferred name is only a default,
# with a lowest-precedence fallback when it is absent.
PREFERRED_SCOPE_ROLE = {
    "project": "project-read",
    "secret": "secret-reveal",
    "folder": "secret-reveal",
}


def default_role_for_scope(cur, scope_kind: str, preferred: str | None = None) -> str:
    """Default bindable role for ``scope_kind`` (preferred name when valid)."""
    names = role_names_for_scope(cur, scope_kind)
    want = preferred or PREFERRED_SCOPE_ROLE.get(scope_kind)
    if want and want in names:
        return want
    if names:
        catalog = role_catalog(cur)
        return min(names, key=lambda n: (_rank(catalog, n), n))
    return want or ""


def _fallback_scopes(name: str) -> list[str]:
    """Scope set for a role name when the catalog table is unavailable."""
    if name in ("global-admin", "audit-viewer"):
        return ["cluster"]
    if name == "auditor":
        return ["team", "project", "folder", "secret"]
    if name.startswith("team-"):
        return ["team"]
    if name.startswith("project-"):
        return ["project"]
    if name.startswith("secret-"):
        return ["folder", "secret"]
    if name.startswith("service-"):
        return ["project", "folder", "secret"]
    return []


def role_catalog(cur) -> dict[str, dict]:
    """Return ``{name: {description, scopes, precedence, built_in}}``.

    Falls back to the static config registry when the query fails or the
    table has no rows. Cached per request (``flask.g``) so pages with many
    gates issue one catalog query, not one per gate.
    """
    if has_app_context():
        cached = getattr(g, "_role_catalog", None)
        if isinstance(cached, dict):
            return cached
    try:
        cur.execute(
            "SELECT name, description, scopes, precedence, built_in FROM rbac.roles"
        )
        rows = cur.fetchall() or None
    except Exception:
        rows = None
    if (
        not isinstance(rows, list)
        or not rows
        or not isinstance(rows[0], dict)
        or "name" not in rows[0]
        or "scopes" not in rows[0]
    ):
        # Table unreachable, empty, or the cursor did not return role rows
        # (e.g. unit-test doubles) — use the static registry, which mirrors
        # the baseline seed, so gates keep legacy allow/deny parity.
        out = _fallback_catalog()
    else:
        try:
            out = {
                r["name"]: {
                    "description": r.get("description") or "",
                    "scopes": list(r.get("scopes") or []),
                    "precedence": int(r.get("precedence") or 0),
                    "built_in": bool(r.get("built_in")),
                }
                for r in rows
            }
        except Exception:
            return {}
    if has_app_context():
        g._role_catalog = out
    return out


def _fallback_catalog() -> dict[str, dict]:
    """Static role registry mirroring the baseline seed (offline/test use)."""
    out: dict[str, dict] = {}
    for dropdown in (
        config.RBAC_CLUSTER_ROLE_DROPDOWN,
        config.RBAC_TEAM_ROLE_DROPDOWN,
        config.RBAC_PROJECT_ROLE_DROPDOWN,
        config.RBAC_SECRET_ROLE_DROPDOWN,
    ):
        for entry in dropdown:
            n, label = entry[0], entry[1] if len(entry) > 1 else entry[0]
            out.setdefault(
                n,
                {
                    "description": label,
                    "scopes": _fallback_scopes(n),
                    "precedence": FALLBACK_PRECEDENCE.get(n, 0),
                    "built_in": True,
                },
            )
    return out


def roles_for_scope(cur, scope_kind: str) -> list[tuple[str, str]]:
    """Return ``(name, description)`` pairs bindable at ``scope_kind``."""
    catalog = role_catalog(cur)
    return sorted(
        (
            (name, info["description"])
            for name, info in catalog.items()
            if scope_kind in info["scopes"]
        ),
        key=lambda pair: pair[0],
    )


def role_names_for_scope(cur, scope_kind: str) -> tuple[str, ...]:
    """Return bindable role names for ``scope_kind``."""
    return tuple(n for n, _ in roles_for_scope(cur, scope_kind))


def role_allowed_at_scope(cur, role_name: str, scope_kind: str) -> bool:
    """Return True when ``role_name`` may be bound at ``scope_kind``."""
    info = role_catalog(cur).get(role_name)
    return bool(info) and scope_kind in info["scopes"]


def team_role_rank(cur) -> dict[str, int]:
    """Return ``{team role name: precedence}`` for directory-map ranking."""
    catalog = role_catalog(cur)
    return {
        name: info["precedence"]
        for name, info in catalog.items()
        if "team" in info["scopes"] and info["precedence"]
    } or {
        name: rank
        for name, rank in FALLBACK_PRECEDENCE.items()
        if name in catalog and "team" in catalog[name]["scopes"]
    }
