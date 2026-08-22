"""Shared helpers for the RBAC admin UI (scope rules, catalog, YAML parsing)."""

from __future__ import annotations

import re

from core import config

_VALID_RESOURCES = set(config.RBAC_RESOURCES)
_VALID_VERBS = set(config.RBAC_VERBS)


def _role_dropdown_for_scope(scope_kind: str) -> list[tuple[str, str]]:
    if scope_kind == "cluster":
        return list(config.RBAC_CLUSTER_ROLE_DROPDOWN)
    if scope_kind == "team":
        return list(config.RBAC_TEAM_ROLE_DROPDOWN)
    if scope_kind == "project":
        return list(config.RBAC_PROJECT_ROLE_DROPDOWN)
    if scope_kind == "secret":
        return list(config.RBAC_SECRET_ROLE_DROPDOWN)
    return []


def _role_allowed_at_scope(role_name: str, scope_kind: str) -> bool:
    if role_name.startswith("team-"):
        return scope_kind == "team"
    if role_name.startswith("project-"):
        return scope_kind == "project"
    if role_name.startswith("secret-"):
        return scope_kind == "secret"
    if role_name.startswith("service-"):
        return scope_kind in ("project", "secret")
    if role_name in ("global-admin", "audit-viewer"):
        return scope_kind == "cluster"
    return scope_kind != "cluster"


def _split_csv(val: str) -> list[str]:
    """Split ``a, b, [c]`` style lists into tokens."""
    raw = (val or "").strip()
    if not raw:
        return []
    raw = raw.strip("[]")
    return [p.strip().strip("\"'") for p in re.split(r"[, ]+", raw) if p.strip()]


def parse_rules_yaml(text: str) -> list[tuple[list[str], list[str]]]:
    """Parse a simple multi-rule text/YAML-ish rules document.

    Format (blank line separates rules)::

        resources: secrets, projects
        verbs: get, list, reveal

        resources: *
        verbs: *

    Returns:
        List of (resources, verbs) pairs. Raises ValueError on bad input.
    """
    blocks: list[str] = []
    cur: list[str] = []
    for line in (text or "").splitlines():
        if line.strip().startswith("#"):
            continue
        if not line.strip():
            if cur:
                blocks.append("\n".join(cur))
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    rules: list[tuple[list[str], list[str]]] = []
    for block in blocks:
        resources: list[str] = []
        verbs: list[str] = []
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key in ("resources", "resource"):
                resources = _split_csv(val)
            elif key in ("verbs", "verb"):
                verbs = _split_csv(val)
        resources = [r for r in resources if r in _VALID_RESOURCES]
        verbs = [v for v in verbs if v in _VALID_VERBS]
        if not resources or not verbs:
            raise ValueError(
                "Each rule needs valid resources: and verbs: lines "
                f"(got resources={resources!r} verbs={verbs!r})"
            )
        rules.append((resources, verbs))
    if not rules:
        raise ValueError("No rules yet. Add at least one resources/verbs pair.")
    return rules


def load_roles_catalog(cur):
    """Return (roles, builtin, custom, can_edit_roles)."""
    cur.execute(
        """
        SELECT r.id, r.name, r.description, r.built_in, r.created_at,
               COALESCE(
                 (
                   SELECT json_agg(json_build_object(
                     'resources', rr.resources, 'verbs', rr.verbs
                   ) ORDER BY rr.id)
                   FROM rbac.role_rules rr WHERE rr.role_id = r.id
                 ),
                 '[]'::json
               ) AS rules
        FROM rbac.roles r
        ORDER BY r.built_in DESC, r.name
        """
    )
    roles = list(cur.fetchall() or [])
    for r in roles:
        rules = r.get("rules") or []
        if isinstance(rules, str):
            import json

            try:
                rules = json.loads(rules)
            except Exception:
                rules = []
        r["rules"] = rules or []
    cur.execute("SELECT api.can_manage_rbac('cluster', NULL) AS ok")
    can_edit_roles = bool((cur.fetchone() or {}).get("ok"))
    builtin = [r for r in roles if r.get("built_in")]
    custom = [r for r in roles if not r.get("built_in")]
    return roles, builtin, custom, can_edit_roles
