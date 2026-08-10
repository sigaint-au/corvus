"""Kubernetes-style RBAC: constants, rule matching docs, route registration."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import config


def test_builtin_role_names_match_docs():
    assert "team-owner" in config.RBAC_BUILTIN_ROLES
    assert "project-write" in config.RBAC_BUILTIN_ROLES
    assert "secret-reveal" in config.RBAC_BUILTIN_ROLES
    assert "service-readonly" in config.RBAC_BUILTIN_ROLES
    assert "cluster-admin" in config.RBAC_BUILTIN_ROLES
    assert "reveal" in config.RBAC_VERBS
    assert "secrets" in config.RBAC_RESOURCES


def test_rbac_sql_ships_can_and_tables():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "db" / "rbac.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS rbac.roles" in sql
    assert "CREATE TABLE IF NOT EXISTS rbac.bindings" in sql
    assert "CREATE OR REPLACE FUNCTION api.can(" in sql
    assert "rbac_scope_chain" in sql
    assert "ensure_builtin_roles" in sql
    # create_team seeds team-owner binding; no bulk migrate from team_members
    assert "INSERT INTO rbac.bindings" in sql
    assert "team-owner" in sql


def test_schema_applies_rbac_sql():
    from pathlib import Path
    import schema as schema_mod

    src = Path(schema_mod.__file__).read_text()
    assert "_apply_rbac_sql" in src
    assert "rbac.sql" in src


def test_rbac_routes_registered(app):
    rules = {r.rule for r in app.url_map.iter_rules()}
    assert "/rbac/roles" in rules
    assert "/rbac/bindings" in rules
    assert "/rbac/access-review" in rules


def test_rbac_roles_requires_login(client):
    r = client.get("/rbac/roles")
    assert r.status_code == 302
    assert "/login" in (r.location or "")


def test_dropdowns_cover_legacy_vocabularies():
    team_names = {n for n, _ in config.RBAC_TEAM_ROLE_DROPDOWN}
    assert team_names == {"team-owner", "team-admin", "team-member", "team-viewer"}
    proj = {n for n, _ in config.RBAC_PROJECT_ROLE_DROPDOWN}
    assert proj == {"project-admin", "project-write", "project-read"}
