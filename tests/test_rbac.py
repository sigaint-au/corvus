"""Kubernetes-style RBAC: constants, rule matching docs, route registration."""
from __future__ import annotations

from pathlib import Path

import pytest

from core import config


def test_builtin_role_names_match_docs():
    assert "team-owner" in config.RBAC_BUILTIN_ROLES
    assert "project-write" in config.RBAC_BUILTIN_ROLES
    assert "project-reveal" in config.RBAC_BUILTIN_ROLES
    assert "secret-reveal" in config.RBAC_BUILTIN_ROLES
    assert "service-read" in config.RBAC_BUILTIN_ROLES
    assert "service-reveal" in config.RBAC_BUILTIN_ROLES
    assert "service-write" in config.RBAC_BUILTIN_ROLES
    assert "team-audit-viewer" in config.RBAC_BUILTIN_ROLES
    assert "global-admin" in config.RBAC_BUILTIN_ROLES
    assert "reveal" in config.RBAC_VERBS
    assert "secrets" in config.RBAC_RESOURCES
    # Legacy service-readonly should NOT be in the list (split into read/reveal)
    assert "service-readonly" not in config.RBAC_BUILTIN_ROLES


def test_rbac_sql_ships_can_and_tables():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "db" / "migrations" / "0001_init.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS rbac.roles" in sql
    assert "CREATE TABLE IF NOT EXISTS rbac.bindings" in sql
    assert "CREATE OR REPLACE FUNCTION api.can(" in sql
    assert "rbac_scope_chain" in sql
    assert "ensure_builtin_roles" in sql
    # create_team seeds team-owner binding; no bulk migrate from team_members
    assert "INSERT INTO rbac.bindings" in sql
    assert "team-owner" in sql
    # New roles present
    assert "project-reveal" in sql
    assert "team-audit-viewer" in sql
    assert "service-read" in sql
    assert "service-reveal" in sql
    # Unique index on bindings
    assert "bindings_unique_idx" in sql
    # updated_at / updated_by columns
    assert "updated_at timestamptz" in sql
    assert "updated_by uuid" in sql
    # Deleted secret check in can()
    assert "deleted_at IS NOT NULL" in sql
    # Access modes: inherit / restricted only (no legacy custom alias)
    assert "'restricted'" in sql
    assert "IN ('restricted', 'custom')" not in sql
    assert "IN ('custom', 'restricted')" not in sql


def test_schema_applies_migrations():
    from pathlib import Path

    from core import migrations as migrations_mod

    src = Path(migrations_mod.__file__).read_text()
    assert "_split_sql_statements" in src
    assert "private.schema_migrations" in src
    assert "apply_pending" in src


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
    assert proj == {"project-admin", "project-write", "project-reveal", "project-read"}


def test_service_dropdown_has_new_roles():
    svc = {n for n, _ in config.RBAC_SERVICE_ROLE_DROPDOWN}
    assert "service-read" in svc
    assert "service-reveal" in svc
    assert "service-write" in svc
    assert "service-readonly" not in svc


def test_machine_token_roles_updated():
    assert "service-read" in config.MACHINE_TOKEN_ROLES
    assert "service-reveal" in config.MACHINE_TOKEN_ROLES
    assert "service-write" in config.MACHINE_TOKEN_ROLES
    assert "read" not in config.MACHINE_TOKEN_ROLES
    assert "read-only" not in config.MACHINE_TOKEN_ROLES


def test_access_modes_updated():
    assert "inherit" in config.ACCESS_MODES
    assert "restricted" in config.ACCESS_MODES
    assert "custom" not in config.ACCESS_MODES
    assert set(config.ACCESS_MODE_LABELS) == {"inherit", "restricted"}


def test_parse_rules_yaml_multi_rule():
    from routes.rbac import parse_rules_yaml

    rules = parse_rules_yaml(
        """
        resources: secrets, projects
        verbs: get, list, reveal

        resources: *
        verbs: get
        """
    )
    assert len(rules) == 2
    assert rules[0][0] == ["secrets", "projects"]
    assert "reveal" in rules[0][1]
    assert rules[1][0] == ["*"]


def test_parse_rules_yaml_rejects_empty():
    from routes.rbac import parse_rules_yaml

    with pytest.raises(ValueError):
        parse_rules_yaml("# only comments\n")


def test_parse_access_mode_accepts_rbac_modes():
    from secret_svc.secret_ops import _parse_access_mode

    assert _parse_access_mode("restricted") == "restricted"
    assert _parse_access_mode("inherit") == "inherit"
    assert _parse_access_mode("") == "inherit"
    assert _parse_access_mode("unknown") == "inherit"
    assert _parse_access_mode({"access_mode": "restricted"}) == "restricted"
    # No aliases: legacy mode names are rejected (default to inherit).
    # Stored rows are scrubbed by ensure_schema, not by the form parser.
    assert _parse_access_mode("custom") == "inherit"
    assert _parse_access_mode({"access_mode": "custom"}) == "inherit"
    assert _parse_access_mode("writers") == "inherit"
    assert _parse_access_mode("admins") == "inherit"
    assert _parse_access_mode("owners") == "inherit"


def test_schema_scrubs_legacy_access_modes():
    """The access_mode data migration rewrites custom/writers/… then enforces
    inherit|restricted, and the follow-up migration drops secret_acl."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    access = (root / 'db' / 'migrations' / '0001_init.sql').read_text()
    cleanup = access
    assert "WHERE access_mode = 'custom'" in access
    assert "WHERE access_mode NOT IN ('inherit', 'restricted')" in access
    assert "DROP COLUMN IF EXISTS acl_mode" in access
    assert "CHECK (access_mode IN ('inherit', 'restricted'))" in access
    assert "WHERE default_access_mode = 'custom'" in cleanup
    assert "DROP TABLE IF EXISTS api.secret_acl" in cleanup
