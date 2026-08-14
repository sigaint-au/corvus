"""Unit tests (pytest). Mock DB — no Postgres required."""
from __future__ import annotations

import re
from unittest.mock import MagicMock, patch
from uuid import uuid4
from pathlib import Path

import pytest

import app as store
import audit
import config

from tests.helpers import APP_ROOT, REPO_ROOT, migrations_src, routes_module_src

store.app.config["TESTING"] = True


class TestOrgAccess:
    """Project members, invites, org audit schema (no live DB)."""

    def test_schema_has_invites_and_org_audit(self):
        from pathlib import Path
        root = REPO_ROOT
        init = (root / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE TABLE api.team_invites' in init
        assert 'CREATE TABLE api.team_join_requests' in init
        assert 'CREATE TABLE api.org_audit' in init
        # guard_last_team_owner moved to rbac.sql as guard_last_team_owner_binding
        rbac_sql = (root / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        assert 'guard_last_team_owner' in rbac_sql
        assert 'guard_last_team_owner' not in init
        assert 'rbac.guard_last_team_owner_binding' in rbac_sql
        assert 'private.project_member_rows' in init
        assert 'private.audit_org' in init
        assert 'default_token_days' in init
        assert "'exported'" in init
        assert 'CREATE TABLE api.secret_access_requests' in init
        assert 'api.can_reveal_secret' in init
        assert 'api.secret_requires_approval' in init
        assert 'require_reveal_approval' in init
        assert 'private.secret_access_request_rows' in init
        assert 'access_requested' in init
        src = migrations_src()
        assert 'api.team_invites' in src
        assert 'private.audit_org' in src
        assert 'exported' in src
        assert 'secret_access_requests' in src
        assert 'can_reveal_secret' in src
        assert 'secret_requires_approval' in src
        assert 'require_reveal_approval' in src
        assert 'access_approved' in src

    def test_log_org_calls_fn(self):
        cur = MagicMock()
        with store.app.test_request_context('/'):
            from flask import session
            session['email'] = 'a@b.c'
            audit.log_org(cur, team_id=uuid4(), action=audit.ORG_MEMBER_ADD, detail='x')
        sql = cur.execute.call_args.args[0]
        assert 'private.audit_org' in sql

    def test_project_roles_config(self):
        names = [n for n, _ in config.RBAC_PROJECT_ROLE_DROPDOWN]
        assert 'project-read' in names
        assert 'project-write' in names
        assert 'project-admin' in names
        assert 'team-member' in config.INVITE_ROLES
        assert 'team-owner' not in config.INVITE_ROLES
        assert not hasattr(config, 'TEAM_ROLES')

    def test_secret_meta_schema(self):
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE TABLE api.secret_meta' in init
        assert 'last_accessed_at' in init
        assert 'last_accessed_by' in init
        assert 'private.secret_meta_rows' in init
        assert 'private.touch_secret_access' in init
        src = migrations_src()
        assert 'secret_meta' in src
        assert 'touch_secret_access' in src
        routes = routes_module_src('secrets')
        assert routes.count('touch_secret_access') >= 2
        ops = (APP_ROOT / 'secret_ops.py').read_text()
        assert 'secret_meta' in ops

    def test_machine_token_scope_schema(self):
        """Per-token key allow-list (exact + glob) is in schema and helpers."""
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        src = migrations_src()
        assert 'CREATE TABLE api.machine_token_scope' in init
        assert 'machine_token_scope' in src
        assert 'private.machine_key_allowed' in init
        assert 'private.glob_to_like' in init
        assert 'machine_key_allowed' in src
        from routes.project_tokens import parse_token_scope_lines
        pairs = parse_token_scope_lines('API_KEY\n# comment\nprod/*\nDB_?\n')
        assert pairs == [('key', 'API_KEY'), ('pattern', 'prod/*'), ('pattern', 'DB_?')]

    def test_security_hardening_policies(self):
        """H1/M1/L1/L2/L5: projects_update, owner assignment, versions, ACL team, FORCE RLS."""
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        src = migrations_src()
        # RLS policies moved from init.sql to rbac.sql
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        assert 'USING (api.can_admin_project(id))' in rbac_sql
        assert 'USING (api.can_admin_project(id))' in src
        # Legacy tm_insert policy removed from init.sql; RBAC bindings write policy in rbac.sql
        assert 'rbac_bindings_write' in rbac_sql
        assert 'can_manage_rbac' in rbac_sql
        assert 'CREATE POLICY secret_versions_insert ON api.secret_versions FOR INSERT' not in init
        assert 'REVOKE INSERT, UPDATE, DELETE ON api.secret_versions FROM authenticated' in init
        assert 'SECURITY DEFINER' in init.split('archive_secret_version')[1][:400]
        assert 'REVOKE INSERT, UPDATE, DELETE ON api.secret_versions' in src
        # L2 was secret_acl group-team check; table dropped — ensure drop remains
        assert 'DROP TABLE IF EXISTS api.secret_acl' in src
        assert 'CREATE TABLE api.secret_acl' not in init
        assert 'FORCE ROW LEVEL SECURITY' in init
        assert 'FORCE ROW LEVEL SECURITY' in src

    def test_secret_acl_schema_and_config(self):
        from pathlib import Path
        assert 'inherit' in config.ACCESS_MODES
        assert 'restricted' in config.ACCESS_MODES
        assert set(config.ACCESS_MODE_LABELS) == {'inherit', 'restricted'}
        assert 'secret-reveal' in dict(config.RBAC_SECRET_ROLE_DROPDOWN)
        assert [n for n, _ in config.RBAC_SECRET_ROLE_DROPDOWN] == [
            'secret-write', 'secret-reveal', 'secret-read',
        ]
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'access_mode' in init
        assert 'CREATE TABLE api.secret_acl' not in init
        assert 'api.can_access_secret' in init  # referenced in private functions (comment + calls)
        # can_access_secret_row and can_reveal_secret defined in rbac.sql (moved from init.sql)
        rbac = (REPO_ROOT / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        assert 'api.can_access_secret_row' in rbac
        # RLS policies pass deleted_at=NULL explicitly so the deleted_at guard
        # in can_access_secret_row does not reject soft-deletes/trash.
        assert "can_access_secret_row(id, project_id, access_mode, 'read', NULL)" in rbac
        assert "deleted_at IS NOT NULL AND api.can_access_secret_row(id, project_id, access_mode, 'write', NULL)" in rbac
        rev = rbac[rbac.index('FUNCTION api.can_reveal_secret'):]
        rev = rev[:rev.index('$$;') + 3]
        assert "can_access_secret(sid, 'reveal')" in rev
        src = migrations_src()
        assert 'can_access_secret' in src
        assert 'can_access_secret_row' in src
        assert 'DROP TABLE IF EXISTS api.secret_acl' in src
        assert "NOT api.can_access_secret(sid, 'reveal')" in src
        assert 'DROP TABLE IF EXISTS api.secret_acl' in rbac
        assert 'rbac_secret_binding_allows' in rbac

    def test_can_access_secret_row_modes_in_sql(self):
        """rbac.sql defines can_access_secret_row with mode branches and k8s bindings."""
        from pathlib import Path
        rbac = (REPO_ROOT / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        start = rbac.index('FUNCTION api.can_access_secret_row')
        body = rbac[start:start + 2500]
        for mode in ('inherit', 'restricted'):
            assert mode in body, f'mode {mode} missing from can_access_secret_row'
        for need in ("'read'", "'reveal'", "'write'"):
            assert need in body
        rstart = rbac.index('FUNCTION api.can_access_secret_row')
        rbody = rbac[rstart:rstart + 2500]
        assert 'rbac_secret_binding_allows' in rbody
        assert 'api.secret_acl' not in rbody

    def test_effective_access_functions_defined(self):
        """Self-service (my access) and resource-level (effective access)
        helpers exist in rbac.sql with the grants they need."""
        from pathlib import Path
        sql = (REPO_ROOT / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        assert 'FUNCTION api.my_access_rows()' in sql
        assert 'FUNCTION api.effective_access_rows(' in sql
        assert 'FROM api.rbac_subjects(' in sql
        assert 'JOIN api.rbac_scope_chain(' in sql
        # chain CTE columns are the same names as the function's OUT params;
        # they must be qualified or PL/pgSQL raises an ambiguity error.
        assert 'FROM api.rbac_scope_chain(p_scope_kind, p_scope_id) AS c' in sql
        assert 'SELECT c.scope_kind::text, c.scope_id' in sql
        assert "ORDER BY 1 NULLS LAST, 4, 6;" in sql
        assert "GRANT EXECUTE ON FUNCTION api.my_access_rows" in sql
        assert "GRANT EXECUTE ON FUNCTION api.effective_access_rows" in sql

    def test_shared_with_me_and_project_select_for_grantees(self):
        """Shared secrets helper exists; projects/teams SELECT allow secret grantees."""
        sql = (REPO_ROOT / 'db' / 'migrations' / '0022_shared_with_me.sql').read_text()
        assert 'FUNCTION private.shared_with_me_secret_rows()' in sql
        assert "GRANT EXECUTE ON FUNCTION private.shared_with_me_secret_rows" in sql
        assert "scope_kind = 'secret'" in sql
        assert 'secret_requires_approval' in sql
        assert 'NOT api.is_team_member(p.team_id)' in sql
        proj = sql[sql.index('CREATE POLICY projects_select ON api.projects'):]
        proj = proj[:proj.index(';')]
        assert 'can_access_secret_row' in proj
        teams = sql[sql.index('CREATE POLICY teams_select ON api.teams'):]
        teams = teams[:teams.index(';')]
        assert 'can_access_secret_row' in teams

    def test_export_filters_reveal_permission(self):
        """Plain export SQL must filter by can_access_secret reveal + can_reveal."""

    def test_secrets_policies_allow_soft_delete(self):
        """Soft-delete must not trip RLS: the UPDATE policy needs an explicit
        WITH CHECK (not the implicit USING default) gated on write access, and
        SELECT must expose trash rows to writers. Regression for
        'new row violates row-level security policy for table secrets'."""
        from pathlib import Path
        rbac = (REPO_ROOT / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        upd = rbac[rbac.index('CREATE POLICY secrets_update ON api.secrets'):]
        upd = upd[:upd.index(';')]
        assert 'WITH CHECK (api.can_access_secret_row(id, project_id, access_mode, \'write\', NULL))' in upd
        sel = rbac[rbac.index('CREATE POLICY secrets_select ON api.secrets'):]
        sel = sel[:sel.index(';')]
        assert 'deleted_at IS NOT NULL' in sel
        delf = rbac[rbac.index('CREATE POLICY secrets_delete ON api.secrets'):]
        delf = delf[:delf.index(';')]
        assert 'deleted_at IS NOT NULL' in delf
        src = migrations_src()
        assert 'WITH CHECK (api.can_access_secret_row(id, project_id, access_mode, \'write\', NULL))' in src
        from pathlib import Path
        src = (APP_ROOT / 'routes' / 'project_io.py').read_text()
        assert "can_access_secret(id, 'reveal')" in src
        assert 'can_reveal_secret(id)' in src
        bulk = src[src.index('def bulk_export'):]
        assert "can_access_secret(id, 'reveal')" in bulk

    def test_acl_management_routes_exist(self):
        """Secret ACL mode/grant routes registered and gated to admins."""
        from pathlib import Path
        src = routes_module_src('secrets')
        assert 'def update_secret_access' in src
        assert 'def add_secret_access_binding' in src
        assert 'def delete_secret_access_binding' in src
        assert 'can_admin_project' in src
        assert 'tab="access"' in src

    def test_eso_pat_checks_acl_before_reveal(self):
        """ESO/PAT get-secret must check can_access_secret reveal before approval."""
        from pathlib import Path
        src = (APP_ROOT / 'routes' / 'eso' / 'secrets.py').read_text()
        i_acl = src.index("can_access_secret(%s, 'reveal')")
        i_rev = src.index('can_reveal_secret(%s)')
        assert i_acl < i_rev
        assert '"error": "forbidden"' in src
        assert '"error": "approval_required"' in src

    def test_eso_pat_bulk_export_filters_reveal_acl(self):
        """PAT bulk list-with-values must filter by can_access_secret(reveal)."""
        from pathlib import Path
        src = (APP_ROOT / 'routes' / 'eso' / 'secrets.py').read_text()
        start = src.index('def eso_list_secrets')
        body = src[start:start + 8000]
        assert 'cli/values' in body
        assert "can_access_secret(id, 'reveal')" in body
        assert 'can_reveal_secret(id)' in body
        assert not re.search('SELECT key, value_enc FROM api\\.secrets\\s+WHERE project_id = %s AND deleted_at IS NULL\\s*\\"\\"\\"', body)

    def test_group_team_roles_config(self):
        """Group team roles now flow through RBAC bindings — api.groups has no
        team_role column."""
        assert [n for n, _ in config.RBAC_TEAM_ROLE_DROPDOWN][0] == 'team-owner'
        assert not hasattr(config, 'GROUP_TEAM_ROLES')
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        gstart = init.index('CREATE TABLE api.groups')
        gend = init.index('CREATE TABLE api.group_members')
        assert 'team_role' not in init[gstart:gend]

    def test_can_access_secret_row_behavioral_matrix(self):
        """Expected outcomes for can_access_secret_row (mirrors rbac.sql CASE).

        Pure-Python stand-in of the SECURITY DEFINER helper so we can assert
        mode × need without a live Postgres. Keep in sync with rbac.sql.
        """
        perm_rank = {'read': 1, 'reveal': 2, 'write': 3}

        def row_access(*, mode, need, deleted=False, can_read=True, can_write=False, can_admin=False, is_global=False, grants=None):
            if deleted or not need or need not in perm_rank:
                return False
            if not can_read and (not is_global):
                return False
            if is_global or can_admin:
                return True
            mode = mode or 'inherit'
            if mode == 'inherit':
                return can_write if need == 'write' else True
            if mode == 'restricted':
                grants = grants or []
                need_r = perm_rank[need]
                return any((perm_rank.get(g, 0) >= need_r for g in grants))
            return False
        assert row_access(mode='inherit', need='read', can_read=True)
        assert row_access(mode='inherit', need='reveal', can_read=True)
        assert not row_access(mode='inherit', need='write', can_read=True, can_write=False)
        assert row_access(mode='inherit', need='write', can_read=True, can_write=True)
        assert not row_access(mode='restricted', need='reveal', can_read=True, grants=['read'])
        assert row_access(mode='restricted', need='reveal', can_read=True, grants=['reveal'])
        assert row_access(mode='restricted', need='read', can_read=True, grants=['write'])
        assert not row_access(mode='restricted', need='write', can_read=True, grants=['reveal'])
        assert not row_access(mode='inherit', need='read', deleted=True)
        assert not row_access(mode='inherit', need='read', can_read=False)

    def test_org_groups_rbac_schema(self):
        """Groups tables and group-aware RBAC helpers."""
        from pathlib import Path
        init = (REPO_ROOT / 'db' / 'migrations' / '0001_init.sql').read_text()
        assert 'CREATE TABLE api.groups' in init
        assert 'CREATE TABLE api.group_members' in init
        assert 'external_key' in init
        assert 'group_members gm' in init
        # Legacy tables removed from init.sql
        assert 'CREATE TABLE api.project_group_roles' not in init
        assert 'api._role_rank' not in init
        rbac_sql = (REPO_ROOT / 'db' / 'migrations' / '0002_rbac.sql').read_text()
        assert 'api.project_role' in rbac_sql
        src = migrations_src()
        assert 'CREATE TABLE IF NOT EXISTS api.groups' in src
        assert 'team_group_rows' in src
        assert 'DROP TABLE IF EXISTS api.secret_acl' in src
        teams_src = routes_module_src('teams')
        assert 'create_team_group' in teams_src
        assert 'apply_group_membership_maps' in Path(APP_ROOT / 'ldap_auth.py').read_text()
        seed = (REPO_ROOT / 'scripts' / 'seed_mock.py').read_text()
        assert 'GROUPS' in seed
        assert 'PROJECT_GROUP_BINDINGS' in seed
        assert 'CUSTOM_ROLES' in seed
        assert 'MACHINE_TOKENS' in seed
        assert 'SECRET_BINDINGS' in seed
        assert 'access_mode' in seed
        assert 'acl_mode' not in seed

    def test_dir_sync_group_membership_maps(self):
        """Directory sync upserts/removes group_members for external_key matches."""
        from unittest.mock import MagicMock
        import dir_sync
        uid = str(uuid4())
        gid_match = str(uuid4())
        gid_other = str(uuid4())
        cur = MagicMock()
        cur.fetchall.return_value = [{'id': gid_match, 'external_key': 'cn=ops,ou=groups'}, {'id': gid_other, 'external_key': 'cn=other,ou=groups'}]
        cur.fetchone.return_value = None
        dir_sync.apply_group_membership_maps(cur, uid, ['cn=ops,ou=groups', 'cn=unrelated'], source='ldap')
        executed = ' '.join((str(c.args[0]) for c in cur.execute.call_args_list)).lower()
        assert 'delete from api.group_members' in executed
        assert 'insert into api.group_members' in executed
        insert_calls = [c for c in cur.execute.call_args_list if 'INSERT INTO api.group_members' in str(c.args[0])]
        assert len(insert_calls) == 1
        assert insert_calls[0].args[1][0] == gid_match

    def test_members_tab_requires_login(self):
        r = store.app.test_client().get(f'/projects/{uuid4()}?tab=settings')
        assert r.status_code == 302

    def test_invite_redeem_requires_login(self):
        c = store.app.test_client()
        r = c.get('/invite/not-a-real-token')
        assert r.status_code == 302
        assert '/login' in (r.location or '')
        with c.session_transaction() as s:
            assert s.get('invite_token') == 'not-a-real-token'

