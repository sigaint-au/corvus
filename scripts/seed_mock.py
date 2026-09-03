#!/usr/bin/env python3
"""Seed mock users, teams, projects, secrets, groups, custom RBAC roles,
machine accounts, and scoped bindings (dev only).

Password for every local account: password. Accounts are email-verified so they can sign in immediately.
Run inside the app container (has MASTER_KEY + DB + crypto):

  podman exec corvus_app_1 python /tmp/seed_mock.py

Or from host after copying the file in.

Covers: teams/projects/secrets, group + project + secret role bindings,
custom roles with rules, restricted (access_mode) secrets, reveal approval,
machine tokens with key allow-lists, ServiceAccount subjects (visible in
Access review, Effective access, and My access), cluster + project webhooks,
and team/project/secret metadata (inheritance).
"""
from __future__ import annotations

import os
import secrets
import sys

# App modules live on PYTHONPATH in the container (/app)
sys.path.insert(0, "/app")
os.chdir("/app")

import crypto  # noqa: E402
from core import db  # noqa: E402

PASSWORD = "password"

# Fixed UUIDs so re-seed is idempotent and CLI docs can quote them.
USERS = [
    # email, name, global_admin
    ("admin@example.com", "Ada Admin", True),
    ("alice@example.com", "Alice Engineer", False),
    ("bob@example.com", "Bob Ops", False),
    ("carol@example.com", "Carol Viewer", False),
    ("dave@example.com", "Dave Contractor", False),
]

TEAMS = [
    # name, owner_email, members: (email, team role short)
    (
        "Platform",
        "admin@example.com",
        [
            ("alice@example.com", "admin"),
            ("bob@example.com", "member"),
            ("carol@example.com", "viewer"),
        ],
    ),
    (
        "Payments",
        "alice@example.com",
        [
            ("bob@example.com", "admin"),
            ("dave@example.com", "member"),
            ("admin@example.com", "admin"),
        ],
    ),
    (
        "Mobile",
        "bob@example.com",
        [
            ("alice@example.com", "member"),
            ("carol@example.com", "viewer"),
        ],
    ),
]

PROJECTS = [
    # team_name, project_name, members: (email, project role short)
    ("Platform", "demo-api", [("alice@example.com", "write"), ("bob@example.com", "read")]),
    ("Platform", "infra-core", [("bob@example.com", "write"), ("carol@example.com", "read")]),
    ("Payments", "billing-api", [("bob@example.com", "write"), ("dave@example.com", "read")]),
    ("Payments", "ledger", [("alice@example.com", "admin"), ("dave@example.com", "write")]),
    ("Mobile", "ios-app", [("alice@example.com", "write")]),
    ("Mobile", "android-app", [("carol@example.com", "read")]),
]

SECRETS = [
    # project (team/name), key, value, note, kind
    ("Platform", "demo-api", "DATABASE_URL", "postgres://demo:s3cret@db:5432/demo", "primary app DB", "database"),
    ("Platform", "demo-api", "API_KEY", "demo-api-key-001", "public API key", "plain"),
    ("Platform", "demo-api", "STRIPE_WEBHOOK_SECRET", "whsec_mock_stripe_001", "stripe webhook", "plain"),
    ("Platform", "demo-api", "REDIS_URL", "redis://redis:6379/0", "cache", "plain"),
    ("Platform", "infra-core", "SSH_DEPLOY_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\nMOCKKEY\n-----END OPENSSH PRIVATE KEY-----", "deploy key", "ssh"),
    ("Platform", "infra-core", "TLS_CERT", "-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----", "edge cert", "certificate"),
    ("Platform", "infra-core", "AWS_ACCESS_KEY_ID", "AKIAMOCKPLATFORM", "AWS key id", "plain"),
    ("Platform", "infra-core", "AWS_SECRET_ACCESS_KEY", "awsSecretMockPlatform001", "AWS secret", "plain"),
    ("Payments", "billing-api", "DATABASE_URL", "postgres://bill:pay@db:5432/billing", "billing DB", "database"),
    ("Payments", "billing-api", "PAYMENT_GATEWAY_KEY", "pk_test_mock_payments", "gateway public", "plain"),
    ("Payments", "billing-api", "PAYMENT_GATEWAY_SECRET", "sk_test_mock_payments_secret", "gateway secret", "plain"),
    ("Payments", "ledger", "DATABASE_URL", "postgres://ledger:led@db:5432/ledger", "ledger DB", "database"),
    ("Payments", "ledger", "KV_CONFIG", "FOO=bar\nBAZ=qux\n", "sample kv", "kv"),
    ("Mobile", "ios-app", "APNS_KEY", "apns-mock-key-ios", "Apple push", "plain"),
    ("Mobile", "ios-app", "SENTRY_DSN", "https://mock@sentry.example/ios", "Sentry", "plain"),
    ("Mobile", "android-app", "FCM_SERVER_KEY", "fcm-mock-server-key", "Firebase", "plain"),
    ("Mobile", "android-app", "SENTRY_DSN", "https://mock@sentry.example/android", "Sentry", "plain"),
]

# Secrets that require admin approval before the value can be revealed.
REQUIRES_APPROVAL = [
    ("Payments", "billing-api", "PAYMENT_GATEWAY_SECRET"),
    ("Platform", "infra-core", "SSH_DEPLOY_KEY"),
]

# Team groups: (team, name, source, external_key, team-binding-role, member emails)
# The team-binding-role is applied as an rbac.bindings at team scope.
GROUPS = [
    (
        "Platform",
        "platform-ops",
        "manual",
        None,
        "member",
        ["bob@example.com", "carol@example.com"],
    ),
    (
        "Platform",
        "ldap-platform-admins",
        "ldap",
        "cn=platform-admins,ou=groups,dc=example,dc=com",
        "admin",
        [],  # membership comes from directory sync
    ),
    (
        "Payments",
        "payments-readers",
        "manual",
        None,
        "viewer",
        ["dave@example.com"],
    ),
]

# Project-scope group bindings: (team, project, group, project role short)
PROJECT_GROUP_BINDINGS = [
    ("Platform", "demo-api", "platform-ops", "write"),
    ("Payments", "billing-api", "payments-readers", "read"),
]

# Custom (non-built-in) roles to exercise the Roles page, custom-role bindings,
# Access review, and Effective access. Each rule is (resources, verbs).
CUSTOM_ROLES = [
    (
        "secrets-operator",
        "Reveal and update secrets in assigned projects",
        [
            (["secrets"], ["get", "list", "reveal", "update"]),
            (["machine_tokens"], ["get", "list"]),
        ],
    ),
    (
        "audit-reader",
        "Read audit logs at team scope",
        [(["audit"], ["get", "list"])],
    ),
    (
        "infra-viewer",
        "Read-only view of projects and secret metadata",
        [(["projects", "secrets"], ["get", "list"])],
    ),
    (
        "payments-reviewer",
        "Reveal-only access to payments secrets",
        [(["secrets"], ["get", "list", "reveal"])],
    ),
]

# Custom-role bindings: (scope_kind, scope key, subject_kind, subject ref, role)
# scope key matches the team/project/secret tuples above ("team" → (team,) etc.).
CUSTOM_BINDINGS = [
    ("team", ("Platform",), "User", "carol@example.com", "audit-reader"),
    ("team", ("Platform",), "User", "dave@example.com", "infra-viewer"),
    ("project", ("Platform", "demo-api"), "Group", "platform-ops", "secrets-operator"),
    ("project", ("Payments", "billing-api"), "Group", "payments-readers", "payments-reviewer"),
    ("secret", ("Platform", "infra-core", "SSH_DEPLOY_KEY"), "User", "carol@example.com", "secrets-operator"),
]

# Machine accounts (ServiceAccount subjects): (team, project, name, role, scopes|None)
# role must match api.machine_tokens CHECK: service-read | service-reveal | service-write
# scopes = exact secret keys and/or glob patterns (containing * or ?), or
# None = wildcard '*' (inherit all project keys). Restricted secrets need an exact key.
MACHINE_TOKENS = [
    ("Platform", "demo-api", "ci-demo", "service-reveal", ["API_KEY", "DATABASE_URL"]),
    ("Platform", "demo-api", "ci-readonly", "service-read", ["API_KEY"]),
    ("Platform", "infra-core", "deploy-bot", "service-write", ["AWS_*", "SSH_DEPLOY_KEY"]),
    ("Payments", "billing-api", "eso-billing", "service-reveal", None),
    ("Mobile", "android-app", "mobile-reader", "service-read", ["SENTRY_*"]),
]

# Secret-scope bindings: (team, project, secret_key, user_email|None, group_name|None, role)
# role is the full rbac.roles name (secret-* or a custom role). Sets access_mode=restricted.
SECRET_BINDINGS = [
    ("Platform", "infra-core", "AWS_SECRET_ACCESS_KEY", "alice@example.com", None, "secret-reveal"),
    ("Platform", "infra-core", "AWS_SECRET_ACCESS_KEY", None, "platform-ops", "secret-read"),
    ("Platform", "infra-core", "SSH_DEPLOY_KEY", "carol@example.com", None, "secrets-operator"),
    ("Payments", "ledger", "DATABASE_URL", None, "payments-readers", "secret-reveal"),
]

# Webhooks: (scope_kind, scope key|None, name, url, events)
# scope_kind is 'cluster' (scope key None) or 'project' (scope key = (team, project)).
# events must match core.config.WEBHOOK_EVENTS.
WEBHOOKS = [
    (
        "cluster",
        None,
        "corvus-cluster-events",
        "https://hooks.example.internal/corvus/cluster",
        ["secret.created", "secret.updated", "secret.revealed", "secret.deleted", "org.member_add", "org.project_key_created"],
    ),
    (
        "project",
        ("Platform", "demo-api"),
        "demo-api-deploy",
        "https://hooks.example.internal/corvus/demo-api",
        ["secret.created", "secret.updated", "secret.deleted"],
    ),
    (
        "project",
        ("Payments", "billing-api"),
        "billing-alerts",
        "https://hooks.example.internal/corvus/billing",
        ["secret.revealed"],
    ),
]

# Metadata (flows team -> project -> secret). Keys must be unique per hierarchy
# level or the guard_meta_precedence trigger rejects the write.
# (team, [(key, value), ...])
TEAM_META = [
    ("Platform", [("cost-center", "CC-100"), ("owner", "platform-ops"), ("compliance", "soc2")]),
    ("Payments", [("cost-center", "CC-200"), ("owner", "payments"), ("compliance", "pci")]),
    ("Mobile", [("cost-center", "CC-300")]),
]

# (team, project, [(key, value), ...])
PROJECT_META = [
    ("Platform", "demo-api", [("tier", "prod"), ("on-call", "platform-ops")]),
    ("Platform", "infra-core", [("tier", "prod"), ("on-call", "platform-ops")]),
    ("Payments", "billing-api", [("tier", "prod"), ("data-class", "restricted")]),
    ("Payments", "ledger", [("tier", "prod")]),
    ("Mobile", "ios-app", [("tier", "staging")]),
    ("Mobile", "android-app", [("tier", "staging")]),
]

# (team, project, secret_key, [(key, value), ...])
SECRET_META = [
    ("Platform", "demo-api", "API_KEY", [("env", "prod"), ("region", "us-east-1")]),
    ("Platform", "demo-api", "DATABASE_URL", [("env", "prod"), ("region", "us-east-1")]),
    ("Platform", "infra-core", "SSH_DEPLOY_KEY", [("region", "us-east-1")]),
    ("Platform", "infra-core", "AWS_SECRET_ACCESS_KEY", [("region", "us-east-1"), ("rotation", "90d")]),
    ("Payments", "billing-api", "PAYMENT_GATEWAY_SECRET", [("env", "prod")]),
    ("Payments", "ledger", "DATABASE_URL", [("env", "prod")]),
]

TEAM_ROLE_MAP = {
    "owner": "team-owner",
    "admin": "team-admin",
    "member": "team-member",
    "viewer": "team-viewer",
}
PROJECT_ROLE_MAP = {
    "admin": "project-admin",
    "write": "project-write",
    "reveal": "project-reveal",
    "read": "project-read",
}
# Machine token / ServiceAccount role names (api.machine_tokens CHECK).
SERVICE_ROLE_MAP = {
    "service-read": "service-read",
    "service-reveal": "service-reveal",
    "service-write": "service-write",
}


def main() -> None:
    with db.connect_admin(autocommit=True) as conn, conn.cursor() as cur:
        # Users
        uids: dict[str, str] = {}
        for email, name, is_admin in USERS:
            cur.execute("SELECT id FROM private.users WHERE email = %s", (email,))
            row = cur.fetchone()
            if row:
                uid = str(row["id"])
                cur.execute(
                    """
                    UPDATE private.users
                       SET password_hash = crypt(%s, gen_salt('bf')),
                           name = %s,
                           is_global_admin = %s,
                           auth_source = 'local',
                           disabled_at = NULL,
                           email_verified_at = COALESCE(email_verified_at, now()),
                           email_verify_token_hash = NULL,
                           email_verify_sent_at = NULL
                     WHERE id = %s::uuid
                    """,
                    (PASSWORD, name, is_admin, uid),
                )
            else:
                cur.execute(
                    "SELECT private.register_user(%s, %s, %s) AS id",
                    (email, PASSWORD, name),
                )
                uid = str(cur.fetchone()["id"])
                if is_admin:
                    cur.execute(
                        "UPDATE private.users SET is_global_admin = true WHERE id = %s::uuid",
                        (uid,),
                    )
            cur.execute(
                """
                UPDATE private.users
                   SET email_verified_at = COALESCE(email_verified_at, now()),
                       email_verify_token_hash = NULL,
                       email_verify_sent_at = NULL
                 WHERE id = %s::uuid
                """,
                (uid,),
            )
            uids[email] = uid
            print(f"user  {email:24}  admin={is_admin}  {uid}")

        def role_id(name: str):
            cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (name,))
            r = cur.fetchone()
            return str(r["id"]) if r else None

        def bind_user(role_name: str, user_id: str, scope_kind: str, scope_id: str):
            rid = role_id(role_name)
            if not rid:
                print(f"warn  missing role {role_name}")
                return
            cur.execute(
                """
                DELETE FROM rbac.bindings
                WHERE subject_kind = 'User' AND subject_id = %s::uuid
                  AND scope_kind = %s AND scope_id = %s::uuid
                """,
                (user_id, scope_kind, scope_id),
            )
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (%s::uuid, 'User', %s::uuid, %s, %s::uuid, %s::uuid)
                ON CONFLICT DO NOTHING
                """,
                (rid, user_id, scope_kind, scope_id, user_id),
            )

        def bind_group(role_name: str, group_id: str, scope_kind: str, scope_id: str, by: str):
            rid = role_id(role_name)
            if not rid:
                print(f"warn  missing role {role_name}")
                return
            cur.execute(
                """
                DELETE FROM rbac.bindings
                WHERE subject_kind = 'Group' AND subject_id = %s::uuid
                  AND scope_kind = %s AND scope_id = %s::uuid
                """,
                (group_id, scope_kind, scope_id),
            )
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (%s::uuid, 'Group', %s::uuid, %s, %s::uuid, %s::uuid)
                ON CONFLICT DO NOTHING
                """,
                (rid, group_id, scope_kind, scope_id, by),
            )

        def bind_sa(role_name: str, token_id: str, scope_kind: str, scope_id: str, by: str):
            rid = role_id(role_name)
            if not rid:
                print(f"warn  missing role {role_name}")
                return
            cur.execute(
                """
                DELETE FROM rbac.bindings
                WHERE subject_kind = 'ServiceAccount' AND subject_id = %s::uuid
                  AND scope_kind = %s AND scope_id = %s::uuid
                """,
                (token_id, scope_kind, scope_id),
            )
            cur.execute(
                """
                INSERT INTO rbac.bindings
                  (role_id, subject_kind, subject_id, scope_kind, scope_id, created_by)
                VALUES (%s::uuid, 'ServiceAccount', %s::uuid, %s, %s::uuid, %s::uuid)
                ON CONFLICT DO NOTHING
                """,
                (rid, token_id, scope_kind, scope_id, by),
            )

        # Custom roles (idempotent by name)
        for name, description, rules in CUSTOM_ROLES:
            cur.execute(
                """
                INSERT INTO rbac.roles (name, description, built_in)
                VALUES (%s, %s, false)
                ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
                RETURNING id
                """,
                (name, description),
            )
            rid = str(cur.fetchone()["id"])
            cur.execute("DELETE FROM rbac.role_rules WHERE role_id = %s::uuid", (rid,))
            for resources, verbs in rules:
                cur.execute(
                    """
                    INSERT INTO rbac.role_rules (role_id, resources, verbs)
                    VALUES (%s::uuid, %s, %s)
                    """,
                    (rid, list(resources), list(verbs)),
                )
            print(f"role  {name:22}  rules={len(rules)}  {rid}")

        # Teams + team RBAC bindings
        team_ids: dict[str, str] = {}
        for team_name, owner_email, members in TEAMS:
            cur.execute("SELECT id FROM api.teams WHERE name = %s", (team_name,))
            row = cur.fetchone()
            if row:
                tid = str(row["id"])
            else:
                cur.execute(
                    """
                    INSERT INTO api.teams (name, created_by)
                    VALUES (%s, %s::uuid)
                    RETURNING id
                    """,
                    (team_name, uids[owner_email]),
                )
                tid = str(cur.fetchone()["id"])
            team_ids[team_name] = tid
            bind_user("team-owner", uids[owner_email], "team", tid)
            for email, role in members:
                bind_user(TEAM_ROLE_MAP.get(role, "team-member"), uids[email], "team", tid)
            print(f"team  {team_name:24}  {tid}")

        # Projects + project RBAC bindings
        project_ids: dict[tuple[str, str], str] = {}
        for team_name, proj_name, members in PROJECTS:
            tid = team_ids[team_name]
            cur.execute(
                "SELECT id FROM api.projects WHERE team_id = %s::uuid AND name = %s",
                (tid, proj_name),
            )
            row = cur.fetchone()
            if row:
                pid = str(row["id"])
            else:
                cur.execute(
                    """
                    INSERT INTO api.projects (team_id, name)
                    VALUES (%s::uuid, %s)
                    RETURNING id
                    """,
                    (tid, proj_name),
                )
                pid = str(cur.fetchone()["id"])
            project_ids[(team_name, proj_name)] = pid
            for email, role in members:
                bind_user(PROJECT_ROLE_MAP.get(role, "project-read"), uids[email], "project", pid)
            print(f"proj  {team_name}/{proj_name:16}  {pid}")

        # Secrets (encrypted with app MASTER_KEY)
        secret_ids: dict[tuple[str, str, str], str] = {}
        for team_name, proj_name, key, value, note, kind in SECRETS:
            pid = project_ids[(team_name, proj_name)]
            enc = crypto.encrypt(value)
            cur.execute(
                """
                INSERT INTO api.secrets (project_id, key, value_enc, note, kind)
                VALUES (%s::uuid, %s, %s, %s, %s)
                ON CONFLICT (project_id, key) WHERE deleted_at IS NULL
                DO UPDATE SET
                  value_enc = EXCLUDED.value_enc,
                  note = EXCLUDED.note,
                  kind = EXCLUDED.kind,
                  updated_at = now()
                RETURNING id
                """,
                (pid, key, enc, note, kind),
            )
            sid = str(cur.fetchone()["id"])
            secret_ids[(team_name, proj_name, key)] = sid
            print(f"sec   {team_name}/{proj_name}/{key}  {sid}")

        # Reveal-approval secrets. Bypass guard_secret_update (requires a
        # project-admin JWT; this seed runs as the postgres superuser).
        cur.execute("ALTER TABLE api.secrets DISABLE TRIGGER guard_secret_update")
        for team_name, proj_name, key in REQUIRES_APPROVAL:
            sid = secret_ids[(team_name, proj_name, key)]
            cur.execute(
                """
                UPDATE api.secrets SET requires_approval = true
                WHERE id = %s::uuid
                """,
                (sid,),
            )
            print(f"appr  {team_name}/{proj_name}/{key}  requires approval")

        # Groups + members + team-scope group bindings
        group_ids: dict[tuple[str, str], str] = {}
        for team_name, gname, source, ext_key, team_role, members in GROUPS:
            tid = team_ids[team_name]
            cur.execute(
                """
                SELECT id FROM api.groups
                WHERE team_id = %s::uuid AND name = %s
                """,
                (tid, gname),
            )
            row = cur.fetchone()
            if row:
                gid = str(row["id"])
                cur.execute(
                    "UPDATE api.groups SET source = %s, external_key = %s WHERE id = %s::uuid",
                    (source, ext_key, gid),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO api.groups (team_id, name, source, external_key)
                    VALUES (%s::uuid, %s, %s, %s)
                    RETURNING id
                    """,
                    (tid, gname, source, ext_key),
                )
                gid = str(cur.fetchone()["id"])
            group_ids[(team_name, gname)] = gid
            for email in members:
                cur.execute(
                    """
                    INSERT INTO api.group_members (group_id, user_id, source)
                    VALUES (%s::uuid, %s::uuid, 'manual')
                    ON CONFLICT (group_id, user_id) DO UPDATE SET source = 'manual'
                    """,
                    (gid, uids[email]),
                )
            if team_role:
                bind_group(
                    TEAM_ROLE_MAP.get(team_role, f"team-{team_role}"),
                    gid, "team", tid,
                    uids.get("admin@example.com") or next(iter(uids.values())),
                )
            print(f"group {team_name}/{gname:24}  {gid}  bind={team_role or 'none'}")

        # Project-scope group bindings
        for team_name, proj_name, gname, role in PROJECT_GROUP_BINDINGS:
            pid = project_ids[(team_name, proj_name)]
            gid = group_ids[(team_name, gname)]
            bind_group(
                PROJECT_ROLE_MAP.get(role, "project-read"),
                gid, "project", pid,
                uids.get("admin@example.com") or next(iter(uids.values())),
            )
            print(f"gbind {team_name}/{proj_name}/{gname} -> {PROJECT_ROLE_MAP.get(role)}")

        # Custom-role bindings
        for scope_kind, scope_key, subject_kind, subject_ref, role_name in CUSTOM_BINDINGS:
            if scope_kind == "team":
                scope_id = team_ids[scope_key[0]]
            elif scope_kind == "project":
                scope_id = project_ids[(scope_key[0], scope_key[1])]
            else:
                scope_id = secret_ids[(scope_key[0], scope_key[1], scope_key[2])]
            if subject_kind == "User":
                bind_user(role_name, uids[subject_ref], scope_kind, scope_id)
            elif subject_kind == "Group":
                gid = group_ids[(scope_key[0], subject_ref)]
                bind_group(role_name, gid, scope_kind, scope_id,
                           uids.get("admin@example.com") or next(iter(uids.values())))
            print(f"cbind {scope_kind} {scope_key} {subject_kind} {subject_ref} -> {role_name}")

        # Machine accounts (ServiceAccount subjects) + allow-list scopes
        token_ids: dict[tuple[str, str, str], str] = {}
        live_machine_token = ""
        live_machine_project_id = ""
        for team_name, proj_name, name, role, scope_keys in MACHINE_TOKENS:
            pid = project_ids[(team_name, proj_name)]
            raw = "ss_" + secrets.token_urlsafe(32)
            thash = crypto.sha256_hex(raw)
            prefix = raw[:11]
            cur.execute(
                """
                INSERT INTO api.machine_tokens (project_id, name, token_hash, token_prefix, role)
                VALUES (%s::uuid, %s, %s, %s, %s)
                ON CONFLICT (token_prefix) DO UPDATE SET
                  project_id = EXCLUDED.project_id,
                  name = EXCLUDED.name,
                  role = EXCLUDED.role,
                  expires_at = NULL
                RETURNING id
                """,
                (pid, name, thash, prefix, role),
            )
            token_id = str(cur.fetchone()["id"])
            token_ids[(team_name, proj_name, name)] = token_id
            if not live_machine_token:
                live_machine_token = raw
                live_machine_project_id = pid
            cur.execute(
                "DELETE FROM api.machine_token_scope WHERE token_id = %s::uuid", (token_id,)
            )
            if scope_keys:
                for k in scope_keys:
                    if any(ch in k for ch in "*?"):
                        cur.execute(
                            """
                            INSERT INTO api.machine_token_scope (token_id, key_pattern)
                            VALUES (%s::uuid, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            (token_id, k),
                        )
                    else:
                        cur.execute(
                            """
                            INSERT INTO api.machine_token_scope (token_id, secret_key)
                            VALUES (%s::uuid, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            (token_id, k),
                        )
            else:
                cur.execute(
                    """
                    INSERT INTO api.machine_token_scope (token_id, key_pattern)
                    VALUES (%s::uuid, '*')
                    ON CONFLICT DO NOTHING
                    """,
                    (token_id,),
                )
            # ServiceAccount binding at project scope (service-* role)
            bind_sa(
                SERVICE_ROLE_MAP.get(role, "service-reveal"),
                token_id, "project", pid,
                uids.get("admin@example.com") or next(iter(uids.values())),
            )
            print(f"token {team_name}/{proj_name}/{name}  {raw}  (scope={'allow-list' if scope_keys else '*'})")

        # Secret-scope bindings (restricted access_mode)
        for team_name, proj_name, key, user_email, gname, role_name in SECRET_BINDINGS:
            sid = secret_ids[(team_name, proj_name, key)]
            cur.execute(
                "UPDATE api.secrets SET access_mode = 'restricted' WHERE id = %s::uuid",
                (sid,),
            )
            rid = role_id(role_name)
            if not rid:
                print(f"warn  missing role {role_name} - skip binding for {key}")
                continue
            if user_email:
                cur.execute(
                    """
                    DELETE FROM rbac.bindings
                    WHERE scope_kind = 'secret' AND scope_id = %s::uuid
                      AND subject_kind = 'User' AND subject_id = %s::uuid
                    """,
                    (sid, uids[user_email]),
                )
                cur.execute(
                    """
                    INSERT INTO rbac.bindings (role_id, subject_kind, subject_id, scope_kind, scope_id)
                    VALUES (%s::uuid, 'User', %s::uuid, 'secret', %s::uuid)
                    """,
                    (rid, uids[user_email], sid),
                )
                print(f"bind  {key} user={user_email} {role_name}")
            if gname:
                gid = group_ids[(team_name, gname)]
                cur.execute(
                    """
                    DELETE FROM rbac.bindings
                    WHERE scope_kind = 'secret' AND scope_id = %s::uuid
                      AND subject_kind = 'Group' AND subject_id = %s::uuid
                    """,
                    (sid, gid),
                )
                cur.execute(
                    """
                    INSERT INTO rbac.bindings (role_id, subject_kind, subject_id, scope_kind, scope_id)
                    VALUES (%s::uuid, 'Group', %s::uuid, 'secret', %s::uuid)
                    """,
                    (rid, gid, sid),
                )
                print(f"bind  {key} group={gname} {role_name}")
        cur.execute("ALTER TABLE api.secrets ENABLE TRIGGER guard_secret_update")

        # Webhooks (cluster-wide + project-scoped), idempotent by (scope_kind, scope_id, name).
        admin_uid = uids.get("admin@example.com") or next(iter(uids.values()))
        for scope_kind, scope_key, name, url, events in WEBHOOKS:
            scope_id = None if scope_kind == "cluster" else project_ids[scope_key]
            cur.execute(
                """
                SELECT id FROM api.webhooks
                WHERE scope_kind = %s AND scope_id IS NOT DISTINCT FROM %s::uuid AND name = %s
                """,
                (scope_kind, scope_id, name),
            )
            row = cur.fetchone()
            token = secrets.token_hex(32)
            if row:
                cur.execute(
                    """
                    UPDATE api.webhooks
                       SET url = %s, events = %s, secret_token = %s, active = true
                     WHERE id = %s::uuid
                    """,
                    (url, events, token, str(row["id"])),
                )
                print(f"hook  {scope_kind}/{scope_key or 'cluster'}/{name}  updated")
            else:
                cur.execute(
                    """
                    INSERT INTO api.webhooks (name, url, secret_token, events, scope_kind, scope_id, ssl_verify, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s::uuid, true, %s::uuid)
                    """,
                    (name, url, token, events, scope_kind, scope_id, admin_uid),
                )
                print(f"hook  {scope_kind}/{scope_key or 'cluster'}/{name}  added")

        # Metadata (team -> project -> secret inheritance).
        for team_name, pairs in TEAM_META:
            tid = team_ids[team_name]
            for key, value in pairs:
                cur.execute(
                    """
                    INSERT INTO api.team_meta (team_id, key, value, updated_at)
                    VALUES (%s::uuid, %s, %s, now())
                    ON CONFLICT (team_id, key) DO UPDATE
                      SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                    """,
                    (tid, key, value),
                )
            print(f"tmeta {team_name:16}  {len(pairs)} keys")

        for team_name, proj_name, pairs in PROJECT_META:
            pid = project_ids[(team_name, proj_name)]
            for key, value in pairs:
                cur.execute(
                    """
                    INSERT INTO api.project_meta (project_id, key, value, updated_at)
                    VALUES (%s::uuid, %s, %s, now())
                    ON CONFLICT (project_id, key) DO UPDATE
                      SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                    """,
                    (pid, key, value),
                )
            print(f"pmeta {team_name}/{proj_name:16}  {len(pairs)} keys")

        for team_name, proj_name, secret_key, pairs in SECRET_META:
            sid = secret_ids[(team_name, proj_name, secret_key)]
            for key, value in pairs:
                cur.execute(
                    """
                    INSERT INTO api.secret_meta (secret_id, key, value, updated_at)
                    VALUES (%s::uuid, %s, %s, now())
                    ON CONFLICT (secret_id, key) DO UPDATE
                      SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                    """,
                    (sid, key, value),
                )
            print(f"smeta {team_name}/{proj_name}/{secret_key}  {len(pairs)} keys")

    print()
    print("All accounts password: (see PASSWORD in scripts/seed_mock.py)")
    print("Log in at http://127.0.0.1:8080  e.g. admin@example.com")
    print("Custom roles:", ", ".join(name for name, _, _ in CUSTOM_ROLES))
    print("Machine tokens (raw, shown once):")
    for team_name, proj_name, name, _role, _keys in MACHINE_TOKENS:
        print(f"  {team_name}/{proj_name}/{name}")
    print("CLI needs a project UUID (above) + a machine token ss_… from UI Integrations.")
    if live_machine_token:
        print("Live API smoke test variables:")
        print(f"  LIVE_PROJECT_REF={live_machine_project_id}")
        print(f"  LIVE_MACHINE_TOKEN={live_machine_token}")
    print("Groups: team Groups tab; project Access and secret Access for scoped bindings.")
    print("Access review: Administration > Access review (custom roles included).")
    seed_hsm_slot()


def seed_hsm_slot():
    """Seed a named HSM slot for the dev SoftHSM2 token, if not already present."""
    inserted = False
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO private.hsm_slots (name, pkcs11_url, description, is_default)
            VALUES (
                'dev-hsm',
                'pkcs11:token=corvus;object=byok-kek'
                '?module-path=/usr/lib64/libsofthsm2.so&pin-source=/hsm/tokens/hsm-pin',
                'Local SoftHSM2 development slot',
                true
            )
            ON CONFLICT (name) DO NOTHING
            """
        )
        inserted = cur.rowcount > 0
    crypto.clear_slot_url_cache()
    if inserted:
        print("HSM slot: dev-hsm (SoftHSM2)")


if __name__ == "__main__":
    main()
