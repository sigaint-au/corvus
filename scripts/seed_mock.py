#!/usr/bin/env python3
"""Seed mock users, teams, projects, and secrets (dev only).

Password for every local account: password
Run inside the app container (has MASTER_KEY + DB + crypto):

  podman exec secretserver_app_1 python /tmp/seed_mock.py

Or from host after copying the file in.
"""
from __future__ import annotations

import os
import sys

# App modules live on PYTHONPATH in the container (/app)
sys.path.insert(0, "/app")
os.chdir("/app")

import crypto  # noqa: E402
import db  # noqa: E402

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
    # name, owner_email, members: (email, role)
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
    # team_name, project_name, members: (email, role)  — team owners/admins get access via team
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

# Team groups: (team_name, group_name, source, external_key, team_role, members emails)
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

# Project group roles: (team, project, group_name, role)
PROJECT_GROUP_ROLES = [
    ("Platform", "demo-api", "platform-ops", "write"),
    ("Payments", "billing-api", "payments-readers", "read"),
]

# Secret-scope RBAC bindings: (team, project, secret_key, user_email|None, group_name|None, perm)
# perm maps to secret-read / secret-reveal / secret-write.
SECRET_ACL_GRANTS = [
    ("Platform", "infra-core", "AWS_SECRET_ACCESS_KEY", "alice@example.com", None, "reveal"),
    ("Platform", "infra-core", "AWS_SECRET_ACCESS_KEY", None, "platform-ops", "read"),
]


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
                           disabled_at = NULL
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
            uids[email] = uid
            print(f"user  {email:24}  admin={is_admin}  {uid}")

        # Teams + memberships
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

            # owner
            cur.execute(
                """
                INSERT INTO api.team_members (team_id, user_id, role, source)
                VALUES (%s::uuid, %s::uuid, 'owner', 'manual')
                ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role
                """,
                (tid, uids[owner_email]),
            )
            for email, role in members:
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s::uuid, %s::uuid, %s, 'manual')
                    ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (tid, uids[email], role),
                )
            print(f"team  {team_name:24}  {tid}")

        # Projects + project members
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
                cur.execute(
                    """
                    INSERT INTO api.project_members (project_id, user_id, role)
                    VALUES (%s::uuid, %s::uuid, %s)
                    ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (pid, uids[email], role),
                )
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

        # Groups + members
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
                    """
                    UPDATE api.groups
                       SET source = %s, external_key = %s, team_role = %s
                     WHERE id = %s::uuid
                    """,
                    (source, ext_key, team_role, gid),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO api.groups
                      (team_id, name, source, external_key, team_role)
                    VALUES (%s::uuid, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (tid, gname, source, ext_key, team_role),
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
            print(f"group {team_name}/{gname:24}  {gid}  role={team_role}")

        # Project group roles
        for team_name, proj_name, gname, role in PROJECT_GROUP_ROLES:
            pid = project_ids[(team_name, proj_name)]
            gid = group_ids[(team_name, gname)]
            cur.execute(
                """
                INSERT INTO api.project_group_roles (project_id, group_id, role)
                VALUES (%s::uuid, %s::uuid, %s)
                ON CONFLICT (project_id, group_id) DO UPDATE SET role = EXCLUDED.role
                """,
                (pid, gid, role),
            )
            print(f"pgr   {team_name}/{proj_name}/{gname} → {role}")

        # Secret-scope role bindings (replaces legacy secret_acl grants)
        perm_to_role = {
            "read": "secret-read",
            "reveal": "secret-reveal",
            "write": "secret-write",
        }
        for team_name, proj_name, key, user_email, gname, perm in SECRET_ACL_GRANTS:
            sid = secret_ids[(team_name, proj_name, key)]
            role_name = perm_to_role.get(perm, "secret-reveal")
            cur.execute(
                """
                UPDATE api.secrets SET acl_mode = 'custom'
                WHERE id = %s::uuid
                """,
                (sid,),
            )
            cur.execute("SELECT id FROM rbac.roles WHERE name = %s", (role_name,))
            role = cur.fetchone()
            if not role:
                print(f"warn  missing role {role_name} — skip binding for {key}")
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
                    INSERT INTO rbac.bindings
                      (role_id, subject_kind, subject_id, scope_kind, scope_id)
                    VALUES (%s::uuid, 'User', %s::uuid, 'secret', %s::uuid)
                    """,
                    (str(role["id"]), uids[user_email], sid),
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
                    INSERT INTO rbac.bindings
                      (role_id, subject_kind, subject_id, scope_kind, scope_id)
                    VALUES (%s::uuid, 'Group', %s::uuid, 'secret', %s::uuid)
                    """,
                    (str(role["id"]), gid, sid),
                )
                print(f"bind  {key} group={gname} {role_name}")

    print()
    print("All accounts password:", PASSWORD)
    print("Log in at http://127.0.0.1:8080  e.g. admin@example.com / password")
    print("CLI needs a project UUID (above) + machine token ss_… from UI Integrations.")
    print("Groups: team Groups tab; project group roles on project Settings.")


if __name__ == "__main__":
    main()
