"""Audit action constants and event-description vocabulary."""

# Actions written to api.secret_audit.action (must match DB CHECK + private.audit_secret)
ACTIONS = (
    "created",
    "updated",
    "revealed",
    "deleted",
    "restored",
    "purged",
    "machine_upsert",
    "exported",
    "access_requested",
    "access_approved",
    "access_denied",
)

# Common org_audit.action values (free text; these are conventions)
ORG_MEMBER_ADD = "member_add"
ORG_MEMBER_REMOVE = "member_remove"
ORG_MEMBER_ROLE = "member_role"
ORG_OWNERSHIP = "ownership_transfer"
ORG_INVITE_CREATE = "invite_create"
ORG_INVITE_REVOKE = "invite_revoke"
ORG_JOIN_REQUEST = "join_request"
ORG_JOIN_APPROVE = "join_approve"
ORG_JOIN_REJECT = "join_reject"
ORG_LDAP_MAP_ADD = "ldap_map_add"
ORG_LDAP_MAP_DELETE = "ldap_map_delete"
ORG_OIDC_MAP_ADD = "oidc_map_add"
ORG_OIDC_MAP_DELETE = "oidc_map_delete"
ORG_TEAM_SETTINGS = "team_settings"
ORG_PROJECT_MEMBER_ADD = "project_member_add"
ORG_PROJECT_MEMBER_REMOVE = "project_member_remove"
ORG_PROJECT_MEMBER_ROLE = "project_member_role"
ORG_PROJECT_KEY_CREATED = "project_key_created"
ORG_PROJECT_KEY_ADOPTED = "project_key_adopted"
ORG_PROJECT_KEY_MIGRATED = "project_key_migrated"
ORG_HSM_KEK_ROTATED = "hsm_kek_rotated"
ORG_HSM_BULK_MIGRATED = "hsm_bulk_migrated"

_ACTION_VERB = {
    "created": "created",
    "updated": "updated",
    "revealed": "revealed",
    "deleted": "deleted",
    "restored": "restored",
    "purged": "permanently deleted",
    "machine_upsert": "upserted via machine token",
    "exported": "exported secrets",
    "access_requested": "requested access to",
    "access_approved": "approved access to",
    "access_denied": "denied access to",
}

# Special per-action sentence shapes for describe_event.
_EVENT_FORMATS = {
    "exported": lambda who, verb, key: f"{who} {verb}" + (f" ({key})" if key else ""),
    "machine_upsert": lambda who, verb, key: (
        f"{who} {verb} “{key}”" if key else f"{who} {verb} a secret"
    ),
}

# Org actions that represent access / role changes (for access reviews)
ROLE_CHANGE_ACTIONS = (
    ORG_MEMBER_ADD,
    ORG_MEMBER_REMOVE,
    ORG_MEMBER_ROLE,
    ORG_OWNERSHIP,
    ORG_INVITE_CREATE,
    ORG_INVITE_REVOKE,
    ORG_JOIN_APPROVE,
    ORG_JOIN_REJECT,
    ORG_LDAP_MAP_ADD,
    ORG_LDAP_MAP_DELETE,
    ORG_OIDC_MAP_ADD,
    ORG_OIDC_MAP_DELETE,
    ORG_PROJECT_MEMBER_ADD,
    ORG_PROJECT_MEMBER_REMOVE,
    ORG_PROJECT_MEMBER_ROLE,
)

# Org actions for the encryption key lifecycle (filtered in the admin audit UI)
ENC_CHANGE_ACTIONS = (
    ORG_PROJECT_KEY_CREATED,
    ORG_PROJECT_KEY_ADOPTED,
    ORG_PROJECT_KEY_MIGRATED,
    ORG_HSM_KEK_ROTATED,
    ORG_HSM_BULK_MIGRATED,
)


def describe_event(row) -> str:
    """Build a human-readable who/what line for a secret audit row.

    Args:
        row: Mapping with optional keys actor_email, action, and secret_key.

    Returns:
        Sentence describing the actor and action, e.g.
        'alice@ex.com created “API_KEY”'.

    Example:
        >>> describe_event({"actor_email": "a@x.com", "action": "created", "secret_key": "K"})
        'a@x.com created “K”'
    """
    who = (row.get("actor_email") or "").strip() or "Someone"
    action = row.get("action") or ""
    key = (row.get("secret_key") or "").strip()
    verb = _ACTION_VERB.get(action, action or "acted on")
    formatter = _EVENT_FORMATS.get(action)
    if formatter:
        return formatter(who, verb, key)
    return f"{who} {verb} " + (f"“{key}”" if key else "a secret")
