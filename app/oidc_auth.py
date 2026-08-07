"""OIDC authorization-code login (Keycloak, etc.).

# ponytail: no Authlib — urllib + PyJWT PyJWKClient. No group→team maps; add when needed.
"""

from __future__ import annotations

import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import jwt
from jwt import PyJWKClient

import crypto
import db
import settings_svc
from config import ROLE_RANK
from ldap_auth import group_matches

log = logging.getLogger(__name__)

_discovery_cache: dict[str, dict] = {}
_jwks_clients: dict[str, PyJWKClient] = {}


def oidc_cfg() -> dict:
    s = settings_svc.get_settings()
    return {
        "oidc_enabled": s.get("oidc_enabled", "false"),
        "oidc_issuer": (s.get("oidc_issuer") or "").strip().rstrip("/"),
        "oidc_client_id": (s.get("oidc_client_id") or "").strip(),
        "oidc_client_secret": s.get("oidc_client_secret") or "",
        "oidc_scopes": (s.get("oidc_scopes") or "openid email profile").strip(),
        "oidc_button_label": (s.get("oidc_button_label") or "Sign in with SSO").strip()
        or "Sign in with SSO",
        "oidc_username_claim": (s.get("oidc_username_claim") or "preferred_username").strip()
        or "preferred_username",
        "oidc_groups_claim": (s.get("oidc_groups_claim") or "groups").strip() or "groups",
    }


def oidc_enabled() -> bool:
    c = oidc_cfg()
    return settings_svc.truthy(c["oidc_enabled"]) and bool(
        c["oidc_issuer"] and c["oidc_client_id"]
    )


def _client_secret_plain() -> str:
    enc = oidc_cfg().get("oidc_client_secret") or ""
    if not enc:
        return ""
    try:
        return crypto.decrypt(enc)
    except Exception:
        # allow plaintext during transition / mis-save
        return enc


def _http_json(method: str, url: str, data: dict | None = None, headers: dict | None = None) -> dict:
    body = None
    hdrs = {"Accept": "application/json", "User-Agent": "secretstore-oidc/1"}
    if headers:
        hdrs.update(headers)
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"OIDC HTTP {e.code} from {url}: {err_body}") from e
    if not raw:
        return {}
    return json.loads(raw)


def discover(issuer: str | None = None) -> dict:
    issuer = (issuer or oidc_cfg()["oidc_issuer"]).rstrip("/")
    if not issuer:
        raise RuntimeError("OIDC issuer not configured")
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]
    url = issuer + "/.well-known/openid-configuration"
    doc = _http_json("GET", url)
    if not doc.get("authorization_endpoint") or not doc.get("token_endpoint"):
        raise RuntimeError("OIDC discovery missing endpoints")
    _discovery_cache[issuer] = doc
    return doc


def clear_discovery_cache():
    _discovery_cache.clear()
    _jwks_clients.clear()


def redirect_uri_for_request(url_root: str = "") -> str:
    """OIDC redirect URI: prefer configured server_url, else request url_root."""
    base = settings_svc.public_base_url(url_root)
    if not base:
        base = (url_root or "").rstrip("/")
    return base + "/login/oidc/callback"


def build_authorize_url(*, redirect_uri: str, state: str, nonce: str) -> str:
    c = oidc_cfg()
    doc = discover(c["oidc_issuer"])
    scopes = c["oidc_scopes"] or "openid email profile"
    if "openid" not in scopes.split():
        scopes = "openid " + scopes
    q = {
        "response_type": "code",
        "client_id": c["oidc_client_id"],
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
    }
    return doc["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)


def exchange_code(*, code: str, redirect_uri: str) -> dict:
    c = oidc_cfg()
    doc = discover(c["oidc_issuer"])
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": c["oidc_client_id"],
    }
    secret = _client_secret_plain()
    if secret:
        data["client_secret"] = secret
    return _http_json("POST", doc["token_endpoint"], data=data)


def verify_id_token(id_token: str, *, nonce: str) -> dict[str, Any]:
    c = oidc_cfg()
    issuer = c["oidc_issuer"]
    doc = discover(issuer)
    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise RuntimeError("OIDC discovery missing jwks_uri")
    client = _jwks_clients.get(jwks_uri)
    if client is None:
        client = PyJWKClient(jwks_uri, cache_keys=True)
        _jwks_clients[jwks_uri] = client
    key = client.get_signing_key_from_jwt(id_token)
    algs = doc.get("id_token_signing_alg_values_supported") or ["RS256"]
    claims = jwt.decode(
        id_token,
        key.key,
        algorithms=list(algs),
        audience=c["oidc_client_id"],
        issuer=issuer,
        options={"require": ["exp", "iat", "sub"]},
    )
    # Some IdPs append slash inconsistently — already normalized issuer in cfg
    token_nonce = claims.get("nonce")
    if not token_nonce or token_nonce != nonce:
        raise RuntimeError("OIDC nonce mismatch")
    return claims


def _claim_value(claims: dict, claim_name: str) -> str:
    """Read a top-level or dotted claim (e.g. preferred_username)."""
    claim_name = (claim_name or "").strip()
    if not claim_name:
        return ""
    if claim_name in claims and not isinstance(claims.get(claim_name), (dict, list)):
        return str(claims.get(claim_name) or "").strip()
    if "." in claim_name:
        cur: Any = claims
        for part in claim_name.split("."):
            if not isinstance(cur, dict):
                return ""
            cur = cur.get(part)
        if cur is None or isinstance(cur, (dict, list)):
            return ""
        return str(cur).strip()
    val = claims.get(claim_name)
    if val is None or isinstance(val, (dict, list)):
        return ""
    return str(val).strip()


def claims_to_identity(claims: dict) -> dict:
    cfg = oidc_cfg()
    email = (claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        # Do not treat preferred_username as email — that claim is for username.
        raise RuntimeError("OIDC token has no usable email claim (need email scope)")
    # Username → display name: configured claim (default preferred_username), then name, then email local-part
    username_claim = cfg.get("oidc_username_claim") or "preferred_username"
    username = _claim_value(claims, username_claim)
    name = username or (claims.get("name") or "").strip()
    if not name:
        parts = [claims.get("given_name") or "", claims.get("family_name") or ""]
        name = " ".join(p for p in parts if p).strip()
    if not name:
        name = email.split("@", 1)[0]
    return {
        "email": email,
        "name": name,
        "username": username or name,
        "sub": claims.get("sub") or "",
        "groups": groups_from_claims(claims),
    }


def groups_from_claims(claims: dict, claim_name: str | None = None) -> list[str]:
    """Collect group/role names from ID token claims (Keycloak-friendly)."""
    claim_name = (claim_name or oidc_cfg().get("oidc_groups_claim") or "groups").strip()
    out: list[str] = []

    def _add(val):
        if val is None:
            return
        if isinstance(val, list):
            for x in val:
                s = str(x).strip()
                if s:
                    out.append(s)
        elif isinstance(val, str) and val.strip():
            out.append(val.strip())

    _add(claims.get(claim_name))
    # Nested path e.g. realm_access.roles
    if "." in claim_name:
        cur: Any = claims
        for part in claim_name.split("."):
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        _add(cur)
    # Keycloak defaults often present alongside custom mappers
    ra = claims.get("realm_access")
    if isinstance(ra, dict):
        _add(ra.get("roles"))
    # de-dupe preserve order
    seen = set()
    uniq = []
    for g in out:
        low = g.lower()
        if low in seen:
            continue
        seen.add(low)
        uniq.append(g)
    return uniq


def sync_oidc_user(email: str, name: str, groups: list | None = None) -> dict:
    """Upsert OIDC user; apply global + team group maps. Returns user row."""
    groups = list(groups or [])
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute("SELECT private.upsert_oidc_user(%s, %s) AS id", (email, name or ""))
        uid = cur.fetchone()["id"]

        cur.execute("SELECT oidc_group, role FROM private.oidc_role_maps")
        role_maps = cur.fetchall() or []
        if role_maps:
            is_admin = any(
                m["role"] == "global_admin" and group_matches(m["oidc_group"], groups)
                for m in role_maps
            )
            cur.execute(
                "UPDATE private.users SET is_global_admin = %s WHERE id = %s",
                (is_admin, str(uid)),
            )

        cur.execute(
            "SELECT id, email, name, is_global_admin FROM private.users WHERE id = %s",
            (str(uid),),
        )
        user = cur.fetchone()
        if not user:
            raise RuntimeError("OIDC user upsert failed")

        cur.execute("SELECT id, team_id, oidc_group, role FROM api.team_oidc_maps")
        tmaps = cur.fetchall() or []
        desired: dict[str, str] = {}
        for m in tmaps:
            if not group_matches(m["oidc_group"], groups):
                continue
            tid = str(m["team_id"])
            role = m["role"]
            if tid not in desired or ROLE_RANK.get(role, 0) > ROLE_RANK.get(
                desired[tid], 0
            ):
                desired[tid] = role

        cur.execute(
            """
            DELETE FROM api.team_members
            WHERE user_id = %s AND source = 'oidc'
              AND NOT (team_id = ANY(%s::uuid[]))
            """,
            (str(uid), list(desired.keys()) or []),
        )
        for tid, role in desired.items():
            cur.execute(
                """
                SELECT role, source FROM api.team_members
                WHERE team_id = %s AND user_id = %s
                """,
                (tid, str(uid)),
            )
            existing = cur.fetchone()
            if existing and existing.get("source") == "manual":
                continue
            if existing:
                cur.execute(
                    """
                    UPDATE api.team_members SET role = %s, source = 'oidc'
                    WHERE team_id = %s AND user_id = %s
                    """,
                    (role, tid, str(uid)),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO api.team_members (team_id, user_id, role, source)
                    VALUES (%s, %s, %s, 'oidc')
                    """,
                    (tid, str(uid), role),
                )
        # re-read is_global_admin after map apply
        cur.execute(
            "SELECT id, email, name, is_global_admin FROM private.users WHERE id = %s",
            (str(uid),),
        )
        return cur.fetchone()


def new_state_nonce() -> tuple[str, str]:
    return secrets.token_urlsafe(24), secrets.token_urlsafe(24)


if __name__ == "__main__":
    # lightweight self-check (no network)
    assert redirect_uri_for_request("https://app.example/") == (
        "https://app.example/login/oidc/callback"
    )
    idt = claims_to_identity(
        {
            "email": "A@B.COM",
            "preferred_username": "ada.l",
            "name": "Ada Lovelace",
            "nonce": "n",
            "sub": "1",
            "groups": ["admins", "eng"],
            "realm_access": {"roles": ["offline_access", "admins"]},
        }
    )
    assert idt["email"] == "a@b.com"
    assert idt["name"] == "ada.l"  # preferred_username wins by default
    assert idt["username"] == "ada.l"
    assert "admins" in idt["groups"] and "eng" in idt["groups"]
    assert group_matches("admins", idt["groups"])
    print("ok")
