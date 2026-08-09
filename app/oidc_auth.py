"""OIDC authorization-code login (Keycloak, etc.).

# ponytail: no Authlib — urllib + PyJWT PyJWKClient. No group→team maps; add when needed.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import jwt
from jwt import PyJWKClient

import crypto
import db
import settings_svc
from ldap_auth import group_matches

log = logging.getLogger(__name__)

# issuer -> (fetched_at_monotonic, doc)
_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_clients: dict[str, PyJWKClient] = {}
_DISCOVERY_TTL_SEC = 3600

# Never accept symmetric/none algs from discovery (alg-confusion)
_ALLOWED_ID_TOKEN_ALGS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
    }
)


def oidc_cfg() -> dict:
    """Load and normalize OIDC settings from the server settings store.

    Returns:
        Dict of OIDC configuration keys (enabled flag, issuer, client id,
        secret, scopes, button label, username/groups claims, and email
        verification requirement), with stripped strings and defaults.

    Example:
        >>> cfg = oidc_cfg()
        >>> "oidc_issuer" in cfg and "oidc_client_id" in cfg
        True
    """
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
        "oidc_require_email_verified": s.get("oidc_require_email_verified", "true"),
    }


def oidc_enabled() -> bool:
    """Return whether OIDC login is configured and turned on.

    Returns:
        True when ``oidc_enabled`` is truthy and both issuer and client
        id are non-empty; False otherwise.

    Example:
        >>> isinstance(oidc_enabled(), bool)
        True
    """
    c = oidc_cfg()
    return settings_svc.truthy(c["oidc_enabled"]) and bool(
        c["oidc_issuer"] and c["oidc_client_id"]
    )


def _client_secret_plain() -> str:
    """Decrypt the OIDC client secret, falling back to stored value.

    On decrypt failure (e.g. plaintext mis-save or MASTER_KEY rotation),
    logs a warning and returns the stored string as plaintext.

    Returns:
        Plaintext client secret string, or empty string if unset.

    Example:
        >>> secret = _client_secret_plain()
        >>> isinstance(secret, str)
        True
    """
    enc = oidc_cfg().get("oidc_client_secret") or ""
    if not enc:
        return ""
    try:
        return crypto.decrypt(enc)
    except Exception:
        # Mis-saved plaintext or MASTER_KEY rotation — do not silently treat as OK forever.
        log.warning(
            "OIDC client secret decrypt failed; using stored value as plaintext "
            "(re-save secret in Server settings after fixing MASTER_KEY)"
        )
        return enc


def _http_json(method: str, url: str, data: dict | None = None, headers: dict | None = None) -> dict:
    """Perform an HTTP request and parse a JSON response body.

    Args:
        method: HTTP method (e.g. ``GET``, ``POST``).
        url: Absolute request URL.
        data: Optional form fields encoded as
            ``application/x-www-form-urlencoded`` for the body.
        headers: Optional extra request headers merged over defaults
            (Accept JSON, User-Agent).

    Returns:
        Parsed JSON object as a dict, or empty dict if the body is empty.

    Example:
        >>> # doc = _http_json("GET", "https://idp.example/.well-known/openid-configuration")
        >>> # "authorization_endpoint" in doc
    """
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
    """Fetch (and cache) the OpenID Connect discovery document for an issuer.

    Args:
        issuer: Issuer base URL; when None, uses configured ``oidc_issuer``.
            Trailing slashes are stripped.

    Returns:
        Discovery document dict including at least
        ``authorization_endpoint`` and ``token_endpoint``.

    Example:
        >>> # doc = discover("https://keycloak.example/realms/app")
        >>> # "jwks_uri" in doc
    """
    issuer = (issuer or oidc_cfg()["oidc_issuer"]).rstrip("/")
    if not issuer:
        raise RuntimeError("OIDC issuer not configured")
    now = time.monotonic()
    cached = _discovery_cache.get(issuer)
    if cached and (now - cached[0]) < _DISCOVERY_TTL_SEC:
        return cached[1]
    url = issuer + "/.well-known/openid-configuration"
    doc = _http_json("GET", url)
    if not doc.get("authorization_endpoint") or not doc.get("token_endpoint"):
        raise RuntimeError("OIDC discovery missing endpoints")
    _discovery_cache[issuer] = (now, doc)
    return doc


def clear_discovery_cache():
    """Clear cached OIDC discovery documents and JWKS clients.

    Returns:
        None.

    Example:
        >>> clear_discovery_cache()
    """
    _discovery_cache.clear()
    _jwks_clients.clear()


def redirect_uri_for_request(url_root: str = "") -> str:
    """Build the OIDC redirect URI for the callback endpoint.

    Prefers the configured public server URL; falls back to the request
    ``url_root``.

    Args:
        url_root: Request root URL (e.g. ``https://app.example/``) used
            when no configured public base URL is available.

    Returns:
        Absolute redirect URI ending in ``/login/oidc/callback``.

    Example:
        >>> redirect_uri_for_request("https://app.example/")
        'https://app.example/login/oidc/callback'
    """
    base = settings_svc.public_base_url(url_root)
    if not base:
        base = (url_root or "").rstrip("/")
    return base + "/login/oidc/callback"


def build_authorize_url(*, redirect_uri: str, state: str, nonce: str) -> str:
    """Build the authorization-code redirect URL for the identity provider.

    Args:
        redirect_uri: Registered OIDC callback URL.
        state: Opaque CSRF/state token returned by the IdP.
        nonce: Nonce embedded in the ID token for replay protection.

    Returns:
        Full authorization endpoint URL with query parameters
        (response_type, client_id, redirect_uri, scope, state, nonce).
        Ensures ``openid`` is included in the scope.

    Example:
        >>> # url = build_authorize_url(
        ... #     redirect_uri="https://app.example/login/oidc/callback",
        ... #     state="abc",
        ... #     nonce="xyz",
        ... # )
        >>> # url.startswith("https://")
    """
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
    """Exchange an authorization code for tokens at the token endpoint.

    Args:
        code: Authorization code from the IdP callback query string.
        redirect_uri: Same redirect URI used in the authorize request.

    Returns:
        Token response dict (typically includes ``id_token``,
        ``access_token``, etc.).

    Example:
        >>> # tokens = exchange_code(
        ... #     code="auth-code",
        ... #     redirect_uri="https://app.example/login/oidc/callback",
        ... # )
        >>> # "id_token" in tokens
    """
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
    """Verify and decode an OIDC ID token using the IdP JWKS.

    Validates signature, audience, issuer, required claims (exp, iat, sub),
    allowed asymmetric algorithms only, and exact nonce match.

    Args:
        id_token: Compact JWT string from the token endpoint.
        nonce: Expected nonce previously sent in the authorize request.

    Returns:
        Decoded ID token claims as a dict.

    Example:
        >>> # claims = verify_id_token(id_token, nonce=session_nonce)
        >>> # claims["sub"]
    """
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
    advertised = doc.get("id_token_signing_alg_values_supported") or ["RS256"]
    algs = [a for a in advertised if a in _ALLOWED_ID_TOKEN_ALGS]
    if not algs:
        algs = ["RS256"]
    claims = jwt.decode(
        id_token,
        key.key,
        algorithms=algs,
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
    """Read a top-level or dotted claim as a non-container string.

    Args:
        claims: ID token (or userinfo) claims mapping.
        claim_name: Claim key, or dotted path (e.g. ``preferred_username``).

    Returns:
        Stripped string value, or empty string if missing, blank, or if
        the value is a dict/list.

    Example:
        >>> _claim_value({"preferred_username": "ada"}, "preferred_username")
        'ada'
        >>> _claim_value({"a": {"b": "x"}}, "a.b")
        'x'
    """
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


def _email_verified(claims: dict) -> bool:
    """Return whether the ID token asserts a verified email.

    Accepts only explicit true / ``"true"`` / ``"1"`` / ``"yes"``;
    missing or false values are rejected for account linking safety.

    Args:
        claims: ID token claims mapping that may include
            ``email_verified``.

    Returns:
        True if email is explicitly verified; False otherwise.

    Example:
        >>> _email_verified({"email_verified": True})
        True
        >>> _email_verified({"email_verified": False})
        False
    """
    v = claims.get("email_verified")
    if v is True:
        return True
    if isinstance(v, str) and v.strip().lower() in ("true", "1", "yes"):
        return True
    return False


def claims_to_identity(claims: dict) -> dict:
    """Map verified ID token claims to an application identity dict.

    Requires a usable email claim; optionally enforces
    ``email_verified`` per settings. Display name prefers the configured
    username claim, then ``name``, then given/family name, then the
    email local-part.

    Args:
        claims: Decoded ID token claims (after signature/nonce checks).

    Returns:
        Dict with ``email``, ``name``, ``username``, ``sub``, and
        ``groups`` (list of group/role strings).

    Example:
        >>> idt = claims_to_identity({
        ...     "email": "A@B.COM",
        ...     "email_verified": True,
        ...     "preferred_username": "ada.l",
        ...     "sub": "1",
        ...     "groups": ["admins"],
        ... })
        >>> idt["email"]
        'a@b.com'
    """
    cfg = oidc_cfg()
    email = (claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        # Do not treat preferred_username as email — that claim is for username.
        raise RuntimeError("OIDC token has no usable email claim (need email scope)")
    if settings_svc.truthy(cfg.get("oidc_require_email_verified", "true")) and not _email_verified(
        claims
    ):
        raise RuntimeError(
            "OIDC email is not verified (email_verified claim required); "
            "fix identity provider email verification, or disable "
            "“Require verified email” in OIDC settings"
        )
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
    """Collect group/role names from ID token claims (Keycloak-friendly).

    Reads the configured (or provided) groups claim, supports dotted
    nested paths, and also merges Keycloak ``realm_access.roles``.
    Deduplicates case-insensitively while preserving first-seen order.

    Args:
        claims: ID token claims mapping.
        claim_name: Optional claim key or dotted path; defaults to
            configured ``oidc_groups_claim`` (usually ``groups``).

    Returns:
        List of unique group/role name strings.

    Example:
        >>> groups_from_claims({"groups": ["admins", "eng"], "realm_access": {"roles": ["admins"]}})
        ['admins', 'eng']
    """
    claim_name = (claim_name or oidc_cfg().get("oidc_groups_claim") or "groups").strip()
    out: list[str] = []

    def _add(val):
        """Append group names from a claim value into the outer list.

        Args:
            val: Claim value: a list of names, a single string, or None.

        Returns:
            None.

        Example:
            >>> # _add(["admins"]); _add("eng")  # mutates outer ``out``
        """
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
    """Upsert an OIDC user and apply global/team group maps.

    Args:
        email: Normalized user email address.
        name: Display name (empty string allowed).
        groups: Optional list of OIDC group/role names for map matching;
            treated as empty list when None.

    Returns:
        User row dict from the database after upsert and map application.

    Example:
        >>> # user = sync_oidc_user("a@b.com", "Ada", ["admins"])
        >>> # user["email"] == "a@b.com"
    """
    from dir_sync import (
        apply_global_admin_maps,
        apply_group_membership_maps,
        apply_team_membership_maps,
        fetch_user_row,
    )

    groups = list(groups or [])
    with db.connect_admin() as conn, conn.cursor() as cur:
        cur.execute("SELECT private.upsert_oidc_user(%s, %s) AS id", (email, name or ""))
        uid = cur.fetchone()["id"]
        cur.execute("SELECT oidc_group, role FROM private.oidc_role_maps")
        apply_global_admin_maps(cur, uid, groups, cur.fetchall() or [], "oidc_group")
        cur.execute("SELECT id, team_id, oidc_group, role FROM api.team_oidc_maps")
        apply_team_membership_maps(
            cur, uid, groups, cur.fetchall() or [], group_key="oidc_group", source="oidc"
        )
        apply_group_membership_maps(cur, uid, groups, source="oidc")
        user = fetch_user_row(cur, uid)
        if not user:
            raise RuntimeError("OIDC user upsert failed")
        return user


def new_state_nonce() -> tuple[str, str]:
    """Generate cryptographically strong OIDC state and nonce values.

    Returns:
        Tuple ``(state, nonce)`` of URL-safe random tokens (24 bytes each
        before encoding).

    Example:
        >>> state, nonce = new_state_nonce()
        >>> len(state) > 0 and len(nonce) > 0 and state != nonce
        True
    """
    return secrets.token_urlsafe(24), secrets.token_urlsafe(24)


if __name__ == "__main__":
    # lightweight self-check (no network)
    assert redirect_uri_for_request("https://app.example/") == (
        "https://app.example/login/oidc/callback"
    )
    idt = claims_to_identity(
        {
            "email": "A@B.COM",
            "email_verified": True,
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
    try:
        claims_to_identity({"email": "x@y.com", "email_verified": False, "sub": "1"})
        raise SystemExit("expected unverified email to fail")
    except RuntimeError:
        pass
    # Optional path when setting is off
    import unittest.mock as mock

    with mock.patch(
        "settings_svc.get_settings",
        return_value={
            "oidc_require_email_verified": "false",
            "oidc_username_claim": "preferred_username",
            "oidc_groups_claim": "groups",
        },
    ):
        loose = claims_to_identity(
            {"email": "x@y.com", "email_verified": False, "sub": "1"}
        )
        assert loose["email"] == "x@y.com"
    print("ok")
