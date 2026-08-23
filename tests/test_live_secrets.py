"""Opt-in live tests: create, edit, and delete secrets on a running app.

These hit a real database through the HTTP UI and (optionally) the ESO API.
They exist to catch bind-order / type errors that mocked-DB unit tests miss —
the secret view-page save previously returned 500 because ``expires_at`` was
bound to the note string.

Skip unless ``LIVE_APP_URL`` is set. See ``docs/dev/testing.md``.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)
from uuid import uuid4

import pytest

pytestmark = pytest.mark.live

_APP_URL = os.environ.get("LIVE_APP_URL", "").rstrip("/")
_EMAIL = os.environ.get("LIVE_USER_EMAIL", "")
_PASSWORD = os.environ.get("LIVE_USER_PASSWORD", "")
_PROJECT_REF = os.environ.get("LIVE_PROJECT_REF", "")
_MACHINE_TOKEN = os.environ.get("LIVE_MACHINE_TOKEN", "")

_CSRF_META = re.compile(r'name="csrf-token"\s+content="([^"]+)"')
_CSRF_INPUT = re.compile(r'name="_csrf"\s+value="([^"]+)"')
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_PROJECT_HREF = re.compile(rf'href="(?:https?://[^"]+)?(/projects/({_UUID}))(?:\?[^"]*)?"')
_VIEW_HREF = re.compile(rf"/projects/({_UUID})/secrets/({_UUID})/view")
_TEAM_OPTION = re.compile(rf'<option value="({_UUID})"')


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class LiveClient:
    """Cookie-aware urllib client that does not auto-follow redirects."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self._opener = build_opener(HTTPCookieProcessor(CookieJar()), _NoRedirect())
        self._csrf = ""

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base + path

    def _open(self, url: str, data: bytes | None = None, headers: dict | None = None):
        req = Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
        try:
            with self._opener.open(req, timeout=30) as response:
                body = response.read()
                return response.status, body, {k.lower(): v for k, v in response.headers.items()}
        except HTTPError as error:
            return error.code, error.read(), {k.lower(): v for k, v in error.headers.items()}

    def get(self, path: str, follow: bool = True) -> tuple[int, str]:
        status, body, headers = self._open(self._url(path))
        hops = 0
        while follow and status in (301, 302, 303, 307, 308) and hops < 6:
            loc = headers.get("location")
            if not loc:
                break
            status, body, headers = self._open(self._url(loc))
            hops += 1
        html = body.decode("utf-8", "replace")
        self._capture_csrf(html)
        return status, html

    def post_form(self, path: str, fields: dict, follow: bool = False) -> tuple[int, str, str | None]:
        payload = dict(fields)
        if self._csrf and "_csrf" not in payload:
            payload["_csrf"] = self._csrf
        status, body, headers = self._open(
            self._url(path),
            data=urlencode(payload).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        html = body.decode("utf-8", "replace")
        loc = headers.get("location")
        if follow and status in (301, 302, 303, 307, 308) and loc:
            status, html = self.get(loc, follow=True)
            return status, html, loc
        self._capture_csrf(html)
        return status, html, loc

    def request_json(
        self,
        path: str,
        method: str = "GET",
        token: str = "",
        payload: dict | None = None,
    ) -> tuple[int, object]:
        headers = {"Accept": "application/json"}
        data = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = Request(self._url(path), data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=30) as response:
                raw = response.read()
                status = response.status
        except HTTPError as error:
            raw = error.read()
            status = error.code
        if not raw:
            return status, None
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError:
            return status, raw.decode("utf-8", "replace")

    def _capture_csrf(self, html: str) -> None:
        match = _CSRF_META.search(html) or _CSRF_INPUT.search(html)
        if match:
            self._csrf = match.group(1)

    def login(self, email: str, password: str) -> None:
        status, _html = self.get("/login")
        assert status == 200, f"login page returned {status}"
        status, html, loc = self.post_form(
            "/login",
            {"email": email, "password": password},
            follow=True,
        )
        assert status == 200, f"login failed: {status} {html[:300]}"
        assert 'name="password"' not in html, "still on login page after POST"


def _assert_ok(status: int, body: str, action: str) -> None:
    assert status != 500, f"{action} returned 500: {body[:500]}"
    assert status < 500, f"{action} returned {status}: {body[:500]}"


def _unique_key() -> str:
    return f"live-pytest-{uuid4().hex[:12]}"


def _expiry_date() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=45)).date().isoformat()


@pytest.fixture
def live_client():
    if not _APP_URL:
        pytest.skip("LIVE_APP_URL is not configured")
    return LiveClient(_APP_URL)


@pytest.fixture
def browser(live_client):
    if not _EMAIL or not _PASSWORD:
        pytest.skip("LIVE_USER_EMAIL and LIVE_USER_PASSWORD are required")
    live_client.login(_EMAIL, _PASSWORD)
    return live_client


def _discover_project_id(browser: LiveClient) -> str:
    if _PROJECT_REF:
        return _PROJECT_REF
    status, html = browser.get("/projects")
    _assert_ok(status, html, "GET /projects")
    if "Choose a team" in html:
        options = _TEAM_OPTION.findall(html)
        assert options, "login succeeded but no team was available to select"
        status, html, _loc = browser.post_form(
            "/select-team",
            {"team_id": options[0], "next": "/projects"},
            follow=True,
        )
        _assert_ok(status, html, "POST /select-team")
    found = _PROJECT_HREF.findall(html)
    assert found, "no project links on /projects — seed a project or set LIVE_PROJECT_REF"
    return found[0][1]


def _find_secret_view(browser: LiveClient, project_id: str, key: str) -> str:
    status, html = browser.get(f"/projects/{project_id}?tab=secrets&q={key}")
    _assert_ok(status, html, f"list secrets q={key}")
    assert key in html, f"created secret {key!r} not listed"
    match = _VIEW_HREF.search(html)
    assert match, f"no /view link for {key!r}"
    return match.group(2)


@pytest.mark.skipif(not _APP_URL, reason="LIVE_APP_URL is not configured")
def test_live_html_secret_create_edit_delete(browser):
    """Create, edit (view-page save), and trash a secret through the HTML UI."""
    project_id = _discover_project_id(browser)
    key = _unique_key()
    secret_id = None
    try:
        status, html = browser.get(f"/projects/{project_id}/secrets/new")
        _assert_ok(status, html, "GET new-secret form")
        status, html, loc = browser.post_form(
            f"/projects/{project_id}/secrets/new",
            {
                "kind": "plain",
                "key": key,
                "plain_value": "live-create-value",
                "note": "live-create",
                "access_mode": "inherit",
                "requires_approval": "inherit",
            },
        )
        _assert_ok(status, html, "create secret")
        assert status in (302, 303), f"create expected redirect, got {status}: {html[:400]}"

        secret_id = _find_secret_view(browser, project_id, key)
        status, html = browser.get(f"/projects/{project_id}/secrets/{secret_id}/view")
        _assert_ok(status, html, "GET secret view")
        assert "live-create-value" in html

        new_value = "live-edited-value"
        note = "live-edited-note"
        status, html, loc = browser.post_form(
            f"/projects/{project_id}/secrets/{secret_id}/view",
            {
                "kind": "plain",
                "plain_value": new_value,
                "note": note,
                "expires_at": _expiry_date(),
            },
        )
        _assert_ok(status, html, "edit secret (view save)")
        assert status in (302, 303), f"edit expected redirect, got {status}: {html[:400]}"

        status, html = browser.get(f"/projects/{project_id}/secrets/{secret_id}/view")
        _assert_ok(status, html, "GET secret view after edit")
        assert new_value in html, "edited value not shown on view page"
        assert note in html, "edited note not shown on view page"

        status, html, loc = browser.post_form(
            f"/projects/{project_id}/secrets/{secret_id}/value",
            {"value": "live-inline-value", "expires_at": _expiry_date()},
        )
        _assert_ok(status, html, "edit secret (inline /value)")
        assert status in (200, 302, 303), f"inline edit returned {status}: {html[:400]}"

        status, html, loc = browser.post_form(
            f"/projects/{project_id}/secrets/{secret_id}/delete",
            {},
        )
        _assert_ok(status, html, "delete secret")
        assert status in (200, 302, 303), f"delete returned {status}: {html[:400]}"
        secret_id = None

        status, html = browser.get(f"/projects/{project_id}?tab=secrets&q={key}")
        _assert_ok(status, html, "list after delete")
        assert f">{key}<" not in html and f">{key}</code>" not in html
    finally:
        if secret_id:
            browser.get(f"/projects/{project_id}/secrets/{secret_id}/view")
            browser.post_form(f"/projects/{project_id}/secrets/{secret_id}/delete", {})


@pytest.mark.skipif(
    not _APP_URL or not _MACHINE_TOKEN or not _PROJECT_REF,
    reason="LIVE_APP_URL, LIVE_MACHINE_TOKEN, and LIVE_PROJECT_REF are required",
)
def test_live_eso_secret_create_edit_delete(live_client):
    """Create, replace, patch, and delete a secret through the ESO API."""
    key = _unique_key()
    base = f"/eso/v1/projects/{_PROJECT_REF}/secrets"
    created = False
    try:
        status, body = live_client.request_json(
            base,
            method="POST",
            token=_MACHINE_TOKEN,
            payload={"key": key, "value": "eso-create", "note": "eso-create", "kind": "plain"},
        )
        assert status != 500, f"ESO create 500: {body}"
        assert status == 200, f"ESO create {status}: {body}"
        created = True
        assert body["key"] == key
        assert body["value"] == "eso-create"

        status, body = live_client.request_json(
            f"{base}/{key}",
            method="PUT",
            token=_MACHINE_TOKEN,
            payload={"value": "eso-edited", "note": "eso-edited"},
        )
        assert status != 500, f"ESO put 500: {body}"
        assert status == 200, f"ESO put {status}: {body}"
        assert body["value"] == "eso-edited"
        assert body.get("note") == "eso-edited"

        status, body = live_client.request_json(
            f"{base}/{key}",
            method="PATCH",
            token=_MACHINE_TOKEN,
            payload={"note": "eso-patched", "expires_days": 30},
        )
        assert status != 500, f"ESO patch 500: {body}"
        assert status == 200, f"ESO patch {status}: {body}"
        assert body.get("note") == "eso-patched"

        status, body = live_client.request_json(
            f"{base}/{key}",
            method="GET",
            token=_MACHINE_TOKEN,
        )
        assert status == 200
        assert body["value"] == "eso-edited"

        status, body = live_client.request_json(
            f"{base}/{key}",
            method="DELETE",
            token=_MACHINE_TOKEN,
        )
        assert status != 500, f"ESO delete 500: {body}"
        assert status == 200, f"ESO delete {status}: {body}"
        created = False

        status, body = live_client.request_json(
            f"{base}/{key}",
            method="GET",
            token=_MACHINE_TOKEN,
        )
        assert status == 404
    finally:
        if created:
            live_client.request_json(
                f"{base}/{key}",
                method="DELETE",
                token=_MACHINE_TOKEN,
            )
