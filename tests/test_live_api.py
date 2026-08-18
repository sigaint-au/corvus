"""Opt-in smoke tests for a running app, PostgREST, and ESO API stack."""
from __future__ import annotations

import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

pytestmark = pytest.mark.live
_APP_URL = os.environ.get("LIVE_APP_URL", "").rstrip("/")
_POSTGREST_URL = os.environ.get("LIVE_POSTGREST_URL", "").rstrip("/")
_JWT = os.environ.get("LIVE_API_JWT", "")
_JWT_IS_GLOBAL_ADMIN = os.environ.get("LIVE_API_JWT_IS_GLOBAL_ADMIN", "") == "1"
_MACHINE_TOKEN = os.environ.get("LIVE_MACHINE_TOKEN", "")
_PROJECT_REF = os.environ.get("LIVE_PROJECT_REF", "")


def _request(url: str, method: str = "GET", token: str = "", body: bytes | None = None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        with urlopen(Request(url, method=method, headers=headers, data=body), timeout=10) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


@pytest.mark.skipif(not _APP_URL, reason="LIVE_APP_URL is not configured")
def test_live_health_endpoint():
    """Verify the Flask health endpoint is reachable and reports healthy."""
    status, body = _request(f"{_APP_URL}/health")
    assert status == 200
    assert json.loads(body)["status"] == "ok"


@pytest.mark.skipif(not _POSTGREST_URL, reason="LIVE_POSTGREST_URL is not configured")
def test_live_hsm_rpc_is_not_anonymous():
    """Verify anonymous callers cannot invoke sensitive HSM slot RPCs."""
    status, _ = _request(
        f"{_POSTGREST_URL}/rpc/list_hsm_slots",
        method="POST",
        body=b"{}",
    )
    assert status in (401, 404)
    status, _ = _request(
        f"{_POSTGREST_URL}/rpc/hsm_slot_url",
        method="POST",
        body=json.dumps({"p_slot_id": "00000000-0000-0000-0000-000000000000"}).encode(),
    )
    assert status in (401, 404)


@pytest.mark.skipif(not _POSTGREST_URL or not _JWT, reason="LIVE_POSTGREST_URL and LIVE_API_JWT are required")
def test_live_authenticated_postgrest_rls():
    """Verify a JWT can query RLS-protected data without receiving HSM URLs."""
    status, body = _request(
        f"{_POSTGREST_URL}/projects?select=id,name",
        token=_JWT,
    )
    assert status == 200
    assert isinstance(json.loads(body), list)

    status, body = _request(
        f"{_POSTGREST_URL}/rpc/list_hsm_slots",
        method="POST",
        token=_JWT,
        body=b"{}",
    )
    assert status == 200
    for slot in json.loads(body):
        if not _JWT_IS_GLOBAL_ADMIN:
            assert slot.get("pkcs11_url") is None


@pytest.mark.skipif(
    not _APP_URL or not _MACHINE_TOKEN or not _PROJECT_REF,
    reason="LIVE_APP_URL, LIVE_MACHINE_TOKEN, and LIVE_PROJECT_REF are required",
)
def test_live_machine_api_projects():
    """Verify the seeded machine-token API can list its project."""
    status, body = _request(
        f"{_APP_URL}/eso/v1/projects/{_PROJECT_REF}/secrets?meta=1",
        token=_MACHINE_TOKEN,
    )
    assert status == 200
    assert isinstance(json.loads(body)["items"], list)
