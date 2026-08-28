"""Opt-in Playwright browser tests against a running app.

Requires ``playwright`` and a Chromium install::

    pip install -e ".[e2e]"
    python -m playwright install chromium

These drive the real UI (HTMX partial swaps, the JS secret form, CSRF) against
a seeded Compose stack, which the urllib-based ``test_live_*`` suites cannot.
Skip unless ``LIVE_APP_URL`` is set. See ``docs/dev/testing.md``.

Run::

    LIVE_APP_URL=http://127.0.0.1:8080 \\
    LIVE_USER_EMAIL=admin@example.com \\
    LIVE_USER_PASSWORD=password \\
    pytest -m live tests/test_e2e.py
"""
from __future__ import annotations

import os
import re
from uuid import uuid4

import pytest

_pw = pytest.importorskip("playwright.sync_api")
sync_playwright = _pw.sync_playwright

pytestmark = pytest.mark.live

_APP_URL = os.environ.get("LIVE_APP_URL", "").rstrip("/")
_EMAIL = os.environ.get("LIVE_USER_EMAIL", "")
_PASSWORD = os.environ.get("LIVE_USER_PASSWORD", "")

_PROJECT_HREF = re.compile(r"/projects/([0-9a-f-]{36})(?:$|[?#])")


@pytest.fixture(scope="session")
def browser():
    if not _APP_URL:
        pytest.skip("LIVE_APP_URL is not configured")
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=True)
        except Exception as exc:  # playwright.Error when the browser is missing
            pytest.skip(f"chromium launch failed (run 'python -m playwright install chromium'): {exc}")
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    context = browser.new_context()
    page = context.new_page()
    page.on("dialog", lambda dialog: dialog.accept())  # hx-confirm delete dialog
    yield page
    context.close()


def _login(page, base: str, email: str, password: str) -> None:
    page.goto(f"{base}/login", wait_until="networkidle")
    page.fill('input[name="email"]', email)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_url("**/teams**", timeout=15_000)


def _first_project_id(page, base: str) -> str:
    page.goto(f"{base}/projects", wait_until="networkidle")
    for el in page.locator('a[href^="/projects/"]').all():
        match = _PROJECT_HREF.search(el.get_attribute("href") or "")
        if match:
            return match.group(1)
    raise AssertionError("no project link on /projects; seed a project or set LIVE_PROJECT_REF")


@pytest.mark.skipif(not _APP_URL, reason="LIVE_APP_URL is not configured")
def test_login(page):
    _login(page, _APP_URL, _EMAIL, _PASSWORD)
    assert page.url.rstrip("/").endswith("/teams")


@pytest.mark.skipif(
    not _APP_URL or not _EMAIL or not _PASSWORD,
    reason="LIVE_APP_URL, LIVE_USER_EMAIL, and LIVE_USER_PASSWORD are required",
)
def test_secret_lifecycle(page):
    base = _APP_URL
    _login(page, base, _EMAIL, _PASSWORD)
    project_id = _first_project_id(page, base)

    key = f"pw-{uuid4().hex[:8]}"
    value = "pw-secret-value"

    # Create through the advanced form (JS kind switching + CSRF).
    page.goto(f"{base}/projects/{project_id}/secrets/new", wait_until="networkidle")
    page.fill('input[name="key"]', key)
    page.fill("#adv-value", value)
    page.click('form#advanced-secret-form button[type="submit"]')
    page.wait_for_url(f"**/projects/{project_id}*", timeout=15_000)

    page.goto(f"{base}/projects/{project_id}?tab=secrets&q={key}", wait_until="networkidle")
    assert key in page.inner_text("#secrets-list")

    # Reveal through HTMX (the value is masked until clicked).
    page.click("#secrets-list a.secret-masked")
    page.wait_for_selector("#secrets-list .secret-value", timeout=15_000)
    assert page.locator("#secrets-list .secret-value").first.input_value() == value

    # Trash it via the row menu; the confirm dialog is auto-accepted.
    page.goto(f"{base}/projects/{project_id}?tab=secrets&q={key}", wait_until="networkidle")
    page.click(f'button[aria-label="Actions for {key}"]')
    page.click('menu button:has-text("Delete")')
    page.wait_for_function(
        "() => ![...document.querySelectorAll('#secrets-list tbody tr')]"
        ".some(tr => tr.textContent.includes(arguments[0]))",
        arg=key,
        timeout=15_000,
    )
