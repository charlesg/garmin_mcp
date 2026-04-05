"""Playwright-based Garmin authentication.

Uses a real Chrome browser to bypass Cloudflare TLS fingerprinting on Garmin's
SSO endpoints, then performs the standard OAuth1/OAuth2 token exchange in Python.

The resulting tokens are written to disk in garth's format (two JSON files),
so the rest of the stack (garminconnect + garth) works exactly as before.
"""

import json
import os
import re
import time
from typing import Callable
from urllib.parse import parse_qs

import requests
from requests_oauthlib import OAuth1Session


OAUTH_CONSUMER_URL = "https://thegarth.s3.amazonaws.com/oauth_consumer.json"
_oauth_consumer: dict = {}


def _get_oauth_consumer() -> dict:
    global _oauth_consumer
    if not _oauth_consumer:
        _oauth_consumer = requests.get(OAUTH_CONSUMER_URL, timeout=10).json()
    return _oauth_consumer


def _get_oauth1_token(ticket: str, domain: str) -> dict:
    """Exchange a service ticket for an OAuth1 token."""
    consumer = _get_oauth_consumer()
    sess = OAuth1Session(consumer["consumer_key"], consumer["consumer_secret"])
    login_url = f"https://sso.{domain}/sso/embed"
    url = (
        f"https://connectapi.{domain}/oauth-service/oauth/preauthorized"
        f"?ticket={ticket}&login-url={login_url}&accepts-mfa-tokens=true"
    )
    resp = sess.get(
        url,
        headers={"User-Agent": "com.garmin.android.apps.connectmobile"},
        timeout=15,
    )
    resp.raise_for_status()
    parsed = parse_qs(resp.text)
    token = {k: v[0] for k, v in parsed.items()}
    token["domain"] = domain
    return token


def _exchange_oauth2(oauth1: dict, domain: str) -> dict:
    """Exchange OAuth1 token for OAuth2 token."""
    consumer = _get_oauth_consumer()
    sess = OAuth1Session(
        consumer["consumer_key"],
        consumer["consumer_secret"],
        resource_owner_key=oauth1["oauth_token"],
        resource_owner_secret=oauth1["oauth_token_secret"],
    )
    data = {}
    if oauth1.get("mfa_token"):
        data["mfa_token"] = oauth1["mfa_token"]

    url = f"https://connectapi.{domain}/oauth-service/oauth/exchange/user/2.0"
    resp = sess.post(
        url,
        headers={
            "User-Agent": "com.garmin.android.apps.connectmobile",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=data,
        timeout=15,
    )
    resp.raise_for_status()
    token = resp.json()
    now = int(time.time())
    token["expires_at"] = now + token["expires_in"]
    token["refresh_token_expires_at"] = now + token["refresh_token_expires_in"]
    return token


def _save_tokens(oauth1: dict, oauth2: dict, token_path: str) -> None:
    """Write tokens to disk in garth's format."""
    expanded = os.path.expanduser(token_path)
    os.makedirs(expanded, exist_ok=True)

    oauth1_data = {
        "oauth_token": oauth1["oauth_token"],
        "oauth_token_secret": oauth1["oauth_token_secret"],
        "mfa_token": oauth1.get("mfa_token"),
        "mfa_expiration_timestamp": oauth1.get("mfa_expiration_timestamp"),
        "domain": oauth1.get("domain", "garmin.com"),
    }
    with open(os.path.join(expanded, "oauth1_token.json"), "w") as f:
        json.dump(oauth1_data, f, indent=4)

    with open(os.path.join(expanded, "oauth2_token.json"), "w") as f:
        json.dump(oauth2, f, indent=4)


def _extract_ticket(text: str) -> str | None:
    """Find a Garmin service ticket in HTML or URL text."""
    m = re.search(r'embed\?ticket=(ST-[^"&\s<]+)', text)
    if m:
        return m.group(1)
    m = re.search(r'[?&]ticket=(ST-[^"&\s<]+)', text)
    if m:
        return m.group(1)
    return None


def login(
    email: str,
    password: str,
    token_path: str,
    *,
    is_cn: bool = False,
    prompt_mfa: Callable[[], str] | None = None,
) -> tuple[dict, dict]:
    """Authenticate with Garmin Connect via a real Chrome browser.

    Handles Cloudflare TLS fingerprinting by using Playwright (real Chrome)
    for the SSO form flow, then completes the OAuth1/OAuth2 token exchange in
    Python.

    Args:
        email: Garmin Connect email.
        password: Garmin Connect password.
        token_path: Directory path where OAuth token files will be saved.
        is_cn: Use Garmin Connect China (garmin.cn).
        prompt_mfa: Callable that returns the MFA code string. If None and MFA
            is required, the browser window stays open for manual entry (up to
            5 minutes).

    Returns:
        Tuple of (oauth1_token dict, oauth2_token dict).

    Raises:
        ImportError: If playwright is not installed / browser not found.
        RuntimeError: If login fails or ticket cannot be extracted.
        requests.HTTPError: If the OAuth token exchange fails.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        raise ImportError(
            "playwright is not installed.\n"
            "Run: uv run playwright install chromium"
        )

    domain = "garmin.cn" if is_cn else "garmin.com"
    SSO = f"https://sso.{domain}/sso"
    EMBED_PARAMS = (
        "?id=gauth-widget"
        "&embedWidget=true"
        f"&gauthHost={SSO}"
    )
    SIGNIN_PARAMS = (
        "?id=gauth-widget"
        "&embedWidget=true"
        f"&gauthHost={SSO}/embed"
        f"&service={SSO}/embed"
        f"&source={SSO}/embed"
        f"&redirectAfterAccountLoginUrl={SSO}/embed"
        f"&redirectAfterAccountCreationUrl={SSO}/embed"
    )

    ticket = None
    mfa_needed = False

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                headless=False,
                channel="chrome",
                args=["--disable-blink-features=AutomationControlled"],
            )
        except Exception:
            # Fall back to bundled Chromium if system Chrome not found
            browser = p.chromium.launch(
                headless=False,
                args=["--disable-blink-features=AutomationControlled"],
            )

        context = browser.new_context(locale="en-US")
        context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        page = context.new_page()

        # Intercept SSO responses to capture the service ticket from the raw
        # response body — more reliable than reading the rendered page, because
        # JavaScript may redirect before we call page.content().
        captured_bodies: list[str] = []

        def on_response(response):
            if "sso" in response.url and response.request.method in ("GET", "POST"):
                try:
                    body = response.text()
                    if "ticket=ST-" in body or 'embed?ticket' in body:
                        captured_bodies.append(body)
                except Exception:
                    pass

        page.on("response", on_response)

        try:
            print("  Opening Garmin sign-in page...")

            # Step 1: establish SSO embed cookies
            page.goto(f"{SSO}/embed{EMBED_PARAMS}", wait_until="domcontentloaded", timeout=20_000)

            # Step 2: load the sign-in form (sets CSRF)
            page.goto(f"{SSO}/signin{SIGNIN_PARAMS}", wait_until="domcontentloaded", timeout=20_000)

            # Step 3: fill credentials
            try:
                user_input = page.locator(
                    'input[name="username"], input[name="email"], input[id="email"]'
                ).first
                user_input.wait_for(timeout=10_000)
                user_input.fill(email)
            except PWTimeout:
                raise RuntimeError(
                    "Could not find email input on page. "
                    f"Current URL: {page.url}"
                )

            page.locator('input[name="password"]').first.fill(password)
            page.locator('button[type="submit"]').first.click()
            print("  Credentials submitted, waiting for Garmin...")

            # Wait for the page to respond — either Success, MFA, or error
            # Poll for up to 30s for either a ticket in captured responses or
            # a detectable page state
            for _ in range(30):
                time.sleep(1)

                # Check responses captured so far
                for body in captured_bodies:
                    t = _extract_ticket(body)
                    if t:
                        ticket = t
                        break
                if ticket:
                    break

                # Check page content / URL
                try:
                    current_url = page.url
                    content = page.content()
                except Exception:
                    continue

                t = _extract_ticket(content) or _extract_ticket(current_url)
                if t:
                    ticket = t
                    break

                # Detect MFA page
                if (
                    "verifyMFA" in current_url
                    or "mfa" in current_url.lower()
                    or "MFA" in content
                    or "mfa-code" in content
                ):
                    mfa_needed = True
                    break

                # Detect obvious failure
                if "success" in content.lower() and "ticket" not in content.lower():
                    # might be a generic success without ticket — keep waiting
                    pass

            # Handle MFA
            if mfa_needed and not ticket:
                print("  MFA required.")
                if prompt_mfa:
                    mfa_code = prompt_mfa()
                    try:
                        mfa_input = page.locator(
                            'input[name="mfa-code"], input[id*="mfa"], '
                            'input[type="tel"], input[inputmode="numeric"]'
                        ).first
                        mfa_input.wait_for(timeout=8_000)
                        mfa_input.fill(mfa_code)
                        page.locator('button[type="submit"]').first.click()
                    except PWTimeout:
                        raise RuntimeError("MFA input field not found on page")

                    # Wait for ticket after MFA submission
                    for _ in range(20):
                        time.sleep(1)
                        for body in captured_bodies:
                            t = _extract_ticket(body)
                            if t:
                                ticket = t
                                break
                        if ticket:
                            break
                        try:
                            t = _extract_ticket(page.content()) or _extract_ticket(page.url)
                            if t:
                                ticket = t
                                break
                        except Exception:
                            pass

                else:
                    # No prompt_mfa — leave browser open for manual entry
                    print(
                        "  Complete the MFA in the browser window (up to 5 min)..."
                    )
                    for _ in range(300):
                        time.sleep(1)
                        for body in captured_bodies:
                            t = _extract_ticket(body)
                            if t:
                                ticket = t
                                break
                        if ticket:
                            break
                        try:
                            t = _extract_ticket(page.content()) or _extract_ticket(page.url)
                            if t:
                                ticket = t
                                break
                        except Exception:
                            pass
                    if not ticket:
                        raise RuntimeError("Timed out waiting for MFA completion")

            if not ticket:
                # Capture debug info before closing
                try:
                    final_url = page.url
                    final_title = page.title()
                except Exception:
                    final_url = "unknown"
                    final_title = "unknown"
                raise RuntimeError(
                    f"Could not find service ticket after login.\n"
                    f"  Final page title: '{final_title}'\n"
                    f"  Final URL: {final_url}\n"
                    f"  This usually means the credentials were rejected or "
                    f"Cloudflare presented a challenge."
                )

        finally:
            context.close()
            browser.close()

    print(f"  Service ticket obtained, exchanging for OAuth tokens...")

    # Steps 4 & 5: OAuth token exchange in Python
    oauth1 = _get_oauth1_token(ticket, domain)
    oauth2 = _exchange_oauth2(oauth1, domain)

    _save_tokens(oauth1, oauth2, token_path)

    return oauth1, oauth2
