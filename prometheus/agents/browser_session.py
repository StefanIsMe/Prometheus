"""Agnostic browser session manager for Prometheus.

Handles browser automation, account creation, login, and state persistence
via CDP (browser-harness). Designed to work on any target website by
discovering form fields, API endpoints, and ID patterns dynamically.

Usage:
    from prometheus.agents.browser_session import BrowserSession

    async with BrowserSession(target="syfe.com") as session:
        await session.create_account(email="user@example.com", password="Test123!")
        await session.login(email="user@example.com", password="Test123!")
        apis = await session.harvest_apis(pages=["/dashboard", "/portfolio"])
"""

from __future__ import annotations

import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Target profile — config per target, extendable via YAML or dict
# ---------------------------------------------------------------------------


@dataclass
class TargetProfile:
    """Defines how to interact with a specific target website.

    All fields are optional — the scanner auto-discovers forms and APIs
    when fields are left as defaults.
    """

    name: str = ""
    base_url: str = ""
    signup_path: str = "/signup"
    login_path: str = "/login"
    pages_to_scan: list[str] = field(default_factory=lambda: ["/"])
    email_domain: str = "@example.com"
    signup_selectors: dict[str, str] = field(default_factory=dict)
    login_selectors: dict[str, str] = field(default_factory=dict)
    api_patterns: list[str] = field(
        default_factory=lambda: [
            r"/api/",
            r"/v\d+/",
            r"/graphql",
            r"/rest/",
            r"/users?",
            r"/account",
            r"/portfolio",
            r"/transaction",
            r"/order",
            r"/profile",
            r"/balance",
            r"/wallet",
        ]
    )
    id_patterns: list[str] = field(
        default_factory=lambda: [
            r"/\d{5,10}",  # numeric IDs in path
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",  # UUIDs
        ]
    )
    id_param_names: list[str] = field(
        default_factory=lambda: [
            "id",
            "userId",
            "user_id",
            "accountId",
            "account_id",
            "portfolioId",
            "portfolio_id",
            "profileId",
            "profile_id",
            "customerId",
            "customer_id",
            "orderId",
            "order_id",
            "transactionId",
            "transaction_id",
            "uuid",
            "token",
        ]
    )


# ---------------------------------------------------------------------------
# Predefined target profiles
# ---------------------------------------------------------------------------

TARGET_PROFILES: dict[str, TargetProfile] = {}


# Load extension profiles (from prometheus/tools/idor_scanner/target_profiles.py)
def _load_extension_target_profiles() -> (
    None
):  # codeql[py/unsafe-cyclic-import] : lazy import to avoid cycle: target_profiles.py imports TargetProfile from this module
    try:
        from prometheus.tools.idor_scanner.target_profiles import (  # noqa: PLC0415
            TARGET_PROFILES as _EXTRA,
        )

        TARGET_PROFILES.update(_EXTRA)
    except ImportError:
        logger.debug("extension target_profiles module not available, ignoring", exc_info=True)


_load_extension_target_profiles()

# Core profiles
TARGET_PROFILES.setdefault(
    "syfe",
    TargetProfile(
        name="Syfe",
        base_url="https://www.syfe.com",
        signup_path="/create-account",
        login_path="/login",
        pages_to_scan=["/", "/dashboard", "/portfolio", "/transactions"],
        api_patterns=[
            r"/api/",
            r"/v\d+/",
            r"/graphql",
            r"/users?",
            r"/account",
            r"/portfolio",
            r"/transaction",
            r"/order",
            r"/balance",
            r"/wallet",
        ],
    ),
)
TARGET_PROFILES.setdefault(
    "bullish",
    TargetProfile(
        name="Bullish Exchange",
        base_url="https://simnext.bullish-test.com",
        signup_path="/register",
        login_path="/login",
        pages_to_scan=["/", "/dashboard", "/wallet", "/orders", "/profile"],
    ),
)


def get_target_profile(name: str) -> TargetProfile:
    """Get a target profile by name, or return a generic one."""
    name = name.lower().replace(" ", "-")
    if name in TARGET_PROFILES:
        return TARGET_PROFILES[name]
    return TargetProfile(name=name)


# ---------------------------------------------------------------------------
# Browser session — wraps browser-harness CDP interface
# ---------------------------------------------------------------------------


class BrowserSession:
    """Manages a browser session via CDP for a single user.

    Handles:
    - Navigation
    - Account creation (auto-discovers form fields)
    - Login
    - API call interception
    - Cookie/session persistence
    """

    def __init__(
        self,
        profile: TargetProfile,
        email_prefix: str = "",
        password: str = "",
        cdp_url: str = "http://localhost:9222",
        session_dir: str = "",
    ):
        self.profile = profile
        self.email_prefix = email_prefix or f"prometheus{random.randint(1000, 9999)}"
        self.password = password or f"Test{random.randint(10000, 99999)}!"
        self.cdp_url = cdp_url
        self.session_dir = Path(session_dir) if session_dir else Path("/tmp/prometheus-sessions")
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.email_a = f"{self.email_prefix}{profile.email_domain}"
        self.email_b = f"{self.email_prefix}+test2{profile.email_domain}"

        # Will be populated dynamically
        self.harvested_endpoints: list[dict[str, Any]] = []
        self.captured_responses: dict[str, str] = {}
        self.auth_cookies: list[dict[str, Any]] = []

    def _ensure_browser(self) -> None:
        """Ensure Chrome and the browser-harness daemon are running."""
        from browser_harness.admin import ensure_daemon

        try:
            ensure_daemon()
            logger.info("Browser daemon ensured")
        except Exception as e:
            logger.warning("Browser daemon start failed: %s", e)

    async def create_account(self, email: str) -> bool:
        """Create an account on the target site.

        Auto-discovers signup fields by looking for email/password/name
        input types. Returns True if account created successfully.
        """
        self._ensure_browser()
        from browser_harness import helpers as h

        signup_url = self.profile.base_url.rstrip("/") + self.profile.signup_path
        logger.info("Creating account %s at %s", email, signup_url)

        h.goto_url(signup_url)
        time.sleep(3)

        # Auto-discover form fields
        fields = self._discover_form_fields()
        if not fields:
            logger.error("No form fields found on %s", signup_url)
            return False

        # Fill in discovered fields
        filled = False  # noqa: F841  — assignment result consumed by outer control flow
        for fld in fields:
            input_type = fld.get("type", "")
            name = fld.get("name", "").lower()
            placeholder = fld.get("placeholder", "").lower()
            selector = fld.get("selector", "")

            if input_type == "email" or "email" in name or "email" in placeholder:
                h.fill_input(selector, email)
                filled = True
            elif input_type == "password" and "confirm" not in name:
                h.fill_input(selector, self.password)
            elif "confirm" in name or "confirm" in placeholder:
                h.fill_input(selector, self.password)
            elif input_type == "text" and ("name" in name or "user" in name):
                h.fill_input(selector, f"Test User {random.randint(100, 999)}")

        if not filled:  # noqa: F841  — assignment result consumed by outer control flow
            # Fallback: try common selectors
            for css in ["input[type=email]", "input[name=email]", "input#email"]:
                try:
                    h.fill_input(css, email)
                    filled = True
                    break
                except Exception:
                    continue

        # Try to submit
        for css in [
            "button[type=submit]",
            "form button",
            "input[type=submit]",
            "button:contains('Sign Up')",
            "button:contains('Create')",
            "button:contains('Register')",
            ".signup-btn",
            "#signup-btn",
        ]:
            try:
                h.js(f"document.querySelector('{css}')?.click()")
                time.sleep(2)
                break
            except Exception:
                continue

        time.sleep(2)
        return True

    def _discover_form_fields(self) -> list[dict[str, str]]:
        """Discover input fields on the current page via JS."""
        from browser_harness import helpers as h

        js_code = """
        (function() {
            var inputs = document.querySelectorAll('input, select, textarea');
            var result = [];
            inputs.forEach(function(inp) {
                var rect = inp.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return; // hidden
                result.push({
                    type: inp.type || 'text',
                    name: inp.name || '',
                    id: inp.id || '',
                    placeholder: inp.placeholder || '',
                    selector: '#' + (inp.id || '') || 'input[name=\"' + (inp.name || '') + '\"]'
                });
            });
            return JSON.stringify(result);
        })()
        """
        try:
            raw = h.js(js_code)
            if raw:
                return json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            logger.debug("Form discovery failed: %s", e)
        return []

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(self, email: str) -> bool:
        """Log in with credentials. Auto-discovers login form fields."""
        from browser_harness import helpers as h

        login_url = self.profile.base_url.rstrip("/") + self.profile.login_path
        logger.info("Logging in as %s at %s", email, login_url)

        h.goto_url(login_url)
        time.sleep(3)

        fields = self._discover_form_fields()
        filled_email = False
        filled_pass = False

        for fld in fields:
            input_type = fld.get("type", "")
            name = fld.get("name", "").lower()
            placeholder = fld.get("placeholder", "").lower()
            selector = fld.get("selector", "")

            if input_type == "email" or "email" in name or "email" in placeholder:
                h.fill_input(selector, email)
                filled_email = True
            elif input_type == "password" or "password" in name:
                h.fill_input(selector, self.password)
                filled_pass = True

        if not filled_email:  # noqa: F841  — assignment result consumed by outer control flow
            for css in [
                "input[type=email]",
                "input[name=email]",
                "input#email",
                "input[placeholder*=mail]",
                "input[placeholder*=Email]",
            ]:
                try:
                    h.fill_input(css, email)
                    filled_email = True
                    break
                except Exception:
                    continue

        if not filled_pass:  # noqa: F841  — assignment result consumed by outer control flow
            for css in ["input[type=password]", "input[name=password]", "input#password"]:
                try:
                    h.fill_input(css, self.password)
                    filled_pass = True
                    break
                except Exception:
                    continue

        # Submit
        for css in [
            "button[type=submit]",
            "form button",
            "input[type=submit]",
            "button:contains('Log in')",
            "button:contains('Sign in')",
            "button:contains('Login')",
            ".login-btn",
            "#login-btn",
        ]:
            try:
                h.js(f"document.querySelector('{css}')?.click()")
                time.sleep(2)
                break
            except Exception:
                continue

        time.sleep(3)

        # Save cookies for later use
        try:
            raw = h.js("document.cookie")
            if raw:
                self.auth_cookies = [
                    {"name": c.split("=")[0].strip(), "value": "=".join(c.split("=")[1:]).strip()}
                    for c in raw.split(";")
                    if "=" in c
                ]
        except Exception:
            logger.debug("reading document.cookie via CDP failed, ignoring", exc_info=True)

        return True

    # ------------------------------------------------------------------
    # API harvesting — intercepts all XHR/fetch calls
    # ------------------------------------------------------------------

    async def harvest_apis(self) -> list[dict[str, Any]]:
        """Navigate to each page in the profile and harvest API calls."""
        from browser_harness import helpers as h

        self.harvested_endpoints = []

        for page_path in self.profile.pages_to_scan:
            url = self.profile.base_url.rstrip("/") + page_path
            logger.info("Scanning page: %s", url)

            try:
                h.goto_url(url)
                time.sleep(4)
            except Exception as e:
                logger.debug("Failed to load %s: %s", url, e)
                continue

            # Wait for network idle
            try:
                h.wait_for_load(timeout=10)
            except Exception:
                logger.debug(
                    "h.wait_for_load(10) failed, continuing without network idle", exc_info=True
                )

            # Extract API calls from Performance API
            apis = self._extract_api_calls()
            self.harvested_endpoints.extend(apis)

            # Also scan page source for API URLs
            source_apis = self._extract_api_from_source()
            self.harvested_endpoints.extend(source_apis)

        # Deduplicate
        seen = set()
        unique = []
        for ep in self.harvested_endpoints:
            key = ep.get("url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(ep)
        self.harvested_endpoints = unique

        logger.info("Harvested %d unique API endpoints", len(self.harvested_endpoints))
        return self.harvested_endpoints

    def _extract_api_calls(self) -> list[dict[str, Any]]:
        """Extract XHR/fetch calls from the Performance API."""
        from browser_harness import helpers as h

        js_code = """
        (function() {
            var entries = performance.getEntriesByType('resource');
            var results = [];
            entries.forEach(function(e) {
                if (e.initiatorType === 'xmlhttprequest' || e.initiatorType === 'fetch') {
                    results.push({
                        url: e.name.split('?')[0],
                        duration: e.duration,
                        type: e.initiatorType
                    });
                }
            });
            return JSON.stringify(results);
        })()
        """
        try:
            raw = h.js(js_code)
            if raw:
                return json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            logger.debug("API extraction failed: %s", e)
        return []

    def _extract_api_from_source(self) -> list[dict[str, Any]]:
        """Extract API URLs from page source and scripts."""
        from browser_harness import helpers as h

        patterns = self.profile.api_patterns
        js_code = (
            """
        (function() {
            var patterns = """
            + json.dumps(patterns)
            + """;
            var results = new Set();
            var pageText = document.documentElement.innerHTML;

            patterns.forEach(function(p) {
                var re = new RegExp(p, 'gi');
                var match;
                while ((match = re.exec(pageText)) !== null) {
                    var start = Math.max(0, match.index - 50);
                    var end = Math.min(pageText.length, match.index + match[0].length + 50);
                    var context = pageText.substring(start, end);
                    // Try to extract full URLs
                    var urlMatch = context.match(/https?:\\/\\/[^"'\\s<>]+/gi);
                    if (urlMatch) {
                        urlMatch.forEach(function(u) { results.add(u); });
                    }
                }
            });

            // Also check all script tags
            document.querySelectorAll('script[src]').forEach(function(s) {
                if (s.src) results.add(s.src);
            });

            return JSON.stringify(Array.from(results).map(function(u) {
                return {url: u.split('?')[0], type: 'source'};
            }));
        })()
        """
        )
        try:
            raw = h.js(js_code)
            if raw:
                return json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            logger.debug("Source extraction failed: %s", e)
        return []

    # ------------------------------------------------------------------
    # ID extraction — finds numeric IDs and UUIDs in API paths
    # ------------------------------------------------------------------

    def extract_ids_from_endpoints(self) -> list[dict[str, Any]]:
        """Find endpoints with ID patterns that can be swapped."""
        candidates = []

        for ep in self.harvested_endpoints:
            url = ep.get("url", "")

            # Check for numeric IDs in path
            for pattern in self.profile.id_patterns:
                matches = re.findall(pattern, url)
                for m in matches:
                    candidates.append(
                        {
                            "url": url,
                            "original_id": m,
                            "id_type": "numeric" if m.isdigit() else "uuid",
                            "method": ep.get("method", "GET"),
                            "source": ep.get("type", "unknown"),
                        }
                    )

            # Check query params with ID-like names
            if "?" in url:
                base, qs = url.split("?", 1)
                for param in qs.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        if any(id_name in key.lower() for id_name in self.profile.id_param_names):
                            candidates.append(
                                {
                                    "url": url,
                                    "original_id": val,
                                    "id_type": "param",
                                    "param_name": key,
                                    "method": ep.get("method", "GET"),
                                    "source": ep.get("type", "unknown"),
                                }
                            )

        return candidates

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close(self):
        """Clean up browser session state."""
        pass


# ---------------------------------------------------------------------------
# Standalone browser interaction helpers
# ---------------------------------------------------------------------------


def open_browser(url: str = "") -> None:
    """Open a URL in the local Chrome instance via CDP."""
    import os
    import subprocess
    import sys

    chrome_path = "/usr/bin/google-chrome-stable"
    user_data_dir = os.environ.get(
        "PROMETHEUS_CHROME_USER_DATA_DIR",
        str(Path.home() / ".cache" / "prometheus" / "chrome"),
    )
    cmd = [
        chrome_path,
        "--remote-debugging-port=9222",
        f"--user-data-dir={user_data_dir}",
    ]
    if url:
        cmd.append(url)

    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except FileNotFoundError:
        logger.error("Chrome not found at %s", chrome_path)
        raise


def check_cdp() -> bool:
    """Verify CDP is available on port 9222."""
    import urllib.request

    try:
        resp = urllib.request.urlopen("http://localhost:9222/json/version", timeout=3)
        return resp.status == 200
    except Exception:
        return False
